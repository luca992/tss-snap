use curv::arithmetic::Converter;
use curv::BigInt;
use curv::elliptic::curves::Secp256k1;
use js_sys::Array;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::verify;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::sign::{CompletedOfflineStage, OfflineStage, PartialSignature, SignManual};
use wasm_bindgen::{JsError, JsValue};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::gg2020::sign::ERR_COMPLETED_OFFLINE_STAGE;
use crate::gg2020::simulate::simulation::Simulation;
use crate::Signature;

/// Simulation Round-based signing protocol.
#[wasm_bindgen]
pub struct SimulationSigner {
    completed_offline_stage: CompletedOfflineStage,
    completed: Option<(CompletedOfflineStage, BigInt)>,
}

impl SimulationSigner {
    /// Create a signer.
    fn new(
        completed_offline_stage: CompletedOfflineStage,
    ) -> SimulationSigner {
        Self {
            completed_offline_stage,
            completed: None,
        }
    }
}

#[wasm_bindgen]
impl SimulationSigner {
    /// Returns the completed offline stage if available.
    pub fn completed_offline_stage(&mut self) -> Result<JsValue, JsError> {
        Ok(serde_wasm_bindgen::to_value(&self.completed_offline_stage)?)
    }

    /// Generate the completed offline stage and store the result
    /// internally to be used when `create()` is called.
    ///
    /// Return a partial signature that must be sent to the other
    /// signing participants.
    pub fn partial(&mut self, message: JsValue) -> Result<JsValue, JsError> {
        let message: Vec<u8> = serde_wasm_bindgen::from_value(message)?;
        let message: [u8; 32] = message.as_slice().try_into()?;
        let completed_offline_stage = &self.completed_offline_stage;
        let data = BigInt::from_bytes(&message);
        let (_sign, partial) =
            SignManual::new(data.clone(), completed_offline_stage.clone())?;

        self.completed = Some((completed_offline_stage.clone(), data));

        Ok(serde_wasm_bindgen::to_value(&partial)?)
    }

    /// Add partial signatures without validating them. Allows multiple partial signatures
    /// to be combined into a single partial signature before sending it to the other participants.
    pub fn add(&mut self, partials: JsValue) -> Result<JsValue, JsError> {
        let partials: Vec<PartialSignature> =
            serde_wasm_bindgen::from_value(partials)?;

        let (completed_offline_stage, data) = self
            .completed
            .take()
            .ok_or_else(|| JsError::new(ERR_COMPLETED_OFFLINE_STAGE))?;
        let (sign, _partial) =
            SignManual::new(data.clone(), completed_offline_stage.clone())?;

        let (_sign, aggregated_partial) = sign.add(&partials)?;

        Ok(serde_wasm_bindgen::to_value(&aggregated_partial)?)
    }

    /// Create and verify the signature.
    pub fn create(&mut self, partials: JsValue) -> Result<JsValue, JsError> {
        let partials: Vec<PartialSignature> =
            serde_wasm_bindgen::from_value(partials)?;

        let (completed_offline_stage, data) = self
            .completed
            .take()
            .ok_or_else(|| JsError::new(ERR_COMPLETED_OFFLINE_STAGE))?;
        let pk = completed_offline_stage.public_key().clone();

        let (sign, _partial) =
            SignManual::new(data.clone(), completed_offline_stage.clone())?;

        let signature = sign.complete(&partials)?;
        verify(&signature, &pk, &data).map_err(|e| {
            JsError::new(&format!("failed to verify signature: {:?}", e))
        })?;

        let public_key = pk.to_bytes(false).to_vec();
        let result = Signature {
            signature,
            address: crate::utils::address(&public_key),
            public_key,
        };

        Ok(serde_wasm_bindgen::to_value(&result)?)
    }
}

#[wasm_bindgen(js_name = "signingOfflineStageSimulated")]
pub fn signing_offline_stage_simulated(
    local_keys: JsValue,
    participants: JsValue,
) -> Result<Array, JsError> {
    let mut simulation = Simulation::new();
    let local_keys: Vec<LocalKey<Secp256k1>> =
        serde_wasm_bindgen::from_value(local_keys)?;
    let s_l: Vec<u16> = serde_wasm_bindgen::from_value(participants)?;
    for (i, keygen_i) in (1..).zip(&s_l) {
        simulation.add_party(
            OfflineStage::new(
                i,
                s_l.to_vec(),
                local_keys[usize::from(keygen_i - 1)].clone(),
            )
            .unwrap(),
        );
    }

    let stages = simulation.run().unwrap();
    let simulation_signers = stages
        .into_iter()
        .map(|s| SimulationSigner::new(s))
        .collect::<Vec<_>>();

    let signers_result = Array::new();
    for signer in simulation_signers.into_iter() {
        signers_result.push(&JsValue::from(signer));
    }

    Ok(signers_result)
}
