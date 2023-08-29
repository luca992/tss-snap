use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::Parameters;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::{Keygen, LocalKey};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::sign::{CompletedOfflineStage, OfflineStage};
use round_based::dev::Simulation;
use wasm_bindgen::{JsError, JsValue};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::KeyShare;

#[wasm_bindgen]
pub fn simulate_keygen(
    parameters: JsValue,
) -> Result<JsValue, JsError> {
    let params: Parameters = serde_wasm_bindgen::from_value(parameters)?;
    let t = params.threshold;
    let n = params.share_count;
    let mut simulation = Simulation::<Keygen>::new();

    for i in 1..=n {
        simulation.add_party(Keygen::new(i, t, n).unwrap());
    }

    let keys = simulation.run().unwrap();

    let key_shares: Vec<KeyShare> = keys.into_iter().map(|k| k.into()).collect();
    Ok(serde_wasm_bindgen::to_value(&key_shares)?)
}

pub fn simulate_offline_stage(
    local_keys: &Vec<LocalKey<curv::elliptic::curves::Secp256k1>>,
    s_l: &[u16],
) -> Vec<CompletedOfflineStage> {
    let mut simulation = Simulation::new();

    for (i, &keygen_i) in (1..).zip(s_l) {
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

    stages
}
