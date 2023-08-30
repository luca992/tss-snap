use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::Keygen;
use wasm_bindgen::{JsError, JsValue};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::gg2020::simulate::simulation::Simulation;
use crate::{KeyShare, Parameters};

#[wasm_bindgen]
pub fn simulate_keygen(parameters: JsValue) -> Result<JsValue, JsError> {
    let params: Parameters = serde_wasm_bindgen::from_value(parameters)?;
    let t = params.threshold;
    let n = params.parties;
    let mut simulation = Simulation::<Keygen>::new();

    for i in 1..=n {
        simulation.add_party(Keygen::new(i, t, n).unwrap());
    }

    let keys = simulation.run().unwrap();

    let key_shares: Vec<KeyShare> =
        keys.into_iter().map(|k| k.into()).collect();
    Ok(serde_wasm_bindgen::to_value(&key_shares)?)
}
