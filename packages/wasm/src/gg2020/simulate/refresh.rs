use std::collections::HashMap;

use cggmp_threshold_ecdsa::refresh::state_machine::KeyRefresh;
use curv::elliptic::curves::Secp256k1;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;
use serde::Deserialize;
use wasm_bindgen::{JsError, JsValue};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::gg2020::simulate::simulation::Simulation;
use crate::{KeyShare, Parameters};

#[derive(Deserialize)]
pub enum KeyRefreshItem {
    Existing {
        key: LocalKey<Secp256k1>,
        updated_party_index: Option<u16>,
    },
    New {
        party_index: u16,
    },
}

#[wasm_bindgen(js_name = "keyRefreshSimulated")]
pub fn key_refresh_simulated(
    parameters: JsValue,
    key_refresh_items: JsValue,
) -> Result<JsValue, JsError> {
    let params: Parameters = serde_wasm_bindgen::from_value(parameters)?;
    let key_refresh_items: Vec<KeyRefreshItem> =
        serde_wasm_bindgen::from_value(key_refresh_items)?;
    let new_t = params.threshold;
    let new_n = params.parties;

    let mut simulation = Simulation::<KeyRefresh>::new();
    let mut old_to_new = HashMap::new();
    let mut old_t = 0;
    for item in &key_refresh_items {
        match item {
            KeyRefreshItem::Existing {
                key,
                updated_party_index,
            } => {
                let new_party_index = updated_party_index.unwrap_or(key.i);
                old_to_new.insert(key.i, new_party_index);
                old_t = key.t;
            }
            _ => {}
        }
    }
    for item in key_refresh_items {
        match item {
            KeyRefreshItem::Existing { key, .. } => {
                simulation.add_party(
                    KeyRefresh::new(
                        Some(key),
                        None,
                        &old_to_new,
                        new_t,
                        new_n,
                        None,
                    )
                    .unwrap(),
                );
            }
            KeyRefreshItem::New { party_index } => {
                simulation.add_party(
                    KeyRefresh::new(
                        None,
                        Some(party_index),
                        &old_to_new,
                        new_t,
                        new_n,
                        Some(old_t),
                    )
                    .unwrap(),
                );
            }
        }
    }

    let keys = simulation.run().unwrap();

    let key_shares: Vec<KeyShare> =
        keys.into_iter().map(|k| k.into()).collect();
    Ok(serde_wasm_bindgen::to_value(&key_shares)?)
}
