/// Common types shared between the server and webassembly modules.

#[cfg(target_arch = "wasm32")]
use curv::{
    cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS,
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
};

#[cfg(target_arch = "wasm32")]
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys,
};

use serde::{Deserialize, Serialize};

pub const ROUND_1: &str = "round1";
pub const ROUND_2: &str = "round2";
pub const AES_KEY_BYTES_LEN: usize = 32;

pub type Key = String;

/// Parameters for key generation and signing.
#[derive(Debug, Serialize, Deserialize)]
pub struct Parameters {
    pub parties: u16,
    pub threshold: u16,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PartySignup {
    pub number: u16,
    pub uuid: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub key: Key,
    pub value: String,
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round1Entry {
    pub party_keys: Keys,
    pub entry: Entry,
    pub decom_i: KeyGenDecommitMessage1,
    pub bc_i: KeyGenBroadcastMessage1,
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round2Entry {
    pub party_keys: Keys,
    pub entry: Entry,
    pub decom_i: KeyGenDecommitMessage1,
    pub bc1_vec: Vec<KeyGenBroadcastMessage1>,
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round3Entry {
    pub vss_scheme: VerifiableSS<Secp256k1>,
    pub secret_shares: Vec<Scalar<Secp256k1>>,
    pub y_sum: Point<Secp256k1>,
}

pub fn into_round_entry(
    party_num: u16,
    round: &str,
    value: String,
    sender_uuid: String,
) -> Entry {
    let key = format!("{}-{}-{}", party_num, round, sender_uuid);
    Entry { key, value }
}