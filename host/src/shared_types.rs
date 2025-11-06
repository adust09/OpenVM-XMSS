use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub leaf_index: u32,
    pub randomness: Vec<u8>,
    pub wots_chain_ends: Vec<Vec<u8>>,
    pub auth_path: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    pub root: Vec<u8>,
    pub parameter: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Statement {
    pub k: u32,
    pub ep: u64,
    pub m: Vec<u8>,
    pub public_keys: Vec<PublicKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Witness {
    pub signatures: Vec<Signature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TslParams {
    pub w: u16,
    pub v: u16,
    pub d0: u32,
    pub security_bits: u16,
    pub tree_height: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationBatch {
    pub params: TslParams,
    pub statement: Statement,
    pub witness: Witness,
}
