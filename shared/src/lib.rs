#![cfg_attr(not(feature = "std"), no_std)]

use serde::{Deserialize, Serialize};

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactSignature {
    pub leaf_index: u32,
    pub randomness: [u8; 32],
    pub wots_signature: Vec<[u8; 32]>,
    pub auth_path: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactPublicKey {
    pub root: [u8; 32],
    pub seed: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationInput {
    pub signatures: Vec<CompactSignature>,
    pub messages: Vec<Vec<u8>>,
    pub public_keys: Vec<CompactPublicKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub all_signatures_valid: bool,
    pub num_signatures_verified: usize,
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
    pub input: VerificationInput,
}
