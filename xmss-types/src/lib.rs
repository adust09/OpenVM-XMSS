#![cfg_attr(not(feature = "std"), no_std)]

use serde::{Deserialize, Serialize};

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub leaf_index: u32,
    pub randomness: Vec<u8>, // Variable length to accommodate different hash-sig instantiations
    pub wots_chain_ends: Vec<Vec<u8>>, // Renamed from wots_signature to reflect chain end semantics
    pub auth_path: Vec<Vec<u8>>, // Variable length for different hash sizes (e.g., 7×4 bytes for Poseidon KoalaBear nodes)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    pub root: Vec<u8>, // Variable length for different hash sizes (e.g., 7×4 bytes for Poseidon KoalaBear nodes)
    pub parameter: Vec<u8>, // Renamed from seed to match hash-sig semantics (5×4 bytes for Poseidon KoalaBear parameters)
}

// Statement/Witness separation to align with pqSNARK.md
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    // Number of signers/signatures expected
    pub k: u32,
    // Epoch (domain component)
    pub ep: u64,
    // Single common message for all signatures
    pub m: Vec<u8>,
    // Public keys corresponding to each signature
    pub public_keys: Vec<PublicKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Witness {
    pub signatures: Vec<Signature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationResult {
    pub all_signatures_valid: bool,
    pub num_signatures_verified: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TslParams {
    pub w: u16,
    pub v: u16,
    pub d0: u32,
    pub security_bits: u16,
    pub tree_height: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationBatch {
    pub params: TslParams,
    pub statement: Statement,
    pub witness: Witness,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_batch_round_trips() {
        let batch = VerificationBatch {
            params: TslParams {
                w: 4,
                v: 8,
                d0: 4,
                security_bits: 128,
                tree_height: 10,
            },
            statement: Statement {
                k: 2,
                ep: 42,
                m: vec![0xAB; 32],
                public_keys: vec![
                    PublicKey {
                        root: vec![1u8; 28],
                        parameter: vec![2u8; 20],
                    },
                    PublicKey {
                        root: vec![9u8; 28],
                        parameter: vec![8u8; 20],
                    },
                ],
            },
            witness: Witness {
                signatures: vec![
                    Signature {
                        leaf_index: 0,
                        randomness: vec![3u8; 20],
                        wots_chain_ends: vec![vec![4u8; 28]; 8],
                        auth_path: vec![vec![5u8; 28]; 10],
                    },
                    Signature {
                        leaf_index: 1,
                        randomness: vec![6u8; 20],
                        wots_chain_ends: vec![vec![7u8; 28]; 8],
                        auth_path: vec![vec![8u8; 28]; 10],
                    },
                ],
            },
        };

        let json = serde_json::to_string(&batch).expect("serialize VerificationBatch");
        let decoded: VerificationBatch =
            serde_json::from_str(&json).expect("deserialize VerificationBatch");
        assert_eq!(decoded, batch);
    }
}
