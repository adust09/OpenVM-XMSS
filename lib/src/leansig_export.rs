use std::fmt;

use leansig::serialization::Serializable;

use crate::DefaultSignatureScheme;

/// Number of field elements used to encode a Poseidon hash domain element.
pub const POSEIDON_HASH_LEN_FE: usize = 7;
/// Number of field elements used for the Poseidon public parameter.
pub const POSEIDON_PARAMETER_LEN_FE: usize = 5;
/// Number of field elements used for the TargetSum randomness (rho).
/// For w=1 TargetSum encoding, this is 6 (different from hashsig's 5).
pub const POSEIDON_RANDOMNESS_LEN_FE: usize = 6;
/// Number of KoalaBear bytes per field element.
pub const POSEIDON_FE_BYTES: usize = 4;
/// Number of TargetSum chains for the w=1, NoOff instantiation.
/// This is the DIMENSION parameter from the encoding.
pub const TARGETSIM_W1_NUM_CHAINS: usize = 155;
/// Merkle tree height for lifetime 2^18.
pub const TARGETSIM_TREE_HEIGHT: usize = 18;

// Computed sizes
const HASH_BYTES: usize = POSEIDON_HASH_LEN_FE * POSEIDON_FE_BYTES;
const PARAM_BYTES: usize = POSEIDON_PARAMETER_LEN_FE * POSEIDON_FE_BYTES;
const RAND_BYTES: usize = POSEIDON_RANDOMNESS_LEN_FE * POSEIDON_FE_BYTES;

/// Host-facing representation of a Poseidon XMSS public key.
pub struct ExportedPublicKey {
    pub root: Vec<u8>,
    pub parameter: Vec<u8>,
}

/// Host-facing representation of a Poseidon XMSS signature.
pub struct ExportedSignature {
    pub randomness: Vec<u8>,
    pub chain_hashes: Vec<Vec<u8>>,
    pub auth_path: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub enum LeansigExportError {
    Serialization(String),
    UnexpectedChainCount { expected: usize, actual: usize },
    InvalidByteLength { expected: usize, actual: usize },
}

impl fmt::Display for LeansigExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LeansigExportError::Serialization(s) => {
                write!(f, "failed to serialize leanSig object: {s}")
            }
            LeansigExportError::UnexpectedChainCount { expected, actual } => {
                write!(f, "unexpected chain count {actual} (expected {expected})")
            }
            LeansigExportError::InvalidByteLength { expected, actual } => {
                write!(f, "invalid byte length {actual} (expected {expected})")
            }
        }
    }
}

impl std::error::Error for LeansigExportError {}

/// Convert a leanSig Poseidon public key into raw byte vectors.
///
/// Public key SSZ layout:
/// - root: 7 * 4 = 28 bytes (7 KoalaBear field elements)
/// - parameter: 5 * 4 = 20 bytes (5 KoalaBear field elements)
///
/// Total: 48 bytes
pub fn export_public_key(
    pk: &<DefaultSignatureScheme as leansig::signature::SignatureScheme>::PublicKey,
) -> Result<ExportedPublicKey, LeansigExportError> {
    let bytes = pk.to_bytes();
    let expected_len = HASH_BYTES + PARAM_BYTES;
    if bytes.len() != expected_len {
        return Err(LeansigExportError::InvalidByteLength {
            expected: expected_len,
            actual: bytes.len(),
        });
    }

    Ok(ExportedPublicKey {
        root: bytes[..HASH_BYTES].to_vec(),
        parameter: bytes[HASH_BYTES..].to_vec(),
    })
}

/// Convert a leanSig Poseidon signature into byte vectors suitable for xmss-types.
///
/// Signature SSZ layout (variable length due to vectors):
/// - Fixed part (offsets): path_offset (4 bytes), rho, hashes_offset
/// - Variable part: path.co_path elements, hashes elements
///
/// We parse the canonical bytes directly.
pub fn export_signature(
    sig: &<DefaultSignatureScheme as leansig::signature::SignatureScheme>::Signature,
) -> Result<ExportedSignature, LeansigExportError> {
    let bytes = sig.to_bytes();

    // SSZ layout for GeneralizedXMSSSignature:
    // Fixed part:
    //   - path offset: 4 bytes (points to variable data)
    //   - rho: RAND_BYTES (5 * 4 = 20 bytes)
    //   - hashes offset: 4 bytes
    // Variable part:
    //   - path.co_path: TREE_HEIGHT * HASH_BYTES
    //   - hashes: NUM_CHAINS * HASH_BYTES

    // Calculate expected sizes
    let fixed_size = 4 + RAND_BYTES + 4; // path_offset + rho + hashes_offset

    if bytes.len() < fixed_size {
        return Err(LeansigExportError::InvalidByteLength {
            expected: fixed_size,
            actual: bytes.len(),
        });
    }

    // Parse fixed part
    let path_offset = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let rho_start = 4;
    let rho_end = rho_start + RAND_BYTES;
    let randomness = bytes[rho_start..rho_end].to_vec();

    let hashes_offset = u32::from_le_bytes([
        bytes[rho_end],
        bytes[rho_end + 1],
        bytes[rho_end + 2],
        bytes[rho_end + 3],
    ]) as usize;

    // Parse variable part: path.co_path
    // path itself has SSZ structure: co_path_offset (4) + co_path data
    // But since HashTreeOpening only has one field, offset is always 4
    let path_data_start = path_offset + 4; // skip the inner offset
    let path_data_end = hashes_offset;
    let path_bytes = &bytes[path_data_start..path_data_end];

    let auth_path: Vec<Vec<u8>> = path_bytes
        .chunks_exact(HASH_BYTES)
        .map(|chunk| chunk.to_vec())
        .collect();

    if auth_path.len() != TARGETSIM_TREE_HEIGHT {
        return Err(LeansigExportError::UnexpectedChainCount {
            expected: TARGETSIM_TREE_HEIGHT,
            actual: auth_path.len(),
        });
    }

    // Parse variable part: hashes
    let hashes_bytes = &bytes[hashes_offset..];
    let chain_hashes: Vec<Vec<u8>> = hashes_bytes
        .chunks_exact(HASH_BYTES)
        .map(|chunk| chunk.to_vec())
        .collect();

    if chain_hashes.len() != TARGETSIM_W1_NUM_CHAINS {
        return Err(LeansigExportError::UnexpectedChainCount {
            expected: TARGETSIM_W1_NUM_CHAINS,
            actual: chain_hashes.len(),
        });
    }

    Ok(ExportedSignature {
        randomness,
        chain_hashes,
        auth_path,
    })
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;

    use super::*;
    use crate::{hash_message_to_digest, SignatureScheme};

    #[test]
    fn exported_signature_has_expected_lengths() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xBADC0FFEE);
        let (pk, sk) = DefaultSignatureScheme::key_gen(&mut rng, 0, 1);
        let digest = hash_message_to_digest(b"poseidon-export");
        // leanSig sign doesn't take external RNG
        let sig = DefaultSignatureScheme::sign(&sk, 0, &digest).unwrap();
        assert!(DefaultSignatureScheme::verify(&pk, 0, &digest, &sig));

        let exported_sig = export_signature(&sig).expect("signature exports");
        assert_eq!(
            exported_sig.randomness.len(),
            POSEIDON_RANDOMNESS_LEN_FE * POSEIDON_FE_BYTES
        );
        assert_eq!(exported_sig.chain_hashes.len(), TARGETSIM_W1_NUM_CHAINS);
        assert!(exported_sig
            .chain_hashes
            .iter()
            .all(|c| c.len() == POSEIDON_HASH_LEN_FE * POSEIDON_FE_BYTES));
        assert_eq!(exported_sig.auth_path.len(), TARGETSIM_TREE_HEIGHT);
        assert!(exported_sig
            .auth_path
            .iter()
            .all(|node| node.len() == POSEIDON_HASH_LEN_FE * POSEIDON_FE_BYTES));

        let exported_pk = export_public_key(&pk).expect("public key exports");
        assert_eq!(
            exported_pk.root.len(),
            POSEIDON_HASH_LEN_FE * POSEIDON_FE_BYTES
        );
        assert_eq!(
            exported_pk.parameter.len(),
            POSEIDON_PARAMETER_LEN_FE * POSEIDON_FE_BYTES
        );
    }
}
