use std::fmt;

use bincode::Options;
use p3_field::PrimeField64;
use p3_koala_bear::KoalaBear;
use serde::Deserialize;

use crate::SIGWinternitzLifetime18W1;

/// Number of field elements used to encode a Poseidon hash domain element.
pub const POSEIDON_HASH_LEN_FE: usize = 7;
/// Number of field elements used for the Poseidon public parameter.
pub const POSEIDON_PARAMETER_LEN_FE: usize = 5;
/// Number of field elements used for the Winternitz randomness (rho).
pub const POSEIDON_RANDOMNESS_LEN_FE: usize = 5;
/// Number of KoalaBear bytes per field element.
pub const POSEIDON_FE_BYTES: usize = core::mem::size_of::<KoalaBear>();
/// Number of Winternitz chains for the w=1 instantiation.
pub const WINTERNITZ_W1_NUM_CHAINS: usize = 163;
/// Merkle tree height for lifetime 2^18.
pub const WINTERNITZ_TREE_HEIGHT: usize = 18;

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
pub enum HashsigExportError {
    Serialization(String),
    UnexpectedChainCount { expected: usize, actual: usize },
}

impl fmt::Display for HashsigExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashsigExportError::Serialization(s) => {
                write!(f, "failed to serialize hash-sig object: {s}")
            }
            HashsigExportError::UnexpectedChainCount { expected, actual } => {
                write!(f, "unexpected chain count {actual} (expected {expected})")
            }
        }
    }
}

impl std::error::Error for HashsigExportError {}

impl From<bincode::Error> for HashsigExportError {
    fn from(err: bincode::Error) -> Self {
        HashsigExportError::Serialization(err.to_string())
    }
}

#[derive(Deserialize)]
struct RawSignature {
    path: RawPath,
    rho: [KoalaBear; POSEIDON_RANDOMNESS_LEN_FE],
    hashes: Vec<[KoalaBear; POSEIDON_HASH_LEN_FE]>,
}

#[derive(Deserialize)]
struct RawPath {
    co_path: Vec<[KoalaBear; POSEIDON_HASH_LEN_FE]>,
}

#[derive(Deserialize)]
struct RawPublicKey {
    root: [KoalaBear; POSEIDON_HASH_LEN_FE],
    parameter: [KoalaBear; POSEIDON_PARAMETER_LEN_FE],
}

fn deserialize_via_bincode<T, U>(value: &T) -> Result<U, HashsigExportError>
where
    T: serde::Serialize,
    U: for<'de> Deserialize<'de>,
{
    // Use little-endian configuration to ensure deterministic layout.
    let bytes = bincode::options().with_little_endian().serialize(value)?;
    Ok(bincode::options()
        .with_little_endian()
        .deserialize(&bytes)?)
}

fn field_array_to_bytes<const N: usize>(arr: &[KoalaBear; N]) -> Vec<u8> {
    let mut out = Vec::with_capacity(N * POSEIDON_FE_BYTES);
    for fe in arr {
        let limb = fe.as_canonical_u64() as u32;
        out.extend_from_slice(&limb.to_le_bytes());
    }
    out
}

fn domains_to_bytes(domains: &[[KoalaBear; POSEIDON_HASH_LEN_FE]]) -> Vec<Vec<u8>> {
    domains
        .iter()
        .map(|domain| field_array_to_bytes(domain))
        .collect()
}

/// Convert a hash-sig Poseidon public key into raw byte vectors.
pub fn export_public_key(
    pk: &<SIGWinternitzLifetime18W1 as hashsig::signature::SignatureScheme>::PublicKey,
) -> Result<ExportedPublicKey, HashsigExportError> {
    let raw: RawPublicKey = deserialize_via_bincode(pk)?;
    Ok(ExportedPublicKey {
        root: field_array_to_bytes(&raw.root),
        parameter: field_array_to_bytes(&raw.parameter),
    })
}

/// Convert a hash-sig Poseidon signature into byte vectors suitable for xmss-types.
pub fn export_signature(
    sig: &<SIGWinternitzLifetime18W1 as hashsig::signature::SignatureScheme>::Signature,
) -> Result<ExportedSignature, HashsigExportError> {
    let raw: RawSignature = deserialize_via_bincode(sig)?;
    if raw.hashes.len() != WINTERNITZ_W1_NUM_CHAINS {
        return Err(HashsigExportError::UnexpectedChainCount {
            expected: WINTERNITZ_W1_NUM_CHAINS,
            actual: raw.hashes.len(),
        });
    }
    Ok(ExportedSignature {
        randomness: field_array_to_bytes(&raw.rho),
        chain_hashes: domains_to_bytes(&raw.hashes),
        auth_path: domains_to_bytes(&raw.path.co_path),
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
        let (pk, sk) = SIGWinternitzLifetime18W1::key_gen(&mut rng, 0, 1);
        let digest = hash_message_to_digest(b"poseidon-export");
        let sig = SIGWinternitzLifetime18W1::sign(&mut rng, &sk, 0, &digest).unwrap();
        assert!(SIGWinternitzLifetime18W1::verify(&pk, 0, &digest, &sig));

        let exported_sig = export_signature(&sig).expect("signature exports");
        assert_eq!(
            exported_sig.randomness.len(),
            POSEIDON_RANDOMNESS_LEN_FE * POSEIDON_FE_BYTES
        );
        assert_eq!(exported_sig.chain_hashes.len(), WINTERNITZ_W1_NUM_CHAINS);
        assert!(exported_sig
            .chain_hashes
            .iter()
            .all(|c| c.len() == POSEIDON_HASH_LEN_FE * POSEIDON_FE_BYTES));
        assert_eq!(exported_sig.auth_path.len(), WINTERNITZ_TREE_HEIGHT);
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
