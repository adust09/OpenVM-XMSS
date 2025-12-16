use std::error::Error;
use std::fmt::{self, Display};

pub mod leansig_export;
pub mod zkvm;

pub use zkvm::ZkvmHost;

// leanSig signature scheme: TargetSum encoding with Poseidon hash
pub use leansig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::target_sum::SIGTargetSumLifetime18W1NoOff;
pub use leansig::signature::SignatureScheme;

// Type alias for the default signature scheme
pub type DefaultSignatureScheme = SIGTargetSumLifetime18W1NoOff;

/// Errors surfaced by host-side helpers when preparing XMSS data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XmssHostError {
    EpochOutOfRange {
        epoch: u32,
        activation_epoch: usize,
        num_active_epochs: usize,
    },
}

impl Display for XmssHostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XmssHostError::EpochOutOfRange {
                epoch,
                activation_epoch,
                num_active_epochs,
            } => write!(
                f,
                "epoch {} is outside [{}, {})",
                epoch,
                activation_epoch,
                activation_epoch + num_active_epochs
            ),
        }
    }
}

impl Error for XmssHostError {}

/// Ensure the requested epoch falls inside the activation range supplied during key generation.
pub fn validate_epoch_range(
    activation_epoch: usize,
    num_active_epochs: usize,
    epoch: u32,
) -> Result<(), XmssHostError> {
    let start = activation_epoch;
    let Some(end) = activation_epoch.checked_add(num_active_epochs) else {
        return Err(XmssHostError::EpochOutOfRange {
            epoch,
            activation_epoch,
            num_active_epochs,
        });
    };
    let epoch_usize = epoch as usize;
    if !(start..end).contains(&epoch_usize) {
        return Err(XmssHostError::EpochOutOfRange {
            epoch,
            activation_epoch,
            num_active_epochs,
        });
    }
    Ok(())
}

/// Hash arbitrary-length message bytes down to the 32-byte digest required by hash-sig.
pub fn hash_message_to_digest(message: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(message);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::{
        hash_message_to_digest, validate_epoch_range, DefaultSignatureScheme, XmssHostError,
    };
    use leansig::signature::SignatureScheme;
    use rand::SeedableRng;

    #[test]
    fn sign_and_verify_roundtrip() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xDEADBEEF);
        let (pk, sk) = DefaultSignatureScheme::key_gen(&mut rng, 0, 4);

        let digest = hash_message_to_digest(b"leansig-roundtrip");
        // leanSig sign doesn't take external RNG - randomness is internal
        let signature = DefaultSignatureScheme::sign(&sk, 0, &digest)
            .expect("leanSig signing should succeed for fixed digest");

        assert!(DefaultSignatureScheme::verify(&pk, 0, &digest, &signature));
    }

    #[test]
    fn epoch_validation_passes_within_range() {
        validate_epoch_range(10, 5, 12).expect("epoch inside range");
    }

    #[test]
    fn epoch_validation_errors_outside_range() {
        let err = validate_epoch_range(10, 5, 42).expect_err("epoch must be rejected");
        assert!(matches!(
            err,
            XmssHostError::EpochOutOfRange {
                epoch: 42,
                activation_epoch: 10,
                num_active_epochs: 5
            }
        ));
    }
}
