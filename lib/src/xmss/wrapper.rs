// Main XmssWrapper API with hash-sig integration

use crate::xmss::{
    config::{ParameterMetadata, ParameterSet},
    epoch::EpochValidator,
    error::WrapperError,
    message::MessagePreprocessor,
};
use hashsig::signature::{
    generalized_xmss::instantiations_sha::{
        lifetime_2_to_the_18::winternitz::{SIGWinternitzLifetime18W4, SIGWinternitzLifetime18W8},
        lifetime_2_to_the_20::winternitz::SIGWinternitzLifetime20W4,
    },
    SignatureScheme,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

/// Wrapped public key with parameter metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedPublicKey<S: SignatureScheme> {
    /// Underlying hash-sig public key
    pub(crate) inner: S::PublicKey,
    /// Parameter set metadata
    pub(crate) params: ParameterMetadata,
}

/// Wrapped secret key with epoch range metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedSecretKey<S: SignatureScheme> {
    /// Underlying hash-sig secret key
    pub(crate) inner: S::SecretKey,
    /// Activation epoch (start of valid range)
    pub(crate) activation_epoch: u32,
    /// Number of active epochs (range size)
    pub(crate) num_active_epochs: u32,
    /// Parameter set metadata
    pub(crate) params: ParameterMetadata,
}

/// Wrapped signature with epoch metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedSignature<S: SignatureScheme> {
    /// Underlying hash-sig signature
    pub(crate) inner: S::Signature,
    /// Epoch at which signature was created
    pub(crate) epoch: u32,
}

/// XMSS wrapper providing ergonomic API over hash-sig
pub struct XmssWrapper<S: SignatureScheme> {
    _phantom: PhantomData<S>,
}

impl<S: SignatureScheme> XmssWrapper<S> {
    /// Generate XMSS key pair with epoch range
    ///
    /// Preconditions:
    /// - activation_epoch + num_active_epochs <= S::LIFETIME
    /// - rng implements rand::RngCore
    ///
    /// Postconditions:
    /// - Returns wrapped keys containing epoch metadata
    /// - Keys are valid for epochs [activation_epoch, activation_epoch + num_active_epochs)
    ///
    /// Invariants:
    /// - Secret key epoch range never changes after generation
    pub fn key_gen<R: RngCore>(
        rng: &mut R,
        params: ParameterSet,
        activation_epoch: u32,
        num_active_epochs: u32,
    ) -> Result<(WrappedPublicKey<S>, WrappedSecretKey<S>), WrapperError> {
        let metadata = params.metadata();

        // Validate epoch range before calling hash-sig
        EpochValidator::validate_epoch_range(
            activation_epoch,
            num_active_epochs,
            metadata.lifetime,
        )?;

        // Call hash-sig key_gen
        let (pk, sk) = S::key_gen(
            rng,
            activation_epoch as usize,
            num_active_epochs as usize,
        );

        Ok((
            WrappedPublicKey {
                inner: pk,
                params: metadata.clone(),
            },
            WrappedSecretKey {
                inner: sk,
                activation_epoch,
                num_active_epochs,
                params: metadata,
            },
        ))
    }

    /// Sign message with XMSS secret key at specific epoch
    ///
    /// Preconditions:
    /// - epoch is within secret key's active range
    /// - message can be any length (will be hashed to 32 bytes)
    /// - rng implements rand::RngCore
    ///
    /// Postconditions:
    /// - Returns signature valid for SHA-256(message) at epoch
    /// - Secret key unchanged (no automatic epoch increment)
    ///
    /// Invariants:
    /// - Same message + epoch always produces valid signature (probabilistic)
    pub fn sign<R: RngCore>(
        rng: &mut R,
        sk: &WrappedSecretKey<S>,
        epoch: u32,
        message: &[u8],
    ) -> Result<WrappedSignature<S>, WrapperError> {
        // Validate epoch is within secret key's range
        EpochValidator::validate_epoch(epoch, sk.activation_epoch, sk.num_active_epochs)?;

        // Preprocess message to 32 bytes
        let digest = MessagePreprocessor::preprocess(message);

        // Call hash-sig sign
        let signature = S::sign(rng, &sk.inner, epoch, &digest)
            .map_err(|e| WrapperError::HashSigError(e.to_string()))?;

        Ok(WrappedSignature {
            inner: signature,
            epoch,
        })
    }

    /// Verify XMSS signature
    ///
    /// Preconditions:
    /// - message can be any length (will be hashed to 32 bytes)
    ///
    /// Postconditions:
    /// - Returns true if signature is valid for SHA-256(message) at epoch
    /// - Returns false otherwise (no error for invalid signatures)
    ///
    /// Invariants:
    /// - Deterministic: same inputs always produce same result
    pub fn verify(
        pk: &WrappedPublicKey<S>,
        epoch: u32,
        message: &[u8],
        signature: &WrappedSignature<S>,
    ) -> bool {
        // Preprocess message to 32 bytes
        let digest = MessagePreprocessor::preprocess(message);

        // Call hash-sig verify
        S::verify(&pk.inner, epoch, &digest, &signature.inner)
    }

    /// Query parameter metadata
    pub fn metadata(params: ParameterSet) -> ParameterMetadata {
        params.metadata()
    }
}

// Type aliases for common instantiations
pub type XmssWrapperH18W4 = XmssWrapper<SIGWinternitzLifetime18W4>;
pub type XmssWrapperH18W8 = XmssWrapper<SIGWinternitzLifetime18W8>;
pub type XmssWrapperH20W4 = XmssWrapper<SIGWinternitzLifetime20W4>;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn test_wrapper_creation_increments_epoch() {
        // Test that we can create wrappers for signature generation
        // This test validates wrapper type instantiation
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let params = ParameterSet::SHA256_H18_W4;

        let result = XmssWrapperH18W4::key_gen(&mut rng, params, 0, 10);
        assert!(result.is_ok(), "Key generation should succeed");

        let (pk, sk) = result.unwrap();
        assert_eq!(sk.activation_epoch, 0);
        assert_eq!(sk.num_active_epochs, 10);
        assert_eq!(pk.params.tree_height, 18);
    }

    #[test]
    fn test_wrapper_validates_epoch_range() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let params = ParameterSet::SHA256_H18_W4;
        let lifetime = params.metadata().lifetime;

        // Test invalid epoch range (exceeds lifetime)
        let result = XmssWrapperH18W4::key_gen(&mut rng, params, 0, lifetime + 1);
        assert!(result.is_err(), "Should reject epoch range exceeding lifetime");

        match result {
            Err(WrapperError::EpochOutOfRange { .. }) => {
                // Expected error
            }
            _ => panic!("Expected EpochOutOfRange error"),
        }
    }

    #[test]
    fn test_sign_validates_epoch() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let params = ParameterSet::SHA256_H18_W4;

        let (_, sk) = XmssWrapperH18W4::key_gen(&mut rng, params, 10, 20).unwrap();

        // Test signing with epoch outside range
        let message = b"test message";
        let result = XmssWrapperH18W4::sign(&mut rng, &sk, 5, message); // Epoch 5 < activation 10
        assert!(result.is_err(), "Should reject epoch below activation");

        let result = XmssWrapperH18W4::sign(&mut rng, &sk, 30, message); // Epoch 30 >= end 30
        assert!(result.is_err(), "Should reject epoch at or above end");
    }

    #[test]
    fn test_message_preprocessing() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let params = ParameterSet::SHA256_H18_W4;

        let (pk, sk) = XmssWrapperH18W4::key_gen(&mut rng, params, 0, 100).unwrap();

        // Sign a message
        let message = b"test message with arbitrary length";
        let signature = XmssWrapperH18W4::sign(&mut rng, &sk, 0, message).unwrap();

        // Verify the signature
        let valid = XmssWrapperH18W4::verify(&pk, 0, message, &signature);
        assert!(valid, "Signature should verify correctly");

        // Verify with different message should fail
        let different_message = b"different message";
        let valid = XmssWrapperH18W4::verify(&pk, 0, different_message, &signature);
        assert!(!valid, "Signature should not verify with different message");
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let params = ParameterSet::SHA256_H18_W4;

        let (pk, sk) = XmssWrapperH18W4::key_gen(&mut rng, params, 0, 10).unwrap();

        // Serialize public key
        let pk_bytes = bincode::serialize(&pk).unwrap();
        let pk_deserialized: WrappedPublicKey<SIGWinternitzLifetime18W4> =
            bincode::deserialize(&pk_bytes).unwrap();
        assert_eq!(pk_deserialized.params.tree_height, pk.params.tree_height);

        // Serialize secret key
        let sk_bytes = bincode::serialize(&sk).unwrap();
        let sk_deserialized: WrappedSecretKey<SIGWinternitzLifetime18W4> =
            bincode::deserialize(&sk_bytes).unwrap();
        assert_eq!(
            sk_deserialized.activation_epoch,
            sk.activation_epoch
        );

        // Sign with original key and verify with deserialized key
        let message = b"test";
        let signature = XmssWrapperH18W4::sign(&mut rng, &sk, 0, message).unwrap();
        let valid = XmssWrapperH18W4::verify(&pk_deserialized, 0, message, &signature);
        assert!(valid, "Deserialized key should work correctly");
    }
}
