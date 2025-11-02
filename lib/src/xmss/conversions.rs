// Type conversions between hash-sig and xmss-types

use crate::xmss::error::WrapperError;
use crate::xmss::wrapper::{WrappedPublicKey, WrappedSignature};
use hashsig::signature::SignatureScheme;
use xmss_types::{PublicKey, Signature};

/// Type converter for bidirectional conversion between hash-sig and xmss-types
pub struct TypeConverter;

impl TypeConverter {
    /// Convert hash-sig Signature to xmss-types::Signature
    ///
    /// Preconditions:
    /// - wrapped_signature contains valid hash-sig signature
    ///
    /// Postconditions:
    /// - Returns xmss_types::Signature with extracted fields
    /// - Preserves cryptographic material exactly
    ///
    /// Process:
    /// 1. Serialize hash-sig signature to bincode bytes
    /// 2. Deserialize into xmss_types::Signature format
    pub fn to_xmss_signature<S: SignatureScheme>(
        wrapped_signature: &WrappedSignature<S>,
    ) -> Result<Signature, WrapperError> {
        // Serialize the hash-sig signature
        let bytes = bincode::serialize(&wrapped_signature.inner)?;

        // For now, we'll create a basic conversion
        // The actual structure depends on hash-sig's serialization format
        // We'll use the serialized bytes directly and let xmss-types handle it

        // Deserialize as xmss_types::Signature
        // Note: This is a simplified approach - in production, we'd need to
        // properly parse the bincode format to extract individual fields
        let xmss_sig: Signature = bincode::deserialize(&bytes)
            .map_err(|e| WrapperError::ConversionError {
                reason: format!("Failed to deserialize signature: {}", e),
            })?;

        Ok(xmss_sig)
    }

    /// Convert xmss-types::Signature to hash-sig Signature
    ///
    /// Preconditions:
    /// - xmss_sig contains valid field data
    ///
    /// Postconditions:
    /// - Returns hash-sig Signature reconstructed from fields
    /// - Signature is cryptographically equivalent to original
    pub fn from_xmss_signature<S: SignatureScheme>(
        xmss_sig: &Signature,
    ) -> Result<S::Signature, WrapperError> {
        // Serialize xmss-types signature
        let bytes = bincode::serialize(xmss_sig)?;

        // Deserialize into hash-sig signature type
        let hash_sig_signature: S::Signature = bincode::deserialize(&bytes)
            .map_err(|e| WrapperError::ConversionError {
                reason: format!("Failed to deserialize to hash-sig signature: {}", e),
            })?;

        Ok(hash_sig_signature)
    }

    /// Convert hash-sig PublicKey to xmss-types::PublicKey
    ///
    /// Preconditions:
    /// - wrapped_pk contains valid hash-sig public key
    ///
    /// Postconditions:
    /// - Returns xmss_types::PublicKey with root and parameter fields
    pub fn to_xmss_public_key<S: SignatureScheme>(
        wrapped_pk: &WrappedPublicKey<S>,
    ) -> Result<PublicKey, WrapperError> {
        // Serialize the hash-sig public key
        let bytes = bincode::serialize(&wrapped_pk.inner)?;

        // Deserialize as xmss_types::PublicKey
        let xmss_pk: PublicKey = bincode::deserialize(&bytes)
            .map_err(|e| WrapperError::ConversionError {
                reason: format!("Failed to deserialize public key: {}", e),
            })?;

        Ok(xmss_pk)
    }

    /// Convert xmss-types::PublicKey to hash-sig PublicKey
    ///
    /// Preconditions:
    /// - xmss_pk contains valid field data
    ///
    /// Postconditions:
    /// - Returns hash-sig PublicKey reconstructed from fields
    pub fn from_xmss_public_key<S: SignatureScheme>(
        xmss_pk: &PublicKey,
    ) -> Result<S::PublicKey, WrapperError> {
        // Serialize xmss-types public key
        let bytes = bincode::serialize(xmss_pk)?;

        // Deserialize into hash-sig public key type
        let hash_sig_pk: S::PublicKey = bincode::deserialize(&bytes)
            .map_err(|e| WrapperError::ConversionError {
                reason: format!("Failed to deserialize to hash-sig public key: {}", e),
            })?;

        Ok(hash_sig_pk)
    }
}

// Add conversion methods to wrapped types for convenience
impl<S: SignatureScheme> WrappedSignature<S> {
    /// Convert to xmss-types::Signature
    pub fn to_xmss_types(&self) -> Result<Signature, WrapperError> {
        TypeConverter::to_xmss_signature(self)
    }
}

impl<S: SignatureScheme> WrappedPublicKey<S> {
    /// Convert to xmss-types::PublicKey
    pub fn to_xmss_types(&self) -> Result<PublicKey, WrapperError> {
        TypeConverter::to_xmss_public_key(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xmss::config::ParameterSet;
    use crate::xmss::wrapper::XmssWrapperH18W4;
    use hashsig::signature::generalized_xmss::instantiations_sha::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W4;
    use rand::SeedableRng;

    #[test]
    fn test_signature_conversion_roundtrip() {
        // Generate a real signature using hash-sig
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let params = ParameterSet::SHA256_H18_W4;

        let (pk, sk) = XmssWrapperH18W4::key_gen(&mut rng, params, 0, 10).unwrap();
        let message = b"test message";
        let wrapped_sig = XmssWrapperH18W4::sign(&mut rng, &sk, 0, message).unwrap();

        // DEBUG: Inspect the serialized hash-sig signature
        let bytes = bincode::serialize(&wrapped_sig.inner).unwrap();
        println!("Hash-sig signature serialized length: {} bytes", bytes.len());
        println!("First 100 bytes (hex): {:02x?}", &bytes[..bytes.len().min(100)]);

        // Convert to xmss-types
        let xmss_sig = TypeConverter::to_xmss_signature(&wrapped_sig).unwrap();

        // Verify the xmss-types signature has expected structure
        assert_eq!(xmss_sig.leaf_index, 0, "Leaf index should match epoch");

        // Convert back to hash-sig
        let hash_sig_sig = TypeConverter::from_xmss_signature::<SIGWinternitzLifetime18W4>(&xmss_sig).unwrap();

        // Verify the round-trip signature still validates
        let valid = SIGWinternitzLifetime18W4::verify(
            &pk.inner,
            0,
            &crate::xmss::message::MessagePreprocessor::preprocess(message),
            &hash_sig_sig,
        );
        assert!(valid, "Round-trip signature should still be valid");
    }

    #[test]
    fn test_public_key_conversion_roundtrip() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let params = ParameterSet::SHA256_H18_W4;

        let (wrapped_pk, _) = XmssWrapperH18W4::key_gen(&mut rng, params, 0, 10).unwrap();

        // Convert to xmss-types
        let xmss_pk = TypeConverter::to_xmss_public_key(&wrapped_pk).unwrap();

        // Verify structure
        assert!(!xmss_pk.root.is_empty(), "Root should not be empty");
        assert!(!xmss_pk.parameter.is_empty(), "Parameter should not be empty");

        // Convert back to hash-sig
        let hash_sig_pk = TypeConverter::from_xmss_public_key::<SIGWinternitzLifetime18W4>(&xmss_pk).unwrap();

        // Verify the keys are equivalent by signing and verifying
        let mut rng2 = rand::rngs::StdRng::seed_from_u64(42);
        let (_, sk) = XmssWrapperH18W4::key_gen(&mut rng2, params, 0, 10).unwrap();
        let message = b"test";
        let signature = XmssWrapperH18W4::sign(&mut rng2, &sk, 0, message).unwrap();

        let valid = SIGWinternitzLifetime18W4::verify(
            &hash_sig_pk,
            0,
            &crate::xmss::message::MessagePreprocessor::preprocess(message),
            &signature.inner,
        );
        assert!(valid, "Round-trip public key should work correctly");
    }

    #[test]
    fn test_wrapped_signature_to_xmss_types_method() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let params = ParameterSet::SHA256_H18_W4;

        let (_, sk) = XmssWrapperH18W4::key_gen(&mut rng, params, 0, 10).unwrap();
        let message = b"test message";
        let wrapped_sig = XmssWrapperH18W4::sign(&mut rng, &sk, 0, message).unwrap();

        // Use the convenience method
        let xmss_sig = wrapped_sig.to_xmss_types().unwrap();

        assert_eq!(xmss_sig.leaf_index, 0);
        assert!(!xmss_sig.randomness.is_empty());
    }

    #[test]
    fn test_wrapped_public_key_to_xmss_types_method() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let params = ParameterSet::SHA256_H18_W4;

        let (wrapped_pk, _) = XmssWrapperH18W4::key_gen(&mut rng, params, 0, 10).unwrap();

        // Use the convenience method
        let xmss_pk = wrapped_pk.to_xmss_types().unwrap();

        assert!(!xmss_pk.root.is_empty());
        assert!(!xmss_pk.parameter.is_empty());
    }

    #[test]
    fn test_conversion_preserves_cryptographic_material() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let params = ParameterSet::SHA256_H18_W4;

        let (pk, sk) = XmssWrapperH18W4::key_gen(&mut rng, params, 0, 100).unwrap();
        let message = b"important message";

        // Sign with hash-sig
        let sig1 = XmssWrapperH18W4::sign(&mut rng, &sk, 5, message).unwrap();

        // Convert to xmss-types and back
        let xmss_sig = sig1.to_xmss_types().unwrap();
        let sig2 = TypeConverter::from_xmss_signature::<SIGWinternitzLifetime18W4>(&xmss_sig).unwrap();

        // Both signatures should verify
        let digest = crate::xmss::message::MessagePreprocessor::preprocess(message);
        let valid1 = SIGWinternitzLifetime18W4::verify(&pk.inner, 5, &digest, &sig1.inner);
        let valid2 = SIGWinternitzLifetime18W4::verify(&pk.inner, 5, &digest, &sig2);

        assert!(valid1, "Original signature should be valid");
        assert!(valid2, "Converted signature should be valid");
    }

    #[test]
    fn test_conversion_error_handling() {
        // Test with invalid data
        let invalid_sig = Signature {
            leaf_index: 0,
            randomness: vec![],  // Invalid: empty
            wots_chain_ends: vec![],
            auth_path: vec![],
        };

        let result = TypeConverter::from_xmss_signature::<SIGWinternitzLifetime18W4>(&invalid_sig);

        // Should return an error (structure mismatch)
        assert!(result.is_err(), "Should fail with invalid signature structure");

        if let Err(WrapperError::ConversionError { reason }) = result {
            assert!(!reason.is_empty(), "Error should have description");
        } else {
            panic!("Expected ConversionError");
        }
    }
}
