// Type conversion layer between xmss-types and hash-sig types
//
// Since hash-sig types have private fields, we use serde serialization
// to convert between xmss-types and hash-sig types via bincode.

use hashsig::signature::generalized_xmss::instantiations_sha::SIGWinternitzLifetime10W4;
use hashsig::signature::SignatureScheme;
use xmss_types::{PublicKey as XmssTypesPublicKey, Signature as XmssTypesSignature};

// Type aliases for concrete instantiation (SIGWinternitzLifetime10W4)
pub type HashSigPublicKey = <SIGWinternitzLifetime10W4 as SignatureScheme>::PublicKey;
pub type HashSigSignature = <SIGWinternitzLifetime10W4 as SignatureScheme>::Signature;
pub type HashSigSecretKey = <SIGWinternitzLifetime10W4 as SignatureScheme>::SecretKey;

// Convert hash-sig PublicKey to xmss-types PublicKey using serde
impl From<&HashSigPublicKey> for XmssTypesPublicKey {
    fn from(pk: &HashSigPublicKey) -> Self {
        // Serialize hash-sig PublicKey to bytes
        let bytes = bincode::serialize(pk).expect("Failed to serialize PublicKey");

        // For now, store serialized bytes directly
        // This preserves all information without accessing private fields
        XmssTypesPublicKey {
            root: bytes.clone(),
            parameter: vec![], // Empty for now, full data in root
        }
    }
}

// Convert hash-sig Signature to xmss-types Signature using serde
impl From<&HashSigSignature> for XmssTypesSignature {
    fn from(sig: &HashSigSignature) -> Self {
        // Serialize hash-sig Signature to bytes
        let bytes = bincode::serialize(sig).expect("Failed to serialize Signature");

        // Store serialized signature data
        XmssTypesSignature {
            leaf_index: 0, // Placeholder, actual data in randomness
            randomness: bytes,
            wots_chain_ends: vec![],
            auth_path: vec![],
        }
    }
}

// Convert xmss-types PublicKey to hash-sig PublicKey
impl TryFrom<&XmssTypesPublicKey> for HashSigPublicKey {
    type Error = String;

    fn try_from(pk: &XmssTypesPublicKey) -> Result<Self, Self::Error> {
        // Deserialize from bytes stored in root field
        bincode::deserialize(&pk.root)
            .map_err(|e| format!("Failed to deserialize PublicKey: {}", e))
    }
}

// Convert xmss-types Signature to hash-sig Signature
impl TryFrom<&XmssTypesSignature> for HashSigSignature {
    type Error = String;

    fn try_from(sig: &XmssTypesSignature) -> Result<Self, Self::Error> {
        // Deserialize from bytes stored in randomness field
        bincode::deserialize(&sig.randomness)
            .map_err(|e| format!("Failed to deserialize Signature: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_round_trip() {
        let mut rng = rand::rng();

        // Generate a real hash-sig keypair
        let (pk, _sk) = SIGWinternitzLifetime10W4::key_gen(&mut rng, 0, 1024);

        // Convert to xmss-types
        let xmss_pk = XmssTypesPublicKey::from(&pk);

        // Convert back to hash-sig
        let converted_back: HashSigPublicKey = (&xmss_pk).try_into().unwrap();

        // Serialize both and compare (since we can't access private fields)
        let original_bytes = bincode::serialize(&pk).unwrap();
        let converted_bytes = bincode::serialize(&converted_back).unwrap();

        assert_eq!(original_bytes, converted_bytes);
    }

    #[test]
    fn test_signature_round_trip() {
        let mut rng = rand::rng();

        // Generate keypair and sign
        let (pk, sk) = SIGWinternitzLifetime10W4::key_gen(&mut rng, 0, 1024);
        let message = [0u8; 32];
        let sig = SIGWinternitzLifetime10W4::sign(&mut rng, &sk, 0, &message).unwrap();

        // Convert to xmss-types
        let xmss_sig = XmssTypesSignature::from(&sig);

        // Convert back to hash-sig
        let converted_back: HashSigSignature = (&xmss_sig).try_into().unwrap();

        // Verify converted signature works
        assert!(SIGWinternitzLifetime10W4::verify(
            &pk,
            0,
            &message,
            &converted_back
        ));
    }

    #[test]
    fn test_invalid_deserialization() {
        let invalid_pk = XmssTypesPublicKey {
            root: vec![0xFFu8; 10], // Invalid bincode data
            parameter: vec![],
        };

        assert!(HashSigPublicKey::try_from(&invalid_pk).is_err());
    }
}
