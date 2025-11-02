// Message preprocessing for hash-sig 32-byte requirement

use sha2::{Digest, Sha256};

/// Message preprocessor that converts arbitrary-length messages to 32-byte digests
pub struct MessagePreprocessor;

impl MessagePreprocessor {
    /// Hash message to 32-byte digest using SHA-256
    ///
    /// Preconditions: None (accepts any byte slice)
    /// Postconditions: Returns exactly 32 bytes
    /// Invariants: Same input always produces same output (deterministic hash)
    pub fn preprocess(message: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preprocess_arbitrary_message_to_32_bytes() {
        // Test various message lengths all produce exactly 32 bytes
        let test_cases = vec![
            vec![],                            // Empty message
            vec![0x42],                        // Single byte
            b"Hello, World!".to_vec(),         // Small message
            vec![0x00; 31],                    // Just under 32 bytes
            vec![0xFF; 32],                    // Exactly 32 bytes
            vec![0xAA; 33],                    // Just over 32 bytes
            vec![0x55; 100],                   // Moderate length
            vec![0x12; 1000],                  // Large message
        ];

        for message in test_cases {
            let digest = MessagePreprocessor::preprocess(&message);
            assert_eq!(
                digest.len(),
                32,
                "Digest should be exactly 32 bytes for message of length {}",
                message.len()
            );
        }
    }

    #[test]
    fn test_preprocess_deterministic() {
        // Same message should always produce same digest
        let message = b"Test message for determinism";

        let digest1 = MessagePreprocessor::preprocess(message);
        let digest2 = MessagePreprocessor::preprocess(message);
        let digest3 = MessagePreprocessor::preprocess(message);

        assert_eq!(digest1, digest2, "First and second digest should match");
        assert_eq!(digest2, digest3, "Second and third digest should match");
        assert_eq!(digest1, digest3, "First and third digest should match");
    }

    #[test]
    fn test_preprocess_different_messages_different_digests() {
        // Different messages should produce different digests
        let message1 = b"Message one";
        let message2 = b"Message two";
        let message3 = b"Completely different message";

        let digest1 = MessagePreprocessor::preprocess(message1);
        let digest2 = MessagePreprocessor::preprocess(message2);
        let digest3 = MessagePreprocessor::preprocess(message3);

        assert_ne!(digest1, digest2, "Different messages should have different digests");
        assert_ne!(digest2, digest3, "Different messages should have different digests");
        assert_ne!(digest1, digest3, "Different messages should have different digests");
    }

    #[test]
    fn test_preprocess_empty_message() {
        // Empty message should still produce valid 32-byte digest
        let empty_message: &[u8] = &[];
        let digest = MessagePreprocessor::preprocess(empty_message);

        assert_eq!(digest.len(), 32, "Empty message should produce 32-byte digest");
        assert_ne!(
            digest,
            [0u8; 32],
            "Empty message digest should not be all zeros"
        );

        // Verify it's the correct SHA-256 hash of empty message
        let expected = sha2::Sha256::digest(b"");
        assert_eq!(
            digest,
            expected.as_slice(),
            "Should match standard SHA-256 of empty input"
        );
    }

    #[test]
    fn test_preprocess_very_long_message() {
        // Test with message >1MB
        let large_message = vec![0x42u8; 1_000_000];
        let digest = MessagePreprocessor::preprocess(&large_message);

        assert_eq!(digest.len(), 32, "Large message should produce 32-byte digest");

        // Verify determinism for large messages
        let digest2 = MessagePreprocessor::preprocess(&large_message);
        assert_eq!(
            digest, digest2,
            "Large message should produce consistent digest"
        );
    }

    #[test]
    fn test_preprocess_32_byte_message() {
        // Even if message is already 32 bytes, it should still be hashed
        let message_32bytes = [0x77u8; 32];
        let digest = MessagePreprocessor::preprocess(&message_32bytes);

        assert_eq!(digest.len(), 32, "Should produce 32-byte digest");

        // The digest should NOT be the same as the input (it gets hashed)
        assert_ne!(
            digest, message_32bytes,
            "32-byte input should be hashed, not passed through"
        );
    }

    #[test]
    fn test_preprocess_matches_standard_sha256() {
        // Verify our preprocessing uses standard SHA-256
        let test_message = b"Test message for SHA-256 verification";

        let our_digest = MessagePreprocessor::preprocess(test_message);
        let expected_digest = sha2::Sha256::digest(test_message);

        assert_eq!(
            our_digest,
            expected_digest.as_slice(),
            "Should match standard SHA-256 implementation"
        );
    }
}
