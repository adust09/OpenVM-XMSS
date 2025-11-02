// Error types for the XMSS wrapper layer

use thiserror::Error;

#[derive(Debug, Error)]
pub enum WrapperError {
    /// Hash-sig library error (wraps underlying error)
    #[error("Hash-sig error: {0}")]
    HashSigError(String),

    /// Epoch value outside valid range for secret key
    #[error("Epoch {epoch} outside valid range [{activation_epoch}, {end_epoch}) for LIFETIME {lifetime}")]
    EpochOutOfRange {
        epoch: u32,
        activation_epoch: u32,
        end_epoch: u32,
        lifetime: u32,
    },

    /// Type conversion failed between hash-sig and xmss-types
    #[error("Type conversion failed: {reason}")]
    ConversionError { reason: String },

    /// Message hashing failed (should never happen with SHA-256)
    #[error("Message hashing failed: {0}")]
    MessageHashingError(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Parameter configuration error
    #[error("Invalid parameter configuration: {0}")]
    ParameterError(String),
}

// Implement From for bincode::Error
impl From<bincode::Error> for WrapperError {
    fn from(err: bincode::Error) -> Self {
        WrapperError::SerializationError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrapper_error_variants_can_be_constructed() {
        // Test HashSigError variant
        let hash_sig_err = WrapperError::HashSigError("test error".to_string());
        assert!(hash_sig_err.to_string().contains("Hash-sig error"));
        assert!(hash_sig_err.to_string().contains("test error"));

        // Test EpochOutOfRange variant with all fields
        let epoch_err = WrapperError::EpochOutOfRange {
            epoch: 100,
            activation_epoch: 0,
            end_epoch: 50,
            lifetime: 1024,
        };
        let err_msg = epoch_err.to_string();
        assert!(err_msg.contains("100"));
        assert!(err_msg.contains("[0, 50)"));
        assert!(err_msg.contains("1024"));

        // Test ConversionError variant
        let conv_err = WrapperError::ConversionError {
            reason: "field mismatch".to_string(),
        };
        assert!(conv_err.to_string().contains("Type conversion failed"));
        assert!(conv_err.to_string().contains("field mismatch"));

        // Test MessageHashingError variant
        let msg_err = WrapperError::MessageHashingError("hash failed".to_string());
        assert!(msg_err.to_string().contains("Message hashing failed"));
        assert!(msg_err.to_string().contains("hash failed"));

        // Test SerializationError variant
        let ser_err = WrapperError::SerializationError("bincode error".to_string());
        assert!(ser_err.to_string().contains("Serialization error"));
        assert!(ser_err.to_string().contains("bincode error"));

        // Test ParameterError variant
        let param_err = WrapperError::ParameterError("invalid height".to_string());
        assert!(param_err.to_string().contains("Invalid parameter configuration"));
        assert!(param_err.to_string().contains("invalid height"));
    }

    #[test]
    fn test_epoch_out_of_range_includes_all_fields() {
        let err = WrapperError::EpochOutOfRange {
            epoch: 500,
            activation_epoch: 10,
            end_epoch: 100,
            lifetime: 1024,
        };

        let msg = err.to_string();

        // Verify all required fields are present in error message
        assert!(msg.contains("500"), "Should contain epoch value");
        assert!(msg.contains("10"), "Should contain activation_epoch");
        assert!(msg.contains("100"), "Should contain end_epoch");
        assert!(msg.contains("1024"), "Should contain lifetime");

        // Verify format includes range notation
        assert!(msg.contains("[10, 100)"), "Should show range in correct format");
    }

    #[test]
    fn test_error_from_bincode() {
        // Create a bincode error by attempting invalid deserialization
        let invalid_data: Vec<u8> = vec![0xFF, 0xFF, 0xFF];
        let bincode_result: Result<u32, bincode::Error> = bincode::deserialize(&invalid_data);

        match bincode_result {
            Err(bincode_err) => {
                let wrapper_err: WrapperError = bincode_err.into();
                match wrapper_err {
                    WrapperError::SerializationError(msg) => {
                        assert!(!msg.is_empty(), "Error message should not be empty");
                    }
                    _ => panic!("Expected SerializationError variant"),
                }
            }
            Ok(_) => panic!("Expected bincode error"),
        }
    }

    #[test]
    fn test_error_display_human_readable() {
        // Test that all error variants produce human-readable messages
        let errors = vec![
            WrapperError::HashSigError("encoding attempts exceeded".to_string()),
            WrapperError::EpochOutOfRange {
                epoch: 200,
                activation_epoch: 0,
                end_epoch: 100,
                lifetime: 1024,
            },
            WrapperError::ConversionError {
                reason: "signature field missing".to_string(),
            },
            WrapperError::MessageHashingError("unexpected hash failure".to_string()),
            WrapperError::SerializationError("failed to serialize".to_string()),
            WrapperError::ParameterError("tree height too large".to_string()),
        ];

        for err in errors {
            let msg = err.to_string();
            // All messages should be non-empty and contain useful information
            assert!(!msg.is_empty(), "Error message should not be empty");
            assert!(msg.len() > 10, "Error message should be descriptive");
        }
    }

    #[test]
    fn test_error_debug_format() {
        let err = WrapperError::EpochOutOfRange {
            epoch: 42,
            activation_epoch: 0,
            end_epoch: 10,
            lifetime: 1024,
        };

        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("EpochOutOfRange"));
        assert!(debug_str.contains("42"));
    }
}
