// Epoch validation logic

use crate::xmss::error::WrapperError;

/// Epoch validator for range checking and validation
pub struct EpochValidator;

impl EpochValidator {
    /// Validate epoch range at key generation
    ///
    /// Preconditions:
    /// - lifetime is SignatureScheme::LIFETIME constant
    ///
    /// Postconditions:
    /// - Returns Ok if activation_epoch + num_active_epochs <= lifetime
    /// - Returns Err(EpochOutOfRange) otherwise
    ///
    /// Invariants:
    /// - Deterministic validation based on integer arithmetic
    pub fn validate_epoch_range(
        activation_epoch: u32,
        num_active_epochs: u32,
        lifetime: u32,
    ) -> Result<(), WrapperError> {
        let end_epoch = activation_epoch
            .checked_add(num_active_epochs)
            .ok_or_else(|| WrapperError::EpochOutOfRange {
                epoch: activation_epoch,
                activation_epoch,
                end_epoch: u32::MAX,
                lifetime,
            })?;

        if end_epoch > lifetime {
            return Err(WrapperError::EpochOutOfRange {
                epoch: end_epoch,
                activation_epoch,
                end_epoch,
                lifetime,
            });
        }

        Ok(())
    }

    /// Validate epoch for signing operation
    ///
    /// Preconditions:
    /// - activation_epoch and num_active_epochs from WrappedSecretKey
    ///
    /// Postconditions:
    /// - Returns Ok if activation_epoch <= epoch < activation_epoch + num_active_epochs
    /// - Returns Err(EpochOutOfRange) otherwise
    ///
    /// Invariants:
    /// - Deterministic validation based on range check
    pub fn validate_epoch(
        epoch: u32,
        activation_epoch: u32,
        num_active_epochs: u32,
    ) -> Result<(), WrapperError> {
        let end_epoch = activation_epoch
            .checked_add(num_active_epochs)
            .ok_or_else(|| WrapperError::EpochOutOfRange {
                epoch,
                activation_epoch,
                end_epoch: u32::MAX,
                lifetime: u32::MAX,
            })?;

        if epoch < activation_epoch || epoch >= end_epoch {
            return Err(WrapperError::EpochOutOfRange {
                epoch,
                activation_epoch,
                end_epoch,
                lifetime: end_epoch - activation_epoch,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests for validate_epoch_range (key generation)

    #[test]
    fn test_validate_epoch_range_valid() {
        // Test valid epoch ranges that should succeed
        let lifetime = 1024u32;

        // Zero activation, full range
        assert!(
            EpochValidator::validate_epoch_range(0, 1024, lifetime).is_ok(),
            "Full range from 0 should be valid"
        );

        // Zero activation, partial range
        assert!(
            EpochValidator::validate_epoch_range(0, 100, lifetime).is_ok(),
            "Partial range from 0 should be valid"
        );

        // Mid-range activation
        assert!(
            EpochValidator::validate_epoch_range(100, 500, lifetime).is_ok(),
            "Mid-range activation should be valid"
        );

        // Activation near end, small range
        assert!(
            EpochValidator::validate_epoch_range(1000, 24, lifetime).is_ok(),
            "Small range near end should be valid"
        );

        // Edge case: exactly at lifetime boundary
        assert!(
            EpochValidator::validate_epoch_range(1023, 1, lifetime).is_ok(),
            "Range exactly at lifetime boundary should be valid"
        );
    }

    #[test]
    fn test_validate_epoch_range_exceeds_lifetime() {
        let lifetime = 1024u32;

        // Range exceeds lifetime
        let result = EpochValidator::validate_epoch_range(0, 1025, lifetime);
        assert!(result.is_err(), "Range exceeding lifetime should fail");

        match result {
            Err(WrapperError::EpochOutOfRange {
                activation_epoch,
                end_epoch,
                lifetime: l,
                ..
            }) => {
                assert_eq!(activation_epoch, 0);
                assert_eq!(end_epoch, 1025);
                assert_eq!(l, lifetime);
            }
            _ => panic!("Expected EpochOutOfRange error"),
        }

        // Mid-range activation exceeding lifetime
        let result = EpochValidator::validate_epoch_range(500, 600, lifetime);
        assert!(
            result.is_err(),
            "Mid-range activation exceeding lifetime should fail"
        );

        // Activation already at lifetime
        let result = EpochValidator::validate_epoch_range(1024, 1, lifetime);
        assert!(
            result.is_err(),
            "Activation at lifetime with any range should fail"
        );
    }

    #[test]
    fn test_validate_epoch_range_zero_activation() {
        let lifetime = 1024u32;

        // Valid zero activation
        assert!(
            EpochValidator::validate_epoch_range(0, 1024, lifetime).is_ok(),
            "Zero activation with full lifetime should be valid"
        );

        assert!(
            EpochValidator::validate_epoch_range(0, 1, lifetime).is_ok(),
            "Zero activation with range 1 should be valid"
        );
    }

    #[test]
    fn test_validate_epoch_range_maximum_valid() {
        let lifetime = 1024u32;

        // Test maximum valid range
        assert!(
            EpochValidator::validate_epoch_range(0, 1024, lifetime).is_ok(),
            "Maximum valid range (0 to LIFETIME) should be accepted"
        );
    }

    #[test]
    fn test_validate_epoch_range_error_includes_values() {
        let lifetime = 1024u32;

        let result = EpochValidator::validate_epoch_range(500, 600, lifetime);

        match result {
            Err(WrapperError::EpochOutOfRange {
                epoch: _,
                activation_epoch,
                end_epoch,
                lifetime: l,
            }) => {
                assert_eq!(activation_epoch, 500, "Should include activation_epoch");
                assert_eq!(end_epoch, 1100, "Should include calculated end_epoch");
                assert_eq!(l, lifetime, "Should include lifetime value");

                let err_msg = format!(
                    "Epoch {} outside valid range [{}, {}) for LIFETIME {}",
                    end_epoch, activation_epoch, end_epoch, l
                );
                assert!(
                    err_msg.contains("500"),
                    "Error message should contain values for debugging"
                );
            }
            _ => panic!("Expected EpochOutOfRange error"),
        }
    }

    // Tests for validate_epoch (signing operation)

    #[test]
    fn test_validate_epoch_within_range() {
        let activation_epoch = 100u32;
        let num_active_epochs = 50u32;

        // Test epochs within valid range
        assert!(
            EpochValidator::validate_epoch(100, activation_epoch, num_active_epochs).is_ok(),
            "Epoch at activation boundary should be valid"
        );

        assert!(
            EpochValidator::validate_epoch(125, activation_epoch, num_active_epochs).is_ok(),
            "Epoch in middle of range should be valid"
        );

        assert!(
            EpochValidator::validate_epoch(149, activation_epoch, num_active_epochs).is_ok(),
            "Epoch just before end should be valid"
        );
    }

    #[test]
    fn test_validate_epoch_at_activation_boundary() {
        let activation_epoch = 100u32;
        let num_active_epochs = 50u32;

        // Epoch equal to activation_epoch should be valid
        let result = EpochValidator::validate_epoch(100, activation_epoch, num_active_epochs);
        assert!(
            result.is_ok(),
            "Epoch equal to activation_epoch should be valid (inclusive lower bound)"
        );
    }

    #[test]
    fn test_validate_epoch_at_end_boundary() {
        let activation_epoch = 100u32;
        let num_active_epochs = 50u32;
        let end_epoch = activation_epoch + num_active_epochs; // 150

        // Epoch equal to end_epoch should be INVALID (exclusive upper bound)
        let result = EpochValidator::validate_epoch(end_epoch, activation_epoch, num_active_epochs);
        assert!(
            result.is_err(),
            "Epoch equal to end_epoch should be invalid (exclusive upper bound)"
        );
    }

    #[test]
    fn test_validate_epoch_below_activation() {
        let activation_epoch = 100u32;
        let num_active_epochs = 50u32;

        // Test epoch below activation_epoch
        let result = EpochValidator::validate_epoch(99, activation_epoch, num_active_epochs);
        assert!(
            result.is_err(),
            "Epoch below activation_epoch should be invalid"
        );

        match result {
            Err(WrapperError::EpochOutOfRange {
                epoch,
                activation_epoch: act,
                end_epoch,
                ..
            }) => {
                assert_eq!(epoch, 99);
                assert_eq!(act, 100);
                assert_eq!(end_epoch, 150);
            }
            _ => panic!("Expected EpochOutOfRange error"),
        }

        // Test epoch far below activation
        let result = EpochValidator::validate_epoch(0, activation_epoch, num_active_epochs);
        assert!(result.is_err(), "Epoch 0 should be invalid when activation is 100");
    }

    #[test]
    fn test_validate_epoch_above_range() {
        let activation_epoch = 100u32;
        let num_active_epochs = 50u32;

        // Test epoch above end_epoch
        let result = EpochValidator::validate_epoch(150, activation_epoch, num_active_epochs);
        assert!(
            result.is_err(),
            "Epoch at end_epoch (exclusive) should be invalid"
        );

        let result = EpochValidator::validate_epoch(151, activation_epoch, num_active_epochs);
        assert!(result.is_err(), "Epoch above end_epoch should be invalid");

        let result = EpochValidator::validate_epoch(1000, activation_epoch, num_active_epochs);
        assert!(result.is_err(), "Epoch far above range should be invalid");
    }

    #[test]
    fn test_validate_epoch_error_includes_values() {
        let activation_epoch = 100u32;
        let num_active_epochs = 50u32;

        let result = EpochValidator::validate_epoch(200, activation_epoch, num_active_epochs);

        match result {
            Err(WrapperError::EpochOutOfRange {
                epoch,
                activation_epoch: act,
                end_epoch,
                lifetime,
            }) => {
                assert_eq!(epoch, 200, "Should include requested epoch");
                assert_eq!(act, 100, "Should include activation_epoch");
                assert_eq!(end_epoch, 150, "Should include calculated end_epoch");
                assert_eq!(lifetime, 50, "Should include valid range size");
            }
            _ => panic!("Expected EpochOutOfRange error"),
        }
    }

    #[test]
    fn test_validate_epoch_zero_activation() {
        let activation_epoch = 0u32;
        let num_active_epochs = 100u32;

        // Valid epochs for zero activation
        assert!(
            EpochValidator::validate_epoch(0, activation_epoch, num_active_epochs).is_ok(),
            "Epoch 0 should be valid with zero activation"
        );

        assert!(
            EpochValidator::validate_epoch(50, activation_epoch, num_active_epochs).is_ok(),
            "Mid-range epoch should be valid"
        );

        assert!(
            EpochValidator::validate_epoch(99, activation_epoch, num_active_epochs).is_ok(),
            "Epoch 99 should be valid (end is 100, exclusive)"
        );

        // Invalid epoch at boundary
        assert!(
            EpochValidator::validate_epoch(100, activation_epoch, num_active_epochs).is_err(),
            "Epoch 100 should be invalid (exclusive upper bound)"
        );
    }
}
