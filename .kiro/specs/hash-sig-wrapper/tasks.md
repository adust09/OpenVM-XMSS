# Implementation Plan

## Overview

This implementation follows Test-Driven Development (TDD) methodology: write tests first, verify they fail, implement functionality, verify tests pass. Each task builds incrementally toward a complete hash-sig wrapper layer that provides ergonomic API, message preprocessing, epoch validation, and type conversion between hash-sig and xmss-types.

---

- [ ] 1. Prepare project dependencies and module structure
  - Upgrade rand dependency from 0.8 to 0.9 in workspace Cargo.toml to match hash-sig requirements
  - Add sha2 crate for SHA-256 message preprocessing
  - Add thiserror crate for error handling derive macros
  - Create empty module structure in lib/src/xmss/ for wrapper, error, message, epoch, conversions, config, test_utils
  - Update lib/src/lib.rs to export xmss module and key wrapper types
  - Verify project compiles with new dependencies
  - _Requirements: All requirements depend on proper dependency setup_

- [ ] 2. Implement comprehensive error handling system
- [ ] 2.1 Define error taxonomy with all failure modes
  - Write test: Verify each error variant can be constructed and displayed with appropriate messages
  - Write test: Verify EpochOutOfRange includes epoch, activation_epoch, end_epoch, and lifetime fields
  - Write test: Verify error conversion from hash-sig SigningError and bincode Error
  - Implement WrapperError enum with variants: HashSigError, EpochOutOfRange, ConversionError, MessageHashingError, SerializationError, ParameterError
  - Implement Display trait with human-readable messages including context values
  - Implement From traits for automatic conversion from hash-sig and bincode errors
  - Verify all tests pass
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6_

- [ ] 3. Build message preprocessing functionality
- [ ] 3.1 Implement SHA-256 message hashing to 32 bytes
  - Write test: Arbitrary-length messages are hashed to exactly 32 bytes
  - Write test: Same message produces same digest (deterministic)
  - Write test: Different messages produce different digests
  - Write test: Empty message is hashed successfully
  - Write test: Very long messages (>1MB) are hashed successfully
  - Implement MessagePreprocessor with preprocess function using sha2::Sha256
  - Apply SHA-256 to all messages regardless of input length (always-hash strategy)
  - Verify all tests pass
  - _Requirements: 2.1, 2.2, 2.3, 2.4_

- [ ] 4. Create epoch validation logic with range checking
- [ ] 4.1 Implement key generation epoch range validation
  - Write test: Valid epoch range (activation + num_active <= LIFETIME) returns Ok
  - Write test: Epoch range exceeding LIFETIME returns EpochOutOfRange error
  - Write test: Zero activation_epoch with valid num_active_epochs is accepted
  - Write test: Maximum valid range (0 to LIFETIME) is accepted
  - Write test: Error message includes actual values for debugging
  - Implement EpochValidator::validate_epoch_range with integer arithmetic check
  - Return detailed EpochOutOfRange error with all relevant values when validation fails
  - Verify all tests pass
  - _Requirements: 3.1, 3.2_

- [ ] 4.2 Implement signing epoch validation against secret key range
  - Write test: Epoch within active range returns Ok
  - Write test: Epoch equal to activation_epoch is valid (boundary condition)
  - Write test: Epoch equal to activation_epoch + num_active_epochs is invalid (boundary condition)
  - Write test: Epoch below activation_epoch returns EpochOutOfRange error
  - Write test: Epoch above range returns EpochOutOfRange error
  - Implement EpochValidator::validate_epoch with range check: activation <= epoch < activation + num_active
  - Return descriptive error including requested epoch and valid range
  - Verify all tests pass
  - _Requirements: 3.3, 3.4, 3.5_

- [ ] 5. Implement parameter configuration and metadata system
- [ ] 5.1 Define XMSS parameter sets with metadata
  - Write test: Each ParameterSet variant returns correct metadata (lifetime, tree_height, winternitz_parameter)
  - Write test: SHA256_H10_W4 has lifetime = 1024, tree_height = 10, winternitz = 4
  - Write test: SHA256_H16_W4 has lifetime = 65536, tree_height = 16
  - Write test: SHA256_H20_W4 has lifetime = 1048576, tree_height = 20
  - Write test: ParameterMetadata converts to TslParams with correct field mapping
  - Implement ParameterSet enum with three variants
  - Implement ParameterMetadata struct with all required fields
  - Implement metadata() method returning ParameterMetadata for each variant
  - Implement to_tsl_params() conversion to xmss_types::TslParams
  - Verify all tests pass
  - _Requirements: 8.1, 8.2, 8.3, 8.5_

- [ ] 6. Build type conversion layer between hash-sig and xmss-types
- [ ] 6.1 Implement signature conversion using serialization strategy
  - Write test: hash-sig signature converts to xmss_types::Signature with correct fields
  - Write test: xmss_types::Signature converts back to hash-sig signature
  - Write test: Round-trip conversion preserves all cryptographic material
  - Write test: Conversion extracts correct leaf_index, randomness, wots_chain_ends, auth_path
  - Write test: Invalid bincode data returns ConversionError with reason
  - Implement TypeConverter::to_xmss_signature using bincode serialization and custom parsing
  - Implement TypeConverter::from_xmss_signature reconstructing bincode bytes from fields
  - Parse bincode bytes to extract signature components into xmss_types structure
  - Handle conversion errors with descriptive ConversionError messages
  - Verify all tests pass
  - _Requirements: 4.1, 4.2, 4.3, 4.7_

- [ ] 6.2 Implement public key conversion between formats
  - Write test: hash-sig PublicKey converts to xmss_types::PublicKey with root and parameter fields
  - Write test: xmss_types::PublicKey converts back to hash-sig PublicKey
  - Write test: Round-trip conversion preserves cryptographic material exactly
  - Write test: Serialization format is consistent and documented
  - Implement TypeConverter::to_xmss_public_key via bincode serialization
  - Implement TypeConverter::from_xmss_public_key via bincode deserialization
  - Extract root and parameter fields from serialized hash-sig PublicKey
  - Verify all tests pass
  - _Requirements: 4.4, 4.5, 4.6, 4.7_

- [ ] 7. Implement wrapper types with metadata and serialization
- [ ] 7.1 Create wrapped key and signature types
  - Write test: WrappedPublicKey serializes and deserializes with serde
  - Write test: WrappedSecretKey serializes with epoch metadata preserved
  - Write test: WrappedSignature serializes with epoch field
  - Write test: Bincode serialization round-trip preserves all fields
  - Write test: JSON serialization works for debugging purposes
  - Implement WrappedPublicKey struct wrapping hash-sig PublicKey with ParameterMetadata
  - Implement WrappedSecretKey struct with activation_epoch and num_active_epochs metadata
  - Implement WrappedSignature struct with epoch field
  - Derive Serialize and Deserialize for all wrapper types
  - Verify all tests pass
  - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5_

- [ ] 7.2 Add conversion methods from wrapper types to xmss-types
  - Write test: WrappedPublicKey::to_xmss_types() returns xmss_types::PublicKey
  - Write test: WrappedSignature::to_xmss_types() returns xmss_types::Signature
  - Write test: Conversions preserve all cryptographic data
  - Implement to_xmss_types() methods on wrapper types delegating to TypeConverter
  - Verify all tests pass
  - _Requirements: 4.1, 4.4_

- [ ] 8. Implement core XmssWrapper API for key generation
- [ ] 8.1 Build key generation with epoch validation and RNG integration
  - Write test: Valid epoch range generates keys successfully
  - Write test: Invalid epoch range returns EpochOutOfRange error before calling hash-sig
  - Write test: Generated keys contain correct epoch metadata
  - Write test: Seeded StdRng produces deterministic keys for testing
  - Write test: Different RNG seeds produce different keys
  - Write test: Keys work with rand::thread_rng() for production randomness
  - Implement XmssWrapper::key_gen accepting RngCore, activation_epoch, num_active_epochs
  - Validate epoch range before invoking hash-sig SignatureScheme::key_gen
  - Wrap returned hash-sig keys in WrappedPublicKey and WrappedSecretKey with metadata
  - Support generic RNG parameter implementing rand::RngCore for flexibility
  - Verify all tests pass
  - _Requirements: 1.1, 1.2, 3.1, 3.2, 7.1, 7.2_

- [ ] 9. Implement signing functionality with preprocessing and validation
- [ ] 9.1 Build signing with message preprocessing and epoch validation
  - Write test: Sign arbitrary-length message with valid epoch succeeds
  - Write test: Sign rejects epoch outside secret key's active range
  - Write test: Message is hashed to 32 bytes before signing (verified via signature validation)
  - Write test: Same message and epoch produce valid signatures (probabilistic)
  - Write test: Different epochs produce different signatures for same message
  - Write test: hash-sig EncodingAttemptsExceeded error is wrapped in WrapperError
  - Implement XmssWrapper::sign accepting RngCore, WrappedSecretKey, epoch, message
  - Preprocess message using MessagePreprocessor to get 32-byte digest
  - Validate epoch against secret key's activation and num_active_epochs range
  - Invoke hash-sig SignatureScheme::sign with preprocessed message
  - Wrap returned signature in WrappedSignature with epoch metadata
  - Propagate hash-sig errors through WrapperError::HashSigError
  - Verify all tests pass
  - _Requirements: 1.1, 1.3, 2.1, 2.2, 2.4, 3.3, 3.4, 7.1_

- [ ] 10. Implement verification functionality
- [ ] 10.1 Build verification with message preprocessing
  - Write test: Verify valid signature returns true
  - Write test: Verify invalid signature returns false (no error thrown)
  - Write test: Message is hashed before verification (consistent with signing)
  - Write test: Verification is deterministic for same inputs
  - Write test: Signature from different message fails verification
  - Write test: Signature from different epoch fails verification
  - Implement XmssWrapper::verify accepting WrappedPublicKey, epoch, message, WrappedSignature
  - Preprocess message using MessagePreprocessor to get 32-byte digest
  - Invoke hash-sig SignatureScheme::verify with preprocessed message
  - Return boolean result directly (no error for invalid signatures)
  - Verify all tests pass
  - _Requirements: 1.1, 1.4, 2.1, 2.4_

- [ ] 11. Add metadata querying and helper methods
- [ ] 11.1 Implement parameter metadata access
  - Write test: XmssWrapper::metadata() returns correct LIFETIME, tree_height, winternitz_parameter
  - Write test: WrappedSecretKey provides method to query remaining signature capacity
  - Write test: Capacity calculation is correct: num_active_epochs - (current_epoch - activation_epoch)
  - Implement XmssWrapper::metadata() returning ParameterMetadata from type parameter
  - Implement query methods on WrappedSecretKey for epoch information
  - Verify all tests pass
  - _Requirements: 1.5, 3.5, 8.3_

- [ ] 12. Create test utilities for deterministic testing
- [ ] 12.1 Build testing helper functions
  - Write test: test_key_gen produces deterministic keys with seeded RNG
  - Write test: test_rng produces reproducible StdRng
  - Write test: Multiple calls to test_key_gen with same seed produce identical keys
  - Implement test_utils module with #[cfg(test)] guard
  - Implement test_key_gen helper using fixed seed for determinism
  - Implement test_rng returning seeded StdRng for reproducible tests
  - Verify all tests pass
  - _Requirements: 10.1_

- [ ] 13. Develop integration tests for end-to-end workflows
- [ ] 13.1 Test complete key generation, signing, and verification workflow
  - Write integration test: Generate keys, sign message, verify signature succeeds
  - Write integration test: Sign multiple messages at different epochs
  - Write integration test: Verify epoch management prevents reuse beyond range
  - Write integration test: Type conversion from wrapper to xmss-types works end-to-end
  - Create lib/tests/wrapper_integration.rs for integration tests
  - Test complete workflows from key generation through verification
  - Verify wrapper integrates correctly with hash-sig library
  - _Requirements: 10.4_

- [ ] 13.2 Test error handling and recovery scenarios
  - Write integration test: EpochOutOfRange error includes all diagnostic information
  - Write integration test: ConversionError provides actionable messages
  - Write integration test: SigningError from hash-sig is properly wrapped and propagated
  - Write integration test: Conversion failures don't panic (graceful error returns)
  - Create lib/tests/error_handling.rs for error scenario tests
  - Test each error variant can be triggered and returns expected error type
  - Verify error messages include context for debugging
  - _Requirements: 6.3, 6.5, 6.6, 10.6_

- [ ] 13.3 Test parameter sets and configuration
  - Write integration test: Key generation works with each ParameterSet variant (H10, H16, H20)
  - Write integration test: ParameterMetadata matches hash-sig constants for each set
  - Write integration test: TslParams conversion preserves parameter values
  - Write integration test: LIFETIME constraints are enforced correctly for each parameter set
  - Create lib/tests/parameter_sets.rs for configuration tests
  - Test all parameter set variants produce working keys and signatures
  - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5_

- [ ] 14. Implement no_std compatibility for type conversion
- [ ] 14.1 Add conditional compilation for no_std support
  - Write compilation test: TypeConverter compiles with #![no_std] and alloc
  - Write compilation test: Wrapper types serialize/deserialize in no_std context
  - Write test: xmss-types conversions work without std (use alloc for Vec)
  - Add #[cfg(not(feature = "std"))] sections to TypeConverter
  - Replace std imports with alloc equivalents in no_std sections
  - Ensure serde derives work with no_std + alloc
  - Create lib/tests/no_std_compile.rs to verify compilation (note: cannot run in std test harness)
  - Document that main wrapper API requires std (hash-sig dependency), only conversions support no_std
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_

- [ ] 15. Create golden test vectors for validation
- [ ] 15.1 Generate and verify golden signatures
  - Generate golden test vectors: known-good signatures from hash-sig reference implementation
  - Write test: Wrapper verifies pre-generated golden signatures correctly
  - Write test: Wrapper produces signatures compatible with golden vector format
  - Create lib/tests/golden_vectors/ directory with test data files
  - Store golden vectors with epoch, message, signature, public key for each parameter set
  - Implement golden vector loading in test_utils
  - Verify wrapper produces compatible signatures
  - _Requirements: 10.2_

- [ ] 16. Integrate wrapper into lib public API
- [ ] 16.1 Export wrapper types and create convenience re-exports
  - Update lib/src/lib.rs to re-export XmssWrapper, WrappedPublicKey, WrappedSecretKey, WrappedSignature
  - Export WrapperError, ParameterSet, ParameterMetadata, MessagePreprocessor
  - Export TypeConverter for manual conversions when needed
  - Create module-level documentation with usage examples
  - Add doc comments showing RNG usage patterns (deterministic vs. secure)
  - Document that arbitrary messages are hashed to SHA-256
  - Verify documentation builds with cargo doc
  - _Requirements: 1.1, 2.5, 7.4, 8.4_

- [ ] 17. Verify complete requirements coverage and finalize
- [ ] 17.1 Run comprehensive test suite and verify all acceptance criteria
  - Run cargo test for all unit and integration tests
  - Run cargo test -- --nocapture to verify detailed test output
  - Verify >90% unit test coverage for wrapper, preprocessor, validator, converter modules
  - Verify all error variants are tested and triggered correctly
  - Run cargo clippy to ensure code quality
  - Run cargo fmt to ensure consistent formatting
  - Review all 10 requirements and verify each acceptance criterion has corresponding passing test
  - _Requirements: All 10 requirements must be verified complete_

- [ ] 17.2 Document API usage and integration patterns
  - Add API documentation with examples for key generation, signing, verification
  - Document message preprocessing behavior (always SHA-256)
  - Document epoch management expectations (explicit caller control)
  - Add examples showing type conversion to xmss-types for host-guest communication
  - Document RNG patterns for testing (StdRng) and production (thread_rng)
  - Document error handling patterns and recovery strategies
  - _Requirements: 2.5, 7.4, 8.4_
