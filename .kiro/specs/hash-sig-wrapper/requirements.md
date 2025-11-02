# Requirements Document

## Introduction

The hash-sig wrapper layer provides a clean abstraction over the hash-sig XMSS library, bridging the gap between hash-sig's low-level cryptographic primitives and OpenVM-XMSS's high-level zkVM integration requirements. This wrapper enables seamless integration of the hash-sig library into the existing host-guest architecture while maintaining compatibility with xmss-types and supporting both no_std and std environments.

The wrapper layer addresses critical integration challenges including hash-sig's 32-byte fixed message length constraint, epoch-based signature generation management, type system compatibility, and no_std guest environment requirements. By providing this abstraction, developers can work with hash-sig through a familiar interface that aligns with existing OpenVM-XMSS patterns while benefiting from hash-sig's robust, standards-compliant XMSS implementation.

## Requirements

### Requirement 1: Hash-sig API Abstraction
**Objective:** As a library developer, I want a clean Rust API that wraps hash-sig's SignatureScheme trait, so that I can perform XMSS operations without directly coupling to hash-sig's internal implementation details.

#### Acceptance Criteria

1. WHEN the wrapper is imported THEN the XmssWrapper SHALL expose key_gen, sign, and verify methods
2. WHEN key_gen is called with RNG and epoch parameters THEN the XmssWrapper SHALL invoke hash-sig's SignatureScheme::key_gen and return wrapped key types
3. WHEN sign is called with a secret key, epoch, and message THEN the XmssWrapper SHALL invoke hash-sig's SignatureScheme::sign and return a Result containing the wrapped signature or error
4. WHEN verify is called with a public key, epoch, message, and signature THEN the XmssWrapper SHALL invoke hash-sig's SignatureScheme::verify and return a boolean verification result
5. WHERE hash-sig uses concrete instantiations (e.g., SIGWinternitzLifetime10W4) THE XmssWrapper SHALL provide a type parameter or configuration mechanism to select the XMSS parameter set
6. IF hash-sig's sign method returns SigningError::EncodingAttemptsExceeded THEN the XmssWrapper SHALL propagate this error through a custom WrapperError type

### Requirement 2: Message Length Adaptation
**Objective:** As a host application developer, I want to sign arbitrary-length messages, so that I can maintain compatibility with existing workflows while meeting hash-sig's 32-byte message requirement.

#### Acceptance Criteria

1. WHEN a message of arbitrary length is provided to the sign method THEN the XmssWrapper SHALL hash the message to produce a 32-byte digest
2. WHERE the message hashing occurs THE XmssWrapper SHALL use SHA-256 to ensure consistency with OpenVM's accelerated hash primitives
3. WHEN a message is already exactly 32 bytes THEN the XmssWrapper SHALL use it directly without additional hashing
4. WHEN verify is called with an arbitrary-length message THEN the XmssWrapper SHALL apply the same hashing logic before verification
5. WHERE message preprocessing is documented THE XmssWrapper SHALL clearly indicate in API documentation that arbitrary messages are hashed to 32 bytes

### Requirement 3: Epoch Management
**Objective:** As a security-conscious developer, I want epoch management that prevents OTS key reuse, so that I can safely generate multiple signatures without compromising security.

#### Acceptance Criteria

1. WHEN the XmssWrapper generates keys THEN it SHALL accept activation_epoch and num_active_epochs parameters
2. IF activation_epoch + num_active_epochs exceeds the LIFETIME constant THEN key_gen SHALL return an error before invoking hash-sig
3. WHEN a signature is requested with a specific epoch THEN the XmssWrapper SHALL validate that the epoch is within the active range for the secret key
4. IF a sign request uses an epoch outside the active range THEN the XmssWrapper SHALL return an error without attempting signature generation
5. WHERE epoch state is tracked THE XmssWrapper SHALL provide a method to query the current epoch and remaining signature capacity
6. WHEN a secret key is used for signing THEN the XmssWrapper SHALL NOT automatically increment epochs (explicit epoch management by caller)

### Requirement 4: Type System Compatibility
**Objective:** As a system integrator, I want wrapper types that are compatible with xmss-types, so that I can serialize, deserialize, and transmit cryptographic objects between host and guest.

#### Acceptance Criteria

1. WHEN the XmssWrapper produces a signature THEN it SHALL provide a conversion method to xmss_types::Signature
2. WHEN converting to xmss_types::Signature THEN the wrapper SHALL extract leaf_index (epoch), randomness, wots_chain_ends, and auth_path from hash-sig's opaque Signature type
3. IF hash-sig's Signature cannot be directly decomposed THEN the conversion SHALL use bincode serialization/deserialization as an intermediate format
4. WHEN the XmssWrapper produces a public key THEN it SHALL provide a conversion method to xmss_types::PublicKey
5. WHERE xmss_types::PublicKey expects root and parameter fields THE conversion SHALL populate these from hash-sig's PublicKey via serialization
6. WHEN xmss_types structures are converted back to hash-sig types THEN the XmssWrapper SHALL provide reverse conversion methods
7. IF conversion fails due to incompatible data THEN the wrapper SHALL return a descriptive error indicating the conversion failure reason

### Requirement 5: No_std Compatibility Support
**Objective:** As a guest program developer, I want type conversion utilities that work in no_std environments, so that I can verify signatures inside the zkVM guest.

#### Acceptance Criteria

1. WHEN type conversion utilities are compiled for no_std THEN they SHALL use alloc instead of std
2. WHERE serialization is required in no_std THE conversion utilities SHALL use serde with no_std support
3. IF the XmssWrapper itself cannot run in no_std (due to hash-sig's std dependency) THEN the wrapper SHALL clearly document that only type conversions are available in no_std contexts
4. WHEN guest code needs to work with signature data THEN the xmss_types conversions SHALL provide all necessary information for verification without requiring hash-sig
5. WHERE no_std compatibility is tested THE project SHALL include integration tests that verify no_std compilation of type conversion code

### Requirement 6: Error Handling and Diagnostics
**Objective:** As a developer debugging integration issues, I want comprehensive error types and messages, so that I can quickly identify and resolve problems in the wrapper layer.

#### Acceptance Criteria

1. WHEN an error occurs in the wrapper THEN it SHALL return a custom WrapperError enum with specific variants
2. WHERE WrapperError is defined IT SHALL include variants for: HashSigError (wrapping hash-sig errors), EpochOutOfRange, ConversionError, and MessageHashingError
3. WHEN WrapperError is displayed THEN it SHALL provide human-readable error messages with context
4. IF hash-sig returns SigningError THEN the wrapper SHALL wrap it in WrapperError::HashSigError with the original error preserved
5. WHERE conversion between types fails THE error message SHALL indicate which type conversion failed and why
6. WHEN epoch validation fails THEN the error SHALL include the requested epoch, active range, and LIFETIME constant for debugging

### Requirement 7: RNG Integration
**Objective:** As a library user, I want flexible RNG support compatible with rand 0.9, so that I can use modern Rust random number generation patterns with hash-sig.

#### Acceptance Criteria

1. WHEN key_gen or sign requires randomness THEN the XmssWrapper SHALL accept a mutable reference to any type implementing rand::RngCore
2. WHERE test determinism is required THE XmssWrapper SHALL work with rand::rngs::StdRng seeded for reproducibility
3. IF production randomness is needed THEN the wrapper SHALL support rand::thread_rng() or similar cryptographically secure RNG sources
4. WHEN the wrapper is documented THEN examples SHALL demonstrate both deterministic (testing) and secure (production) RNG usage

### Requirement 8: Parameter Selection and Configuration
**Objective:** As a system architect, I want to configure XMSS parameters (tree height, Winternitz parameter), so that I can balance security, signature size, and performance for my use case.

#### Acceptance Criteria

1. WHEN the XmssWrapper is instantiated THEN it SHALL support selection of hash-sig instantiation types (e.g., SIGWinternitzLifetime10W4)
2. WHERE parameter sets are defined THE wrapper SHALL provide named constants or enums for common configurations (e.g., XMSS_SHA256_H10_W4)
3. IF a parameter set is selected THEN the wrapper SHALL expose the LIFETIME, tree height (h), and Winternitz parameter (w) as queryable metadata
4. WHEN documentation describes parameter choices THEN it SHALL include guidance on security levels, signature sizes, and performance implications
5. WHERE TslParams integration is required THE wrapper SHALL provide a method to generate TslParams from the selected hash-sig instantiation

### Requirement 9: Serialization and Persistence
**Objective:** As a host application developer, I want to serialize and deserialize keys and signatures, so that I can store them in files or transmit them over network boundaries.

#### Acceptance Criteria

1. WHEN secret keys, public keys, or signatures need persistence THEN the wrapper types SHALL implement serde::Serialize and serde::Deserialize
2. WHERE bincode is used for serialization THE wrapper SHALL support bincode::serialize and bincode::deserialize
3. IF serde_json compatibility is needed for debugging THEN wrapper types SHALL serialize to human-readable JSON
4. WHEN keys are serialized and deserialized THEN the round-trip SHALL preserve all cryptographic material exactly
5. WHERE serialization format is documented THE wrapper SHALL specify the expected binary or JSON schema

### Requirement 10: Testing and Validation Hooks
**Objective:** As a QA engineer, I want testing utilities and validation methods, so that I can verify wrapper correctness and integration with hash-sig.

#### Acceptance Criteria

1. WHEN running tests THEN the wrapper SHALL provide a test_key_gen utility that generates deterministic keys for testing
2. WHERE signature verification is tested THE wrapper SHALL provide golden test vectors with known-good signatures
3. IF hash-sig provides internal_consistency_check THEN the wrapper SHALL expose this or a similar method for parameter validation
4. WHEN integration tests run THEN they SHALL verify round-trip key generation, signing, and verification
5. WHERE type conversions are tested THE tests SHALL verify conversion to xmss_types and back maintains cryptographic correctness
6. IF errors occur in the wrapper THEN tests SHALL verify that each error variant can be triggered and returns the expected error type
