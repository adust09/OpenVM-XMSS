## ADDED Requirements
### Requirement: Direct hash-sig XMSS usage
OpenVM XMSS functionality SHALL invoke `hashsig::signature::generalized_xmss::instantiations_sha::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1` directly for key generation, signing, and verification.

#### Scenario: library calls hash-sig functions
- **GIVEN** an OpenVM component inside the `xmss-lib` crate needs to generate keys
- **WHEN** it requests key generation for XMSS
- **THEN** the implementation MUST call `SIGWinternitzLifetime18W1::key_gen` without routing through a custom wrapper layer.

#### Scenario: host verifies signatures via hash-sig
- **GIVEN** the OpenVM host CLI needs to verify an XMSS signature
- **WHEN** verification runs
- **THEN** the implementation MUST call `SIGWinternitzLifetime18W1::verify` directly.

### Requirement: Wrapper layer removed
OpenVM SHALL NOT expose or depend on the previous XMSS wrapper modules nor on the `xmss-types` compatibility layer.

#### Scenario: wrapper modules absent
- **GIVEN** the repository source tree
- **WHEN** the XMSS code is inspected
- **THEN** no `lib/src/xmss` wrapper modules (e.g., `wrapper.rs`, `conversions.rs`) SHALL remain, and no `xmss-types` conversions SHALL be required to use XMSS functionality.
