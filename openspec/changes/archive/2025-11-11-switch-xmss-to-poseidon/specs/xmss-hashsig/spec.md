## MODIFIED Purpose
OpenVM XMSS integrations SHALL target the Poseidon-based hash-sig instantiations so that the host design, parameter sizing, and proof economics are aligned with the Poseidon hash function family.

## MODIFIED Requirements
### Requirement: Direct hash-sig XMSS usage
OpenVM XMSS functionality SHALL invoke `hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1` directly for key generation, signing, and verification.

#### Scenario: library calls Poseidon instantiation
- **GIVEN** an OpenVM component inside the `xmss-lib` crate needs to generate keys
- **WHEN** it requests key generation for XMSS
- **THEN** the implementation MUST call `instantiations_poseidon::...::SIGWinternitzLifetime18W1::key_gen` (not the SHA-based instantiation) without routing through a custom wrapper layer.

#### Scenario: host verifies Poseidon signatures via hash-sig
- **GIVEN** the OpenVM host CLI needs to verify an XMSS signature
- **WHEN** verification runs
- **THEN** the implementation MUST call `SIGWinternitzLifetime18W1::verify` from the Poseidon module path, ensuring that all witness/public key data corresponds to the Poseidon parameter set.
