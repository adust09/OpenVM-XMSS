## MODIFIED Purpose
OpenVM XMSS integrations SHALL use the upstream hash-sig implementation on the host while providing deterministic, `no_std`-friendly verification inputs (via `xmss-types`) to zkVM guests.

## REMOVED Requirements
### Requirement: Wrapper layer removed
OpenVM SHALL NOT expose or depend on the previous XMSS wrapper modules nor on the `xmss-types` compatibility layer.

#### Scenario: wrapper modules absent
- **GIVEN** the repository source tree
- **WHEN** the XMSS code is inspected
- **THEN** no `lib/src/xmss` wrapper modules (e.g., `wrapper.rs`, `conversions.rs`) SHALL remain, and no `xmss-types` conversions SHALL be required to use XMSS functionality.

## ADDED Requirements
### Requirement: Host-only hash-sig boundary
The `hashsig` crate SHALL be linked only by host-side crates (`xmss-lib`, `xmss-host`, benches), and all guest / `no_std` flows MUST operate exclusively on serialized `xmss-types::VerificationBatch` payloads.

#### Scenario: guest build excludes hash-sig
- **GIVEN** the `guest` crate is compiled with `cargo build -p guest`
- **WHEN** the dependency graph is inspected (e.g., `cargo tree --edges normal`)
- **THEN** `hashsig` SHALL NOT appear anywhere in the guest's dependencies, and the guest SHALL receive XMSS data only via `xmss-types` structures supplied by the host.

### Requirement: xmss-types serialization schema
`xmss-types` SHALL remain a `#![no_std]` crate (using `alloc`) that defines the canonical serde schema (`Signature`, `PublicKey`, `Statement`, `Witness`, `VerificationResult`, `TslParams`, `VerificationBatch`) used to transfer XMSS statements/witnesses between host and guest.

#### Scenario: xmss-types builds under no_std
- **GIVEN** `xmss-types` is built with `--no-default-features`
- **WHEN** `cargo check -p xmss-types --no-default-features` runs
- **THEN** the crate SHALL compile without `std`, and every struct listed above SHALL derive `Serialize` + `Deserialize` so the host can serialize data and the guest can deserialize it.

### Requirement: SHA-256 message preprocessing
Before invoking `hashsig::SignatureScheme::sign` or `verify`, the host MUST compute `Sha256` over the caller-provided message bytes and pass the resulting 32-byte digest as the message parameter to hash-sig. The digest SHALL be recorded in the `Statement.m` field inside `xmss-types::VerificationBatch` so that host and guest verify the exact same value.

#### Scenario: CLI signing hashes inputs
- **GIVEN** the host CLI is asked to sign an arbitrary-length message
- **WHEN** it calls into `hashsig` to produce a signature
- **THEN** it SHALL first hash the message with `Sha256`, use that digest for signing and verification, and place the digest (not the raw message) into the statement shared with the guest.

### Requirement: Epoch-range validation
Host-side signing SHALL validate that the requested epoch `ep` satisfies `activation_epoch <= ep < activation_epoch + num_active_epochs` for the key material being used, returning an explicit error otherwise. The validated epoch SHALL also be embedded into `Statement.ep` so the guest verifies signatures against the same epoch number.

#### Scenario: out-of-range epoch rejected
- **GIVEN** a secret key generated for epochs `[1_000, 1_000 + 512)`
- **WHEN** a caller requests a signature for epoch `2_000`
- **THEN** the host SHALL fail before calling `hashsig::SignatureScheme::sign`, returning an "epoch out of range" error that reports the valid bounds, and SHALL NOT emit any witness data for the guest.
