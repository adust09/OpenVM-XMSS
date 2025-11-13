## Why
- The current `xmss-hashsig` spec only states that we call hash-sig directly and that wrapper/xmss-types layers must not exist, leaving the no_std guest boundary unspecified.
- In practice we need a clear requirement for how host crates hand data to the guest without linking `hashsig`, including canonical serialization and preprocessing rules.
- Formalizing message hashing and epoch validation is necessary to avoid inconsistent host implementations once the hash-sig flow is rebuilt.

## What Changes
- Update the spec purpose to describe the host/guest separation for hash-sig based XMSS usage.
- Remove the outdated "Wrapper layer removed" requirement and replace it with explicit requirements for a host-only hash-sig boundary, the `xmss-types` serialization schema, SHA-256 preprocessing, and epoch-range validation.
- Document the expectation that guest/`no_std` crates operate purely on `xmss-types::VerificationBatch` data with serde support.

## Impact
- Provides reviewers with concrete acceptance criteria for rebuilding the XMSS pipeline without `hashsig` ever reaching the guest binary.
- Ensures all host flows perform the same digest + epoch checks before calling hash-sig, reducing audit risk.
- Gives downstream consumers confidence that `xmss-types` stays the canonical schema for OpenVM XMSS proofs.
