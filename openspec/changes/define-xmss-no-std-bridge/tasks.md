## 1. Implementation
- [x] 1.1 Define/confirm the `xmss-types` structs (`Signature`, `PublicKey`, `Statement`, `Witness`, `VerificationBatch`, `TslParams`) as the canonical serialization boundary under `#![no_std]`.
- [x] 1.2 Update `xmss-lib` + `xmss-host` flows to construct `xmss-types::VerificationBatch` payloads and keep `hashsig` restricted to host-side crates.
- [x] 1.3 Add SHA-256 preprocessing and epoch-range validation before every `hashsig::SignatureScheme::sign` call, and document the resulting error semantics.
- [x] 1.4 Ensure guest/zkVM verification logic consumes only `xmss-types` data and does not link `hashsig`.
- [x] 1.5 Document the host/guest split and serialization format in README/CLI help.

## 2. Validation
- [x] 2.1 `cargo test --workspace`
- [ ] 2.2 `cargo build -p guest` _(fails on this machine: standard `cargo build` expects a `main`, and `cargo openvm build` currently errors because openvm pins rustc 1.86.0 while the workspace requires 1.87.0)_
- [x] 2.3 Round-trip serde test for `xmss-types::VerificationBatch`
