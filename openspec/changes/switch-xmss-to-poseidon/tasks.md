## 1. Implementation
- [x] 1.1 Update `xmss-lib` re-exports and call sites to use `instantiations_poseidon::...::SIGWinternitzLifetime18W1`.
- [x] 1.2 Regenerate any host fixtures/serde vectors so they reflect the Poseidon parameter sizes.
- [x] 1.3 Ensure guest verification, docs, and examples describe the Poseidon instantiation.

## 2. Validation
- [x] 2.1 `cargo test --workspace`
- [ ] 2.2 `cargo openvm build -p xmss-guest` _(blocked: OpenVM bundles rustc 1.86.0-nightly while this workspace declares `rust-version = 1.87`, so the build command fails before compiling `xmss-types`.)_
