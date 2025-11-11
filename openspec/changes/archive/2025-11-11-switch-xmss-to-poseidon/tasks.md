## 1. Implementation
- [x] 1.1 Update `xmss-lib` re-exports and call sites to use `instantiations_poseidon::...::SIGWinternitzLifetime18W1`.
- [x] 1.2 Regenerate any host fixtures/serde vectors so they reflect the Poseidon parameter sizes.
- [x] 1.3 Ensure guest verification, docs, and examples describe the Poseidon instantiation.

## 2. Validation
- [x] 2.1 `cargo test --workspace`
- [x] 2.2 `cargo openvm build -p xmss-guest` _(passes with `cd guest && cargo openvm build` after updating to a rustc 1.87.0-capable toolchain.)_
