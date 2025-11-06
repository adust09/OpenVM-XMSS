## 1. Implementation
- [x] 1.1 Remove `lib/src/xmss` wrapper modules and associated re-exports.
- [x] 1.2 Replace library call sites with direct `hashsig::SIGWinternitzLifetime18W1` key_gen/sign/verify usage.
- [x] 1.3 Update host CLI flows (prove/verify/benchmark) to invoke the direct hash-sig API.
- [x] 1.4 Drop the `xmss-types` compatibility layer and clean up dependencies or tests that referenced it.

## 2. Validation
- [x] 2.1 `cargo test -p xmss-lib`
- [x] 2.2 `cargo test -p xmss-host`
