## 1. Implementation
- [ ] 1.1 Remove `lib/src/xmss` wrapper modules and associated re-exports.
- [ ] 1.2 Replace library call sites with direct `hashsig::SIGWinternitzLifetime18W4` key_gen/sign/verify usage.
- [ ] 1.3 Update host CLI flows (prove/verify/benchmark) to invoke the direct hash-sig API.
- [ ] 1.4 Drop the `xmss-types` compatibility layer and clean up dependencies or tests that referenced it.

## 2. Validation
- [ ] 2.1 `cargo test -p xmss-lib`
- [ ] 2.2 `cargo test -p xmss-host`
