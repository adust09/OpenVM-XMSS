## Context
The current repository contains an incomplete wrapper in `lib/src/xmss` that attempted to model XMSS keys and signatures independently from the upstream `hashsig` crate. Because `hashsig` keeps its key/signature fields private, the wrapper relies on serialization tricks and cannot satisfy the intended `xmss-types` conversions.

## Approach
- Delete the wrapper modules (`config`, `conversions`, `epoch`, `error`, `message`, `wrapper`, etc.) and stop exporting wrapper-specific types from `xmss-lib`.
- Treat `hashsig::signature::generalized_xmss::instantiations_sha::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1` as the default XMSS instantiation for OpenVM.
- Call `SIGWinternitzLifetime18W1::key_gen`, `sign`, and `verify` directly from library/host strata.
- Encapsulate only minimal glue that OpenVM needs (e.g., message preprocessing) without recreating a full wrapper layer.
- Remove `xmss-types` conversions entirely; downstream code will handle hash-sig structures directly or serialize them via `serde` if needed.

## Open Questions / Follow-ups
- Future instantiations (e.g., `Lifetime18W8`, `Lifetime20W4`) can be reintroduced later if required; this change focuses on the minimal viable path.
- Guest integration will require separate work once the direct hash-sig usage pattern is finalized.
