## Why
- The existing XMSS wrapper layer (`lib/src/xmss`) cannot interoperate cleanly with the upstream `hashsig` crate and depends on private structures.
- We want OpenVM components to invoke `hashsig`'s XMSS implementation directly, starting with the `SIGWinternitzLifetime18W4` instantiation, to simplify maintenance and unblock further guest/host work.

## What Changes
- Remove the custom wrapper modules under `lib/src/xmss` and stop exposing wrapper-specific types.
- Update library and host flows to call `hashsig::signature::generalized_xmss::instantiations_sha::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1::{key_gen, sign, verify}` directly.
- Eliminate the `xmss-types` compatibility layer that is no longer required once the wrapper goes away.

## Impact
- Simplifies the XMSS surface area for callers; downstream code must construct and manage hash-sig keys/signatures directly.
- Breaks any consumers that relied on the wrapper or on `xmss-types` conversions; they must migrate to the direct hash-sig API.
- Unlocks further OpenVM work that assumes direct hash-sig usage without intermediary abstractions.
