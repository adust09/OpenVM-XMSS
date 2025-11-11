## Why
- The current `xmss-hashsig` spec hardcodes the SHA-based instantiation (`instantiations_sha::...::SIGWinternitzLifetime18W1`), but the OpenVM design we are now following assumes Poseidon primitives to keep zkVM costs low.
- Without updating the requirement, reviewers cannot insist on the Poseidon parameter set, and future code could regress to SHA variants that are incompatible with the Poseidon-first architecture.

## What Changes
- Update the spec Purpose to explicitly state that XMSS integrations are Poseidon-based.
- Replace the “Direct hash-sig XMSS usage” requirement so it mandates `instantiations_poseidon::...::SIGWinternitzLifetime18W1` (and scenarios that reference the Poseidon path).
- Leave the wrapper-removal requirement untouched; the only behavioral change is the choice of hash-sig instantiation.

## Impact
- Host and guest implementations will be evaluated against the Poseidon instantiation, ensuring consistent parameter sizing (hash output length, tweak parameters, etc.).
- Teams building tooling or docs must reflect the new module path, but no additional capabilities are introduced.
- Existing SHA-specific code will need to migrate once this proposal is adopted; however, the change keeps the same lifetime/winernitz settings to limit churn.
