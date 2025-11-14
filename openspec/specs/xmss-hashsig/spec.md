# xmss-hashsig Specification

## Purpose
TBD - created by archiving change remove-xmss-wrapper. Update Purpose after archive.
## Requirements
### Requirement: Direct hash-sig XMSS usage
OpenVM XMSS functionality SHALL invoke `hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1` directly for key generation, signing, and verification.

#### Scenario: library calls Poseidon instantiation
- **GIVEN** an OpenVM component inside the `xmss-lib` crate needs to generate keys
- **WHEN** it requests key generation for XMSS
- **THEN** the implementation MUST call `instantiations_poseidon::...::SIGWinternitzLifetime18W1::key_gen` (not the SHA-based instantiation) without routing through a custom wrapper layer.

#### Scenario: host verifies Poseidon signatures via hash-sig
- **GIVEN** the OpenVM host CLI needs to verify an XMSS signature
- **WHEN** verification runs
- **THEN** the implementation MUST call `SIGWinternitzLifetime18W1::verify` from the Poseidon module path, ensuring that all witness/public key data corresponds to the Poseidon parameter set.

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

### Requirement: Poseidon permutation reuse
XMSSゲスト検証は Poseidon2 (16レーン/24レーン) パーミュテーションを検証ループ外で初期化し、WOTSチェーン進行・Merkle認証・メッセージハッシュで共有しなければならない。この検証ロジック SHALL NOT 再帰的に `default_koalabear_poseidon2_*` を生成し直し、同一バッチ内では同一インスタンスを使い回して Poseidon ステート初期化のオーバーヘッドを排除しなければならない。

#### Scenario: guest reuses Poseidon builders
- **GIVEN** `cargo openvm run --mode meter --input guest/input.json` を実行して単一バッチを検証する
- **WHEN** WOTS チェーン `walk_chain` と `hash_tree_verify` が多数の Poseidon 圧縮を行う
- **THEN** それぞれの呼び出しは事前に確保された Poseidon2 コンテキストを共有し、新しい `Poseidon2KoalaBear` を都度生成しないため、命令数・セル数は再利用前の実装より減少する

