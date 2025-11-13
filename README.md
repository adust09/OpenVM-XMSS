# OpenVM-XMSS

XMSS (eXtended Merkle Signature Scheme) verification tailored for Ethereum, with an OpenVM guest program that proves batch verification using the TSL encoding scheme and accelerated SHA‑256, and binds a public statement (k, ep, m, pk_i) via a commitment revealed as public output.

## 1. Overview

This repository focuses on verifiable XMSS verification inside OpenVM:
- Verify multiple XMSS signatures in a guest program
- Generate application-level proofs
- Reveal pass/fail, count, and statement commitment as public values
 - Aggregate and verify large batches (10, 100, 1,000, up to 10,000)


## 2. Prerequisites

Install the OpenVM CLI and toolchain (see OpenVM book). This project now targets Rust 1.87 or newer, so make sure the stable toolchain is installed locally:

```bash
rustup install 1.87.0
cargo +1.87.0 install --locked --git https://github.com/openvm-org/openvm.git --tag v1.3.0 cargo-openvm
rustup install nightly-2025-02-14
rustup component add rust-src --toolchain nightly-2025-02-14
```

## 3. Getting Started

### Quick Start (固定ベンチ)

```
cargo run --release --bin xmss-host
```

実行すると以下が自動で行われます（パラメータはコード内の定数で固定）：
1. 署名 2 件分の入力 JSON を生成
2. 必要に応じて `cargo openvm keygen` を実行（初回のみ）
3. `cargo openvm prove app` → `cargo openvm verify app` を順に実行
4. 各フェーズの所要時間とメモリ使用量を表示

追加の CLI オプションやサブコマンドはありません。カスタム件数で測定したい場合はコード中の定数 (`SIGNATURES` など) を書き換えてください。CUDA 等の OpenVM フィーチャーを使う場合は上記コマンドに環境変数 `OPENVM_GUEST_FEATURES=cuda` などを付与してください。

#### デフォルトビルド vs OpenVM 実行

- ゲスト crate のデフォルトは `#![no_std]` です。OpenVM 実行時は追加フラグ無しでそのままコンパイル・実行されます。
- 手元で `cargo build --manifest-path guest/Cargo.toml` を通したい場合は `cargo build --manifest-path guest/Cargo.toml --features std-entry` のように明示的にフィーチャーを付与してください（`main()` スタブがリンクされます）。
- ホスト CLI は prove/verify 実行前に `cargo openvm keygen` を自動実行するため、手動で `cd guest && cargo openvm keygen` を走らせる必要はありません。

## 3.5 Host ↔ Guest Boundary

- Host-side crates (`xmss-lib`, `xmss-host`, benches) are the only components that link the `hashsig` crate. They derive XMSS keys/signatures, hash arbitrary messages with SHA-256, and serialize the resulting witness into `xmss-types::VerificationBatch`.
- The guest program is `#![no_std]` and depends solely on `xmss-types` for serde. It never links `hashsig`; all XMSS material arrives as serialized buffers prepared by the host.
- Every signing flow must validate the requested epoch against the `(activation_epoch, num_active_epochs)` range supplied at key generation. Attempts outside that interval are rejected before calling into `hashsig`.
- `Statement.m` always stores the 32-byte SHA-256 digest that was signed. This ensures the host and guest agree on the exact bytes that were proven, regardless of the original message length.
- XMSS primitives are instantiated via `hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1`, so public keys/witness fragments use KoalaBear Poseidon field elements (e.g., 7×4-byte nodes, 5×4-byte parameters).

## 4. Benchmarking

This repository provides OpenVM end-to-end benchmarking capabilities. `xmss-host` always runs「入力生成 → prove → verify」までを固定パラメータで通し、各フェーズの時間／メモリを表示します。

```bash
cargo run --release --bin xmss-host
```

出力には入力生成・prove・verify・合計時間、およびピークメモリ (子プロセス RSS) が含まれます。件数や反復回数を変えたい場合は `host/src/commands/benchmark_openvm.rs` 内の定数を書き換えてください。
