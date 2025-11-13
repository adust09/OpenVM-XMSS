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

### Quick Start (Fixed Workflow)

```
cargo run --release --bin xmss-host
```

This single command always executes the exact same pipeline (all parameters come from constants inside `host/src/commands/benchmark_openvm.rs`):
1. Generate an input JSON with two signatures.
2. Run `cargo openvm keygen` automatically when needed (first run only).
3. Execute `cargo openvm prove app` and then `cargo openvm verify app`.
4. Print per-phase timings and child-process peak RSS.

No additional CLI flags or subcommands exist. To benchmark different batch sizes or iteration counts, edit the corresponding constants (e.g. `SIGNATURES`) in the code. To enable optional OpenVM features such as CUDA, prefix the command with `OPENVM_GUEST_FEATURES=cuda`.

#### Default build vs OpenVM run

- The guest crate defaults to `#![no_std]`, so OpenVM builds run without extra flags.
- If you want to check the guest with a plain `cargo build`, invoke `cargo build --manifest-path guest/Cargo.toml --features std-entry` to link the stub `main()`.
- The host CLI runs `cargo openvm keygen` automatically before prove/verify, so you never have to run it manually.

## 3.5 Host ↔ Guest Boundary

- Host-side crates (`xmss-lib`, `xmss-host`, benches) are the only components that link the `hashsig` crate. They derive XMSS keys/signatures, hash arbitrary messages with SHA-256, and serialize the resulting witness into `xmss-types::VerificationBatch`.
- The guest program is `#![no_std]` and depends solely on `xmss-types` for serde. It never links `hashsig`; all XMSS material arrives as serialized buffers prepared by the host.
- Every signing flow must validate the requested epoch against the `(activation_epoch, num_active_epochs)` range supplied at key generation. Attempts outside that interval are rejected before calling into `hashsig`.
- `Statement.m` always stores the 32-byte SHA-256 digest that was signed. This ensures the host and guest agree on the exact bytes that were proven, regardless of the original message length.
- XMSS primitives are instantiated via `hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1`, so public keys/witness fragments use KoalaBear Poseidon field elements (e.g., 7×4-byte nodes, 5×4-byte parameters).

## 4. Benchmarking

This repository provides a fully scripted OpenVM benchmark. Each run of `xmss-host` performs “input generation → prove → verify” with fixed parameters and reports the timing and peak memory of every phase.

```bash
cargo run --release --bin xmss-host
```

The output includes input/prove/verify/total durations plus child-process peak RSS. To experiment with other batch sizes or iteration counts, adjust the constants inside `host/src/commands/benchmark_openvm.rs` and rebuild.
