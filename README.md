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

### Quick Start (Default Benchmark)

The simplest way to run a full benchmark (prove + verify with 2 signatures):

```bash
# Run full benchmark with default settings (2 signatures)
cargo run --release --bin xmss-host
```

This command will:
1. Auto-generate input with 2 signatures
2. Run prove (generate OpenVM proof)
3. Run verify (verify the proof)
4. Display timing and memory metrics for each step

Note: First run requires keys generation (`cd guest && cargo openvm keygen`).

### Advanced Usage

You can also drive the OpenVM workflow via explicit subcommands:

```bash
# Build the guest once (optional)
cd guest
cargo openvm build --release
cd ..

# Generate proof with single signature (auto-generates input)
OPENVM_GUEST_FEATURES=cuda \
  cargo run -p xmss-host --bin xmss-host -- benchmark-openvm prove \
  --signatures 1 --generate-input --iterations 1

# Verify the app proof (uses guest/xmss-guest.app.proof by default)
OPENVM_GUEST_FEATURES=cuda \
  cargo run -p xmss-host --bin xmss-host -- verify

```

Note: This expects `cargo-openvm` to be installed and keys generated (`cd guest && cargo openvm keygen`). If a command fails, the host will surface a helpful error.

## 3.5 Host ↔ Guest Boundary

- Host-side crates (`xmss-lib`, `xmss-host`, benches) are the only components that link the `hashsig` crate. They derive XMSS keys/signatures, hash arbitrary messages with SHA-256, and serialize the resulting witness into `xmss-types::VerificationBatch`.
- The guest program is `#![no_std]` and depends solely on `xmss-types` for serde. It never links `hashsig`; all XMSS material arrives as serialized buffers prepared by the host.
- Every signing flow must validate the requested epoch against the `(activation_epoch, num_active_epochs)` range supplied at key generation. Attempts outside that interval are rejected before calling into `hashsig`.
- `Statement.m` always stores the 32-byte SHA-256 digest that was signed. This ensures the host and guest agree on the exact bytes that were proven, regardless of the original message length.
- XMSS primitives are instantiated via `hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1`, so public keys/witness fragments use KoalaBear Poseidon field elements (e.g., 7×4-byte nodes, 5×4-byte parameters).

## 4. Benchmarking

This repository provides OpenVM end-to-end benchmarking capabilities. Measure OpenVM execution times for `prove app` / `verify app` from the host. The CLI also reports peak memory (RSS of child processes) after each iteration.

### Default Full Benchmark

Run the complete workflow (input generation, prove, verify) with a single command:

```bash
# Full benchmark with 2 signatures (fixed)
cargo run --release --bin xmss-host
```

Output includes timing for each phase and total execution time.

### Individual Operations

You can also benchmark specific operations:

```bash
# prove app with 100 signatures
cargo run -p xmss-host --bin xmss-host -- benchmark-openvm prove --signatures 100 --generate-input --iterations 1

# verify app: measure proof verification (uses guest/xmss-guest.app.proof by default)
cargo run -p xmss-host --bin xmss-host -- benchmark-openvm verify --iterations 5
```

- `--signatures` (`-s`): Number of signatures to generate for benchmarking (default: 1)
- `--iterations` (`-n`): Number of benchmark iterations to run (default: 1)
- `--generate-input`: Generate valid input JSON if missing

automatically calculated based on signature count: `h >= log2(signatures)`
Run the prove command once per signature count (`N ∈ {1, 100, 500, 1000}`) and reuse the generated proof for verification.

Notes:
- Timings include OpenVM build/transpile work invoked by `cargo openvm`. With warm caches or build skipping, prove times may drop.
