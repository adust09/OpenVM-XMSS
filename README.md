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

You can drive the OpenVM workflow via the host CLI:

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

## 4. Benchmarking

This repository provides OpenVM end-to-end benchmarking capabilities. Measure OpenVM execution times for `prove app` / `verify app` from the host. The CLI also reports peak memory (RSS of child processes) after each iteration.

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

### CPU Results:

Environment (CPU baseline): aarch64-apple-darwin (macOS), Rust nightly-2025-02-14, OpenVM toolchain per prerequisites.

| Operation | Signatures | Wall-clock (avg) | Peak RSS      |
|-----------|------------|------------------|---------------|
| Prove     | 100        | 28.17 s          | 2.63 GiB      |
| Verify    | 100        | 0.881 s          | 16.81 MiB     |
| Prove     | 1000       | 444.29 s         | 5.30 GiB      |
| Verify    | 1000       | 1.522 s          | 18.64 MiB     |

Commands run:

```
cargo run -p xmss-host --bin xmss-host -- benchmark-openvm prove --signatures 100 --generate-input --iterations 3
cargo run -p xmss-host --bin xmss-host -- benchmark-openvm verify --iterations 3
```

### GPU Results:

Environment (GPU): Ubuntu 24.04.2 (RTX 5090, driver 570.158.01, CUDA 12.9.86), Rust nightly-2025-02-14, `cargo-openvm` v1.4.0 (built with `--features cuda`).

| Operation | Signatures | Wall-clock (avg) | Peak RSS      |
|-----------|------------|------------------|---------------|
| Prove     | 100        | 18.42 s          | 3.67 GiB      |
| Verify    | 100        | ~0.05 s          | 25.81 MiB     |
| Prove     | 500        | 68.58 s          | 12.50 GiB     |
| Verify    | 500        | ~0.05 s          | 25.66 MiB     |
| Prove     | 1000       | 139.72 s         | 19.12 GiB     |
| Verify    | 1000       | ~0.05 s          | 25.82 MiB     |

Commands run:

```
OPENVM_GUEST_FEATURES=cuda cargo run -p xmss-host --bin xmss-host -- benchmark-openvm prove \
  --signatures <N> --generate-input --iterations 1
OPENVM_GUEST_FEATURES=cuda cargo run -p xmss-host --bin xmss-host -- verify
```
