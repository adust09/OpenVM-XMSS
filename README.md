# OpenVM-XMSS

XMSS (eXtended Merkle Signature Scheme) verification tailored for Ethereum, with an OpenVM guest program that proves batch verification using the TSL encoding scheme and accelerated SHA‑256, and binds a public statement (k, ep, m, pk_i) via a commitment revealed as public output.

## Table of Contents

- [XMSS for Ethereum](#xmss-for-ethereum)
  - [Table of Contents](#table-of-contents)
  - [1. Overview](#1-overview)
  - [2. Prerequisites](#2-prerequisites)
  - [3. Getting Started](#3-getting-started)
  - [4. Benchmarking](#4-benchmarking)

## 1. Overview

This repository focuses on verifiable XMSS verification inside OpenVM:
- Verify multiple XMSS signatures in a guest program
- Generate application-level proofs
- Reveal pass/fail, count, and statement commitment as public values
 - Aggregate and verify large batches (10, 100, 1,000, up to 10,000)


## 2. Prerequisites

Install the OpenVM CLI and toolchain (see OpenVM book):

```bash
cargo +1.85 install --locked --git https://github.com/openvm-org/openvm.git --tag v1.3.0 cargo-openvm
rustup install nightly-2025-02-14
rustup component add rust-src --toolchain nightly-2025-02-14
```

## 3. Getting Started

You can drive the OpenVM workflow via the host CLI:

```bash
# Generate proof with single signature (auto-generates input)
cargo run -p xmss-host --bin xmss-host -- benchmark-openvm prove --signatures 1 --generate-input --iterations 1

# Verify the app proof (uses guest/xmss-guest.app.proof by default)
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

Environment: aarch64-apple-darwin (macOS), Rust nightly-2025-02-14, OpenVM toolchain per prerequisites.

Commands run:

```
cargo run -p xmss-host --bin xmss-host -- benchmark-openvm prove --signatures 100 --generate-input --iterations 3
cargo run -p xmss-host --bin xmss-host -- benchmark-openvm verify --iterations 3
```

Results (wall-clock and memory):

| Operation | Signatures | Wall-clock (avg) | Peak RSS      |
|-----------|------------|------------------|---------------|
| Prove     | 100        | 28.17 s          | 2.63 GiB      |
| Verify    | 100        | 0.881 s          | 16.81 MiB     |
| Prove     | 1000       | 444.29 s         | 5.30 GiB      |
| Verify    | 1000       | 1.522 s          | 18.64 MiB     |

Notes:
- Timings include OpenVM build/transpile work invoked by `cargo openvm`. With warm caches or build skipping, prove times may drop.
