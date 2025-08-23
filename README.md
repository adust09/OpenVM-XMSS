# XMSS for Ethereum

XMSS (eXtended Merkle Signature Scheme) verification tailored for Ethereum, with an OpenVM guest program that proves batch verification using the TSL encoding scheme and accelerated SHA‑256, and binds a public statement (k, ep, m, pk_i) via a commitment revealed as public output.

## Table of Contents

- [XMSS for Ethereum](#xmss-for-ethereum)
  - [Table of Contents](#table-of-contents)
  - [1. Overview](#1-overview)
  - [2. Project Structure](#2-project-structure)
  - [3. Prerequisites](#3-prerequisites)
  - [4. Getting Started](#4-getting-started)
  - [5. Benchmarking](#5-benchmarking)

## 1. Overview

This repository focuses on verifiable XMSS verification inside OpenVM:
- Verify multiple XMSS signatures in a guest program
- Generate application-level proofs
- Reveal pass/fail, count, and statement commitment as public values
 - Aggregate and verify large batches (10, 100, 1,000, up to 10,000)



## 2. Project Structure

```
xmss-for-ethereum/
├── guest/                 # OpenVM guest (no_std)
│   ├── src/main.rs        # Entry; reads batch input and reveals results
│   └── openvm.toml        # VM config (sha256 enabled)
├── shared/                # Shared, no_std types (input/output structs)
│   └── src/lib.rs         # CompactSignature/PublicKey/Statement/Witness
├── host/                  # Host CLI (prove/verify) + Criterion benches
│   ├── src/main.rs        # CLI entrypoints
│   └── benches/           # Host-side aggregation/verify benches (HTML reports)
└── lib/                   # XMSS helpers (CPU), Criterion benches; no standalone CLI
    ├── src/xmss/          # Wrapper/aggregator (internal use)
    └── benches/           # Key ops, aggregate, serialize (HTML reports)
```

## 3. Prerequisites

Install the OpenVM CLI and toolchain (see OpenVM book):

```bash
cargo +1.85 install --locked --git https://github.com/openvm-org/openvm.git --tag v1.3.0 cargo-openvm
rustup install nightly-2025-02-14
rustup component add rust-src --toolchain nightly-2025-02-14
```

## 4. Getting Started

You can drive the OpenVM workflow via the host CLI:

```bash
# Generate proof with single signature (auto-generates input)
cargo run -p xmss-host --bin xmss-host -- benchmark-openvm prove --signatures 1 --generate-input --iterations 1

# Verify the app proof (uses guest/xmss-guest.app.proof by default)
cargo run -p xmss-host --bin xmss-host -- verify

# Alternative: Generate HTML report covering all steps
cargo run -p xmss-host --bin xmss-host -- report-getting-started
```

Note: This expects `cargo-openvm` to be installed and keys generated (`cd guest && cargo openvm keygen`). If a command fails, the host will surface a helpful error.

## 5. Benchmarking

This repository provides OpenVM end-to-end benchmarking capabilities. Measure OpenVM execution times for `prove app` / `verify app` from the host. This focuses on wall-clock time of the OpenVM CLI, not CPU-only signature verification.

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
