# XMSS for Ethereum

XMSS (eXtended Merkle Signature Scheme) verification tailored for Ethereum, with an OpenVM guest program that proves batch verification using the TSL encoding scheme and accelerated SHA‑256, and binds a public statement (k, ep, m, pk_i) via a commitment revealed as public output.

## Overview

This repository focuses on verifiable XMSS verification inside OpenVM:
- Verify multiple XMSS signatures in a guest program
- Generate application-level proofs (`cargo openvm prove app`)
- Reveal pass/fail, count, and statement commitment as public values
 - Aggregate and verify large batches (10, 100, 1,000, up to 10,000)

### In Progress 🚧
- Guest TSL mapper and XMSS verification wiring

## Project Structure

```
xmss-for-ethereum/
├── guest/                 # OpenVM guest (no_std)
│   ├── src/main.rs        # Entry; reads batch input and reveals results
│   └── openvm.toml        # VM config (sha256 enabled)
├── shared/                # Shared, no_std types (input/output structs)
│   └── src/lib.rs         # CompactSignature/PublicKey/Statement/Witness
├── host/                  # Host CLI (integration hooks)
│   └── src/main.rs        # Prove/verify scaffolding (WIP)
└── lib/                   # XMSS helpers (CPU), no benchmarks/CLI
    └── src/xmss/          # Wrapper/aggregator (internal use)
```

## Prerequisites

Install the OpenVM CLI and toolchain (see OpenVM book):

```bash
cargo +1.85 install --locked --git https://github.com/openvm-org/openvm.git --tag v1.3.0 cargo-openvm
rustup install nightly-2025-02-14
rustup component add rust-src --toolchain nightly-2025-02-14
```

## Build, Prove, Verify

```bash
# Build the OpenVM guest
cd guest
cargo openvm build

# Generate app proving/verifying keys
cargo openvm keygen

# Provide input (OpenVM bytes format) and generate an app-level proof
# Example: guest/input.json with { "input": ["0x01<serialized VerificationBatch>"] }
cargo openvm prove app --input input.json

# Verify the app-level proof
cargo openvm verify app

# Optional: generate/verify EVM proof after heavy setup
# cargo openvm setup
# cargo openvm prove evm --input guest/input.json
# cargo openvm verify evm
```

### Quick: Single-Signature Valid Example

Generate a minimal, valid single-XMSS input and run it:

```bash
# From repo root
cargo run -p xmss-host -- single-gen --output guest/input.json
cd guest
cargo openvm run --input input.json   # reveals: all_valid=1, num_verified=1, stmt_commit[8 words]
# Optional: app proof
cargo openvm prove app --input input.json
cargo openvm verify app
```

This uses parameters `w=2, v=1, d0=1, tree_height=0`, so the guest’s constraints are satisfied and the Merkle root equals the WOTS leaf, making a compact, verifiable single-signature case.

### Host-Driven Prove/Verify

You can drive the OpenVM workflow via the host CLI:

```bash
# Generate a valid single-signature input
cargo run -p xmss-host -- single-gen --output guest/input.json

# Produce an app proof (writes to guest/xmss-guest.app.proof and copies to proof.bin)
cargo run -p xmss-host -- prove --input guest/input.json --output proof.bin

# Verify a given app proof (copies it into guest/ then runs verify)
cargo run -p xmss-host -- verify --proof proof.bin
```

Note: This expects `cargo-openvm` to be installed and keys generated (`cd guest && cargo openvm keygen`). If a command fails, the host will surface a helpful error.

## Benchmarks

Criterion benchmarks live under `lib/benches` and measure keygen, sign, verify, aggregation, and serialization.

Run benches for the library package:

```bash
# Build workspace artifacts (first run may fetch deps)
cargo build

# Run benches (recommend --release)
cargo bench -p xmss-lib -- --warm-up-time 1 --sample-size 30

# View HTML reports
open target/criterion/report/index.html
```

Bench parameters:
- Tree heights: `h in {4, 8, 10}` (keygen), `{8, 10}` (others)
- Batch sizes: `{1, 8, 32}` for aggregation/serialization
- Message sizes: `{32B, 1KB, 64KB}` for signing; `{32B, 1KB}` for verify

Notes:
- Signing consumes the OTS index; benches use per-iter setup to avoid exhausting keys.
- Aggregation benches pre-populate inputs during setup so measurements reflect verification/serialization only.

### Host CLI Quick Benchmark (arbitrary N)

Run an end-to-end CPU benchmark for arbitrary batch sizes using the host CLI. The command auto-selects the XMSS tree height `h` so that `2^h >= --signatures`.

Examples:

```bash
# 1,000 signatures (h auto≈10; capacity inferred)
cargo run -p xmss-host -- benchmark --signatures 1000

# 10,000 signatures (h auto≈14)
cargo run -p xmss-host -- benchmark --signatures 10000

# Explicit aggregator capacity (optional; defaults to --signatures)
cargo run -p xmss-host -- benchmark --signatures 10000 --agg-capacity 10000
```

Sample results (local, release build):

```bash
$ cargo run -p xmss-host --bin xmss-host --release -- benchmark --signatures 10
Benchmarking verification with 10 signatures
Verified: true | count: 10 | elapsed: 7.92ms
```

```bash
$ cargo run -p xmss-host --bin xmss-host --release -- benchmark --signatures 100
Benchmarking verification with 100 signatures
Verified: true | count: 100 | elapsed: 75.38ms
```

Note: Times are machine- and build-dependent. Use `--release` for realistic numbers.

Library-side helpers:
- `SignatureAggregator::new()` → capacity 10
- `SignatureAggregator::new_100()` → capacity 100
- `SignatureAggregator::new_1000()` → capacity 1,000
- `SignatureAggregator::new_10000()` → capacity 10,000
- `SignatureAggregator::with_capacity(params, n)` → custom capacity

## Input Format

Inputs use OpenVM’s byte format (little‑endian, 4‑byte padding). The guest reads a single `VerificationBatch` containing:
- `params`: TSL/XMSS parameters (`w`, `v`, `d0`, `security_bits`, `tree_height`)
- `statement`: `Statement { k, ep, m, public_keys }`
  - `k`: number of signatures expected
  - `ep`: epoch (u64) mixed into the domain for TSL step derivation
  - `m`: single common message for all signatures
  - `public_keys`: array of `CompactPublicKey { root, seed }`
- `witness`: `Witness { signatures }` where each is `CompactSignature`

Place serialized bytes in `guest/input.json` as `{ "input": ["0x01<hex>"] }`.
The guest reveals: `all_valid`, `num_verified`, and `stmt_commit` (8 little-endian u32 words).
