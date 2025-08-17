# XMSS for Ethereum

XMSS (eXtended Merkle Signature Scheme) verification tailored for Ethereum, with an OpenVM guest program that proves batch verification using the TSL encoding scheme and accelerated SHA‑256.

## Overview

This repository focuses on verifiable XMSS verification inside OpenVM:
- Verify multiple XMSS signatures in a guest program
- Generate application-level proofs (`cargo openvm prove app`)
- Reveal pass/fail and counts as public values

### In Progress 🚧
- Guest TSL mapper and XMSS verification wiring
- App‑level proof workflow and inputs tooling
- Optional EVM proof path (post `cargo openvm setup`)

## Project Structure

```
xmss-for-ethereum/
├── guest/                 # OpenVM guest (no_std)
│   ├── src/main.rs        # Entry; reads batch input and reveals results
│   └── openvm.toml        # VM config (sha256 enabled)
├── shared/                # Shared, no_std types (input/output structs)
│   └── src/lib.rs         # CompactSignature/PublicKey/VerificationInput
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
cargo openvm run --input input.json   # reveals: all_valid=1, num_verified=1
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

## Input Format

Inputs use OpenVM’s byte format (little‑endian, 4‑byte padding). The guest reads a single `VerificationBatch` containing:
- `params`: TSL/XMSS parameters (`w`, `v`, `d0`, `security_bits`, `tree_height`)
- `input`: `VerificationInput` with arrays of `CompactSignature`, messages, and public keys

Place serialized bytes in `guest/input.json` as `{ "input": ["0x01<hex>"] }`.

## Notes

- The guest enables SHA‑256 acceleration via `guest/openvm.toml` `[app_vm_config.sha256]` and uses `openvm-sha2` in code.
- The verifier enforces `wots_signature.len() == v` and `auth_path.len() == tree_height`.
- CPU benchmarks and lib‑level CLI have been removed to focus on the proof path.
