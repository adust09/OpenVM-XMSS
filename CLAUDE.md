# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OpenVM-XMSS implements XMSS (eXtended Merkle Signature Scheme) verification for Ethereum using OpenVM zkVM. The system generates zero-knowledge proofs for batch XMSS signature verification, revealing pass/fail status and statement commitments as public outputs.

## Build and Development Commands

```bash
# Build workspace (lib, host, xmss-types)
cargo build --release

# Run the default benchmark (2 signatures: generate → prove → verify)
cargo run --release --bin xmss-host

# Build guest for plain cargo check (not OpenVM)
cargo build --manifest-path guest/Cargo.toml --features std-entry

# Format and lint
cargo fmt --all
cargo clippy --all-targets --all-features -D warnings

# Run tests
cargo test                     # All workspace tests
cargo test -p xmss-lib         # Library tests only
cargo test -p xmss-types       # Types crate tests
cargo test -- --nocapture      # With output

# Benchmarks (Criterion)
cargo bench -p xmss-lib
```

### OpenVM-Specific Commands

The host CLI auto-runs `cargo openvm keygen` on first use. For manual operations:

```bash
cd guest
cargo openvm build --release   # Build guest ELF
cargo openvm keygen            # Generate proving/verification keys
```

GPU acceleration (CUDA):
```bash
OPENVM_GUEST_FEATURES=cuda cargo run --release --bin xmss-host
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         HOST                                 │
│  xmss-host: CLI orchestrator (prove/verify workflow)        │
│  xmss-lib: XMSS operations via leanSig crate                │
│            + zkVM integration utilities                      │
│  xmss-types: Serialization types (VerificationBatch, etc.)  │
└──────────────────────────┬──────────────────────────────────┘
                           │ JSON input via OpenVM I/O
┌──────────────────────────▼──────────────────────────────────┐
│                     GUEST (no_std)                           │
│  xmss-guest: zkVM program that verifies XMSS batches        │
│  - Never links leanSig (all crypto data serialized by host) │
│  - Uses openvm-sha2 for accelerated SHA-256                 │
│  - Poseidon2 over KoalaBear field for Merkle tree ops       │
│  - Outputs: (all_valid, count, statement_commitment)        │
└─────────────────────────────────────────────────────────────┘
```

### Crate Responsibilities

- **host/** (`xmss-host`): CLI entry point. Orchestrates input generation, proof generation, and verification.
- **lib/** (`xmss-lib`): XMSS primitives via `leanSig` crate. Provides `ZkvmHost` for preparing guest inputs. Host-only (links `leanSig`).
- **xmss-types/**: Shared types (`VerificationBatch`, `Statement`, `Witness`, `TslParams`) with `no_std` support. Used by both host and guest for serialization.
- **guest/**: zkVM program. Separate workspace (not in main `Cargo.toml`). Pure verification logic with Poseidon2-KoalaBear.

### Key Type Flow

1. Host generates XMSS keys/signatures using `leanSig`
2. Host serializes to `VerificationBatch` (includes `TslParams`, `Statement`, `Witness`)
3. Guest deserializes and verifies using re-implemented Poseidon2 logic
4. Guest reveals `(all_valid, count, commitment_hash)` as public outputs

## Cryptographic Details

- **Signature scheme**: `SIGTargetSumLifetime18W1NoOff` (TargetSum encoding, Poseidon-based, KoalaBear field)
- **Tree height**: 18 levels (supports 2^18 = 262,144 signatures per key)
- **Hash nodes**: 7×4 bytes (7 KoalaBear field elements)
- **Parameters**: 5×4 bytes (5 KoalaBear field elements)
- **Randomness**: 6×4 bytes (6 KoalaBear field elements, ρ)
- **Chains**: 155 (TargetSum w=1, no checksum)

## Toolchain Requirements

- Rust 1.90+ (stable) for workspace
- Nightly `nightly-2025-08-02` for guest builds
- OpenVM CLI v1.4.2+ (`cargo-openvm`)

## Important Constraints

- Guest is `#![no_std]` — no `std`-only dependencies
- `leanSig` is host-only — guest receives pre-serialized data
- `Statement.m` must be a 32-byte SHA-256 digest (not raw message)
- Epoch validation: signing requires epoch within `[activation_epoch, activation_epoch + num_active_epochs)`
