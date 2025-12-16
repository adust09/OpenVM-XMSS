# OpenVM-XMSS

XMSS (eXtended Merkle Signature Scheme) verification tailored for Ethereum, with an OpenVM guest program that proves batch verification using the leanSig TargetSum encoding scheme and accelerated SHA-256, and binds a public statement (k, ep, m, pk_i) via a commitment revealed as public output.

## 1. Purpose

This project generates zero-knowledge proofs for XMSS signature batch verification inside OpenVM. Multiple XMSS signatures are verified within a zkVM guest program, producing succinct application-level proofs of correct verification. The primary use case is enabling Ethereum to verify post-quantum signatures.

## 2. leanSig and std/no_std Relationship

### Host Side (std)

The host-side crates run in a standard Rust environment with full `std` support:

| Crate | Role |
|-------|------|
| `xmss-host` | CLI orchestrator that generates inputs, runs OpenVM prove/verify |
| `xmss-lib` | Links `leanSig` crate for XMSS key generation and signing |
| `xmss-types` | Serialization types (used by both host and guest) |

The host uses `leanSig` to:
1. Generate XMSS key pairs
2. Sign messages
3. Export public keys and signatures into serialized formats

### Guest Side (no_std)

The guest program (`xmss-guest`) runs inside OpenVM in a `#![no_std]` environment. It does not link `leanSig`; all XMSS material arrives pre-serialized from the host. The guest re-implements Poseidon2 using `p3-koala-bear` for KoalaBear field operations and uses OpenVM-accelerated SHA-256 for statement commitment hashing. It contains pure verification logic with no key generation or signing capability. This separation ensures the guest remains lightweight and zkVM-compatible.

### Key Type Flow

```
┌─────────────────────────────────────────────────────────────┐
│                      HOST (std)                              │
│                                                              │
│  leanSig::key_gen() → (PublicKey, SecretKey)                │
│  leanSig::sign()    → Signature                              │
│                ↓                                             │
│  export_public_key() → ExportedPublicKey { root, parameter } │
│  export_signature()  → ExportedSignature { randomness,       │
│                         chain_hashes, auth_path }            │
│                ↓                                             │
│  Serialize to VerificationBatch (JSON)                       │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────┐
│                     GUEST (no_std)                            │
│                                                               │
│  Deserialize VerificationBatch                                │
│                ↓                                              │
│  verify_batch() using Poseidon2-KoalaBear                     │
│  - Parse field elements from bytes                            │
│  - Compute TargetSum codeword                                 │
│  - Walk WOTS chains                                           │
│  - Verify Merkle tree path                                    │
│                ↓                                              │
│  reveal_u32(all_valid, count, commitment[0..8])               │
└───────────────────────────────────────────────────────────────┘
```

## 3. Cryptographic Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Signature scheme | `SIGTargetSumLifetime18W1NoOff` | TargetSum encoding, Poseidon hash |
| Tree height | 18 | Supports 2^18 = 262,144 signatures per key |
| Number of chains | 155 | TargetSum w=1 (no checksum) |
| Base | 2 | Binary digits |
| Hash output | 7 × 4 bytes | 7 KoalaBear field elements |
| Parameter size | 5 × 4 bytes | 5 KoalaBear field elements |
| Randomness size | 6 × 4 bytes | 6 KoalaBear field elements (ρ) |

## 4. Getting Started

### Quick Start

```bash
cargo run --release --bin xmss-host
```

This command executes the full pipeline:
1. Generate an input JSON with 2 signatures
2. Run `cargo openvm keygen` (first run only)
3. Execute `cargo openvm prove app`
4. Execute `cargo openvm verify app`
5. Print per-phase timings and peak memory usage

### Build Commands

```bash
# Build workspace (lib, host, xmss-types)
cargo build --release

# Format and lint
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings

# Run tests
cargo test                     # All workspace tests
cargo test -p xmss-lib         # Library tests only
cargo test -p xmss-types       # Types crate tests
```

### Guest-Specific Commands

```bash
# Build guest for plain cargo check (not OpenVM)
cargo build --manifest-path guest/Cargo.toml --features std-entry

# Manual OpenVM operations (usually auto-run by host)
cd guest
cargo openvm build --release   # Build guest ELF
cargo openvm keygen            # Generate proving/verification keys
```
