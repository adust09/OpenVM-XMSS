# XMSS for Ethereum Project Overview

## Purpose
This project implements XMSS (eXtended Merkle Signature Scheme) signature aggregation for Ethereum, with zkVM proof generation support. The main goals are:
- Benchmark XMSS signature verification performance
- Prove successful XMSS signature verification using zkVM
- Aggregate up to 10 signatures for batch verification
- Measure proof time and memory consumption

## Tech Stack
- **Language**: Rust (edition 2021)
- **XMSS Implementation**: hypercube-signatures library (TSL optimized)
- **zkVM Framework**: OpenVM
- **CLI Framework**: Clap 4.0
- **Async Runtime**: Tokio
- **Benchmarking**: Criterion
- **Serialization**: Serde
- **Logging**: Tracing

## Project Structure
```
xmss-for-ethereum/
├── host/               # Host program for proof generation
├── guest/              # Guest program for zkVM verification
├── shared/             # Shared code between host and guest
├── lib/                # Main library with XMSS wrapper and aggregator
│   ├── src/
│   │   ├── xmss/      # XMSS wrapper and signature aggregator
│   │   ├── zkvm/      # zkVM integration
│   │   ├── benchmark/ # Performance measurement tools
│   │   └── main.rs    # CLI application
│   └── libs/hypercube/ # Git submodule for XMSS implementation
└── plan.md            # OpenVM integration plan

## Key Components
- **XmssWrapper**: Wrapper around hypercube XMSS implementation with Ethereum-suitable parameters
- **SignatureAggregator**: Aggregates and batch-verifies up to 10 signatures
- **Host Program**: Generates zkVM proofs for signature verification
- **Guest Program**: Runs in zkVM to verify signatures