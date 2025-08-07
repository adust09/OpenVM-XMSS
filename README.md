# XMSS for Ethereum

A high-performance implementation of XMSS (eXtended Merkle Signature Scheme) signature aggregation for Ethereum, with zkVM proof generation support for quantum-resistant cryptography.

## Overview

This repository provides benchmarking and verification tools for XMSS aggregated signatures, designed to:
- Aggregate and verify multiple XMSS signatures efficiently
- Generate zkVM proofs for signature verification
- Measure performance metrics including proof generation time and memory consumption
- Support up to 10 aggregated signatures per batch

### In Progress 🚧
- OpenVM zkVM integration
- On-chain verification contracts
- Performance optimizations
- Extended benchmarking scenarios
## Project Structure

```
xmss-for-ethereum/
├── lib/                    # Main library implementation
│   ├── src/               
│   │   ├── xmss/          # XMSS module
│   │   │   ├── mod.rs     # Module exports
│   │   │   ├── wrapper.rs # XMSS wrapper functionality
│   │   │   └── aggregator.rs # Signature aggregation logic
│   │   ├── zkvm/          # zkVM integration module
│   │   ├── benchmark/     # Benchmarking utilities
│   │   ├── lib.rs         # Library exports
│   │   └── main.rs        # CLI application
│   ├── tests/             # Integration tests
│   └── benches/           # Criterion benchmarks
├── host/                  # zkVM host implementation
├── guest/                 # zkVM guest implementation
└── shared/                # Shared types and utilities
```

## Installation

```bash
# Clone the repository
git clone https://github.com/your-username/xmss-for-ethereum.git
cd xmss-for-ethereum

# Build the project
cargo build --release
```

## Usage

### Library Usage

```rust
use xmss_lib::{XmssWrapper, SignatureAggregator};

// Create wrapper with default parameters
let wrapper = XmssWrapper::new()?;

// Create aggregator
let mut aggregator = SignatureAggregator::new(wrapper.params().clone());

// Generate and aggregate signatures
for i in 0..10 {
    let keypair = wrapper.generate_keypair()?;
    let message = format!("Message {}", i).into_bytes();
    let signature = wrapper.sign(&keypair, &message)?;
    let public_key = keypair.lock().unwrap().public_key().clone();
    
    aggregator.add_signature(signature, message, public_key)?;
}

// Verify all signatures
let (is_valid, duration) = aggregator.verify_all()?;
println!("Verified {} signatures in {:?}", aggregator.len(), duration);
```

### CLI Commands

```bash
# Run benchmarks with 10 signatures (from lib directory)
cd lib && cargo run --release -- benchmark --signatures 10

# Run benchmarks with custom parameters
cd lib && cargo run --release -- benchmark \
  --signatures 5 \
  --tree-height 8 \
  --security-bits 128 \
  --output results.json

# Generate test data for zkVM
cd lib && cargo run --release -- generate --count 10 --output test_data.bin
```

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_single_signature_verification

# Run benchmarks
cargo bench
```
