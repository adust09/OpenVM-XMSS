# Product Overview

## Product Description

OpenVM-XMSS is a zero-knowledge proof system for verifying XMSS (eXtended Merkle Signature Scheme) signatures using OpenVM, a zkVM (zero-knowledge virtual machine) framework. The system enables efficient batch verification of multiple XMSS signatures with cryptographic proof generation, specifically tailored for Ethereum and blockchain applications.

## Core Features

- **Batch XMSS Signature Verification**: Verify multiple XMSS signatures (1, 10, 100, 500, 1,000, up to 10,000) in a single proof
- **Zero-Knowledge Proof Generation**: Generate application-level proofs using OpenVM's zkVM technology
- **TSL Encoding Scheme**: Utilizes TSL (Tree Structure Layout) encoding for efficient signature verification
- **Accelerated SHA-256**: Leverages OpenVM's optimized SHA-256 implementation with optional CUDA GPU acceleration
- **Public Statement Binding**: Binds public statements (k, ep, m, pk_i) via commitment revealed as public output
- **Comprehensive Benchmarking**: End-to-end benchmarking for both CPU and GPU proving/verification with memory tracking
- **Flexible Input Generation**: Automatic generation of valid test inputs for benchmarking and development

## Target Use Cases

### Primary Use Cases
1. **Blockchain Integration**: Verify post-quantum XMSS signatures on Ethereum with minimal on-chain verification cost
2. **Batch Verification Systems**: Process large batches of XMSS signatures efficiently for high-throughput applications
3. **Post-Quantum Cryptography Research**: Experiment with XMSS signature schemes in zero-knowledge proof contexts
4. **Performance Benchmarking**: Measure zkVM proof generation and verification performance at scale

### Specific Scenarios
- **Smart Contract Applications**: Enable post-quantum signature verification in smart contracts without exposing full verification logic on-chain
- **Identity Systems**: Verify multiple user signatures in batch for authentication and authorization
- **Certificate Transparency**: Verify XMSS-signed certificates with cryptographic proof of correctness
- **High-Performance Computing**: Leverage GPU acceleration for proof generation in time-sensitive applications

## Key Value Propositions

### Performance
- **GPU Acceleration**: CUDA support reduces 1000-signature proof generation from 444s (CPU) to 140s (GPU)
- **Efficient Verification**: Sub-2-second application proof verification regardless of batch size
- **Scalable Batch Processing**: Linear scaling for batch sizes from 1 to 10,000 signatures

### Security
- **Post-Quantum Ready**: XMSS is NIST-approved and quantum-resistant
- **Zero-Knowledge Proofs**: Cryptographic guarantees without revealing signature internals
- **Public Statement Commitment**: Binds verified data to public outputs for transparency

### Developer Experience
- **Simple CLI Interface**: Intuitive command-line tools for proving, verification, and benchmarking
- **Automatic Input Generation**: Built-in test data generation for rapid development
- **Comprehensive Documentation**: Clear examples and benchmarking guidelines
- **Modular Architecture**: Separate library, host, and guest components for flexible integration

### Integration Benefits
- **OpenVM Ecosystem**: Leverages mature zkVM framework with active development
- **Ethereum Compatibility**: Designed for blockchain integration patterns
- **Flexible Deployment**: CPU and GPU support for different infrastructure requirements
- **Memory Efficient**: Predictable memory usage with detailed RSS tracking

## Recent Evolution

### Migration to hash-sig Library
The project recently migrated from a custom XMSS implementation (hypercube-signatures) to the `hash-sig` library, providing:
- More robust and maintained XMSS implementation
- Better compliance with XMSS standards
- Conversion layer for seamless integration with OpenVM

This architectural decision reflects commitment to leveraging established cryptographic libraries while maintaining high-performance zkVM integration.
