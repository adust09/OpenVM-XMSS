# OpenVM Integration Plan for XMSS-for-Ethereum

## Overview
This plan outlines the integration of OpenVM zkVM framework to generate zero-knowledge proofs for XMSS signature verification. The goal is to prove that 10 XMSS signatures are valid without revealing the actual signatures.

## Phase 1: Environment Setup and Project Restructuring

### 1.1 Install OpenVM Tools
```bash
# Install cargo-openvm CLI tool
cargo install cargo-openvm

# Verify installation
cargo openvm --version
```

### 1.2 Restructure Project as Workspace
Transform the current single-crate project into a workspace with separate host and guest programs:

```
xmss-for-ethereum/
├── Cargo.toml          # Workspace root
├── host/               # Host program (proof generation)
│   ├── Cargo.toml
│   └── src/
│       └── main.rs
├── guest/              # Guest program (XMSS verification in zkVM)
│   ├── Cargo.toml
│   ├── openvm.toml    # OpenVM configuration
│   └── src/
│       └── main.rs
├── shared/             # Shared code between host and guest
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs
└── lib/                # Existing library code
    ├── Cargo.toml
    └── src/
        ├── lib.rs
        ├── xmss/
        ├── benchmark/
        └── zkvm/

```

### 1.3 Update Workspace Cargo.toml
```toml
[workspace]
members = ["host", "guest", "shared", "lib"]
resolver = "2"

[workspace.dependencies]
openvm = { git = "https://github.com/openvm-org/openvm.git", features = ["std"] }
serde = { version = "1.0", features = ["derive"] }
hypercube-signatures = { path = "libs/hypercube" }
```

## Phase 2: Guest Program Implementation

### 2.1 Guest Cargo.toml
```toml
[package]
name = "xmss-guest"
version = "0.1.0"
edition = "2021"

[dependencies]
openvm = { workspace = true, default-features = false }
shared = { path = "../shared" }
```

### 2.2 OpenVM Configuration (guest/openvm.toml)
```toml
[app_vm_config.rv32i]
[app_vm_config.io]
[app_vm_config.rv32m]
[app_vm_config.keccak]  # For hash operations
```

### 2.3 Guest Program Structure
The guest program will:
1. Read serialized XMSS signatures from host
2. Deserialize and verify each signature
3. Output verification result

Key implementation points:
- Use `openvm::io::read()` for input
- Use `openvm::io::reveal()` for output
- Implement custom deserialization (no-std environment)
- Minimize dependencies for smaller proof size

## Phase 3: Host Program Implementation

### 3.1 Host Cargo.toml
```toml
[package]
name = "xmss-host"
version = "0.1.0"
edition = "2021"

[dependencies]
openvm = { workspace = true }
lib = { path = "../lib" }
shared = { path = "../shared" }
clap = { version = "4.0", features = ["derive"] }
tokio = { version = "1.0", features = ["full"] }
serde_json = "1.0"
```

### 3.2 Host Program Features
1. **Proof Generation**
   - Load guest program binary
   - Prepare input data (serialized signatures)
   - Execute guest in zkVM
   - Generate STARK proof

2. **Benchmarking Integration**
   - Measure proof generation time
   - Track memory usage
   - Compare with native verification

3. **CLI Commands**
   ```bash
   # Generate proof for 10 signatures
   cargo run --bin xmss-host -- prove --input signatures.bin --output proof.json
   
   # Verify a proof
   cargo run --bin xmss-host -- verify --proof proof.json
   
   # Benchmark with different parameters
   cargo run --bin xmss-host -- benchmark --signatures 10
   ```

## Phase 4: Shared Library Implementation

### 4.1 Shared Types
Create serialization-friendly types that work in both std and no-std environments:

```rust
// shared/src/lib.rs
#[derive(Debug, Clone)]
pub struct CompactSignature {
    pub leaf_index: u32,
    pub randomness: [u8; 32],
    pub wots_signature: Vec<[u8; 32]>,
    pub auth_path: Vec<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct VerificationInput {
    pub signatures: Vec<CompactSignature>,
    pub messages: Vec<Vec<u8>>,
    pub public_keys: Vec<CompactPublicKey>,
}
```

### 4.2 Serialization Strategy
- Custom binary format for efficiency
- Fixed-size fields where possible
- Minimize overhead for zkVM execution

## Phase 5: Integration and Testing

### 5.1 Build Process
```bash
# Build guest program
cd guest && cargo openvm build

# Generate proving/verification keys
cargo openvm keygen

# Run host program
cd ../host && cargo run -- prove
```

### 5.2 Test Suite
1. **Unit Tests**
   - Guest logic verification
   - Serialization/deserialization
   - Host-guest communication

2. **Integration Tests**
   - End-to-end proof generation
   - Proof verification
   - Performance benchmarks

3. **Stress Tests**
   - Maximum signature count
   - Large message sizes
   - Memory constraints

## Phase 6: Performance Optimization

### 6.1 Guest Program Optimization
- Minimize allocations
- Use stack-based arrays where possible
- Optimize hash computations
- Consider OpenVM extensions for crypto operations

### 6.2 Proof Size Optimization
- Tune OpenVM parameters
- Experiment with different proof systems
- Measure trade-offs between proof size and generation time

## Timeline and Milestones

### Week 1
- [ ] Environment setup
- [ ] Project restructuring
- [ ] Basic guest program

### Week 2
- [ ] Host program implementation
- [ ] Proof generation working
- [ ] Basic benchmarks

### Week 3
- [ ] Optimization
- [ ] Extended testing
- [ ] Documentation

## Success Criteria

1. **Functional Requirements**
   - Successfully prove verification of 10 XMSS signatures
   - Proof can be verified independently
   - Integration with existing CLI

2. **Performance Targets**
   - Proof generation < 5 minutes for 10 signatures
   - Proof size < 1MB
   - Memory usage < 8GB

3. **Code Quality**
   - Comprehensive test coverage
   - Clear documentation
   - Modular, maintainable design

## Risks and Mitigations

1. **Risk**: OpenVM API changes
   - **Mitigation**: Pin to specific version, monitor updates

2. **Risk**: Performance constraints
   - **Mitigation**: Start with smaller signature counts, optimize incrementally

3. **Risk**: Memory limitations in zkVM
   - **Mitigation**: Efficient serialization, batch processing if needed

## Next Steps

1. Create plan.md file with this content ✓
2. Set up development branch
3. Begin Phase 1 implementation
4. Regular progress updates and benchmarks

This plan provides a clear roadmap for integrating OpenVM into the XMSS-for-Ethereum project while maintaining the existing functionality and adding zkVM proof capabilities.