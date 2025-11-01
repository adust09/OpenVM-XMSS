# Technology Stack

## Architecture Overview

OpenVM-XMSS follows a **host-guest zkVM architecture** where:
- **Host** generates proofs by executing the guest program and producing zero-knowledge proofs
- **Guest** runs verification logic inside the zkVM with `no_std` constraints
- **Library** provides core XMSS operations and zkVM integration utilities
- **Types** shared between host and guest for serialization compatibility

The system uses OpenVM as the underlying zkVM framework, which provides:
- RISC-V based execution environment
- Accelerated cryptographic primitives (SHA-256)
- Application-level proof generation and verification
- Optional CUDA GPU acceleration

## Language and Core Framework

### Rust Ecosystem
- **Language Version**: Rust 2021 edition
- **Toolchain**:
  - Stable: `rustc 1.85` for host/library
  - Nightly: `nightly-2025-02-14` for guest (required for `no_std` builds)
- **Build System**: Cargo with workspace management
- **Formatter**: `cargo fmt` (4-space indentation)
- **Linter**: `cargo clippy` with warnings-as-errors mode

### OpenVM Framework
- **Version**: v1.4.1 (host/library), v1.4.0 (guest)
- **Repository**: https://github.com/openvm-org/openvm.git
- **Key Components**:
  - `openvm` crate: Core zkVM runtime and SDK
  - `openvm-sha2`: Accelerated SHA-256 for guest programs
  - `cargo-openvm`: CLI tool for building and proving guest programs

## Key Dependencies

### Core Libraries

#### XMSS Implementation
```toml
hashsig = { git = "https://github.com/b-wagn/hash-sig.git" }
```
- Provides XMSS signature generation and verification
- Replaces previous `hypercube-signatures` implementation
- Used exclusively in `xmss-lib`

#### Serialization
```toml
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"  # Host only
bincode = "1.3"     # Library serialization
```
- `serde` with `no_std` support for guest compatibility
- `serde_json` for input/output in host CLI
- `bincode` for efficient binary serialization

#### Cryptography
```toml
sha2 = "0.10"                    # Host/library
openvm-sha2 = { tag = "v1.4.0" } # Guest accelerated SHA-256
```

### Development Tools

#### CLI Framework
```toml
clap = { version = "4.0", features = ["derive"] }
```
- Used in `xmss-host` for command-line interface
- Subcommands: `prove`, `verify`, `benchmark`, `benchmark-openvm`

#### Async Runtime
```toml
tokio = { version = "1.0", features = ["full"] }
```
- Powers host CLI's async operations
- Used for concurrent task execution

#### Benchmarking
```toml
criterion = { version = "0.5", features = ["html_reports"] }
```
- Micro-benchmarks for library functions
- HTML report generation for performance analysis

#### Testing
```toml
rand = "0.8"  # Test data generation
```

## Development Environment

### Required Tools

1. **Rust Toolchains**
```bash
# Stable for workspace
rustup install stable

# Nightly for guest builds
rustup install nightly-2025-02-14
rustup component add rust-src --toolchain nightly-2025-02-14
```

2. **OpenVM CLI**
```bash
cargo +1.85 install --locked --git https://github.com/openvm-org/openvm.git \
  --tag v1.3.0 cargo-openvm
```

3. **CUDA Toolkit (Optional)**
- Required for GPU acceleration
- Version: CUDA 12.9.86+ (tested with driver 570.158.01)
- GPU: NVIDIA RTX series (tested on RTX 5090)

### Build Commands

#### Workspace (lib, host, shared)
```bash
cargo build              # Debug build
cargo build --release    # Release build
cargo test              # Run all tests
cargo bench -p xmss-lib # Run benchmarks
```

#### Guest Program
```bash
cd guest
cargo openvm build --release        # Build guest ELF
cargo openvm keygen                 # Generate proving keys
cd ..
```

#### Format and Lint
```bash
cargo fmt --all                               # Format code
cargo clippy --all-targets --all-features \
  -D warnings                                 # Lint with warnings as errors
```

## Environment Variables

### CUDA Acceleration
```bash
OPENVM_GUEST_FEATURES=cuda
```
- Enables CUDA acceleration for guest program
- Must be set when building guest and running proofs
- Example:
  ```bash
  OPENVM_GUEST_FEATURES=cuda cargo run -p xmss-host --bin xmss-host -- \
    benchmark-openvm prove --signatures 100
  ```

### OpenVM Configuration
- Guest configuration in `guest/openvm.toml`
- No additional environment variables required for basic operation

## Port Configuration

**Not applicable** - This is a CLI application without network services.

## Common Development Commands

### Proof Generation and Verification
```bash
# Generate proof with auto-generated input
cargo run -p xmss-host --bin xmss-host -- benchmark-openvm prove \
  --signatures 1 --generate-input --iterations 1

# Verify proof
cargo run -p xmss-host --bin xmss-host -- verify

# GPU-accelerated proving
OPENVM_GUEST_FEATURES=cuda cargo run -p xmss-host --bin xmss-host -- \
  benchmark-openvm prove --signatures 100 --generate-input
```

### Benchmarking
```bash
# Library benchmarks (Criterion)
cargo bench -p xmss-lib

# End-to-end OpenVM benchmarks
cargo run -p xmss-host --bin xmss-host -- benchmark-openvm prove \
  --signatures 100 --iterations 3

cargo run -p xmss-host --bin xmss-host -- benchmark-openvm verify \
  --iterations 5
```

### Testing
```bash
# All tests
cargo test

# Specific package
cargo test -p xmss-lib

# With output
cargo test -- --nocapture
```

## Build Artifacts

### Workspace Artifacts (Standard Cargo)
- `target/debug/` - Debug builds
- `target/release/` - Release builds

### Guest Artifacts (OpenVM)
- `guest/target/` - Guest program builds
- `guest/xmss-guest.app.proof` - Generated application proof
- `guest/xmss-guest.elf` - Guest program ELF binary
- `guest/xmss-guest.app.pk` - Application proving key
- `guest/xmss-guest.app.vk` - Application verification key

### Input/Output Files
- `guest/input.json` - Generated test inputs (gitignored)
- Benchmark reports in `target/criterion/` (HTML)

## Platform Support

### Tested Platforms
- **macOS** (aarch64-apple-darwin): CPU proving/verification
- **Linux** (x86_64-unknown-linux-gnu): CPU and GPU proving/verification

### GPU Requirements
- NVIDIA GPU with CUDA support
- CUDA 12.9+ recommended
- Driver version 570+
- Tested on RTX 5090 (Ubuntu 24.04.2)

## Security Considerations

### No Standard Library in Guest
- Guest program uses `no_std` for zkVM compatibility
- All dependencies must support `no_std` or have separate guest-compatible versions
- Cryptographic operations use OpenVM's accelerated primitives

### Dependency Management
- Pin OpenVM versions to ensure reproducible builds
- Use git dependencies for `hashsig` (active development)
- Workspace dependencies for version consistency

### Build Reproducibility
- Lock file committed for deterministic builds
- Specific toolchain versions documented
- OpenVM CLI version pinned in instructions
