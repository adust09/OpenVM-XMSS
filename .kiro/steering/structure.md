# Project Structure

## Root Directory Organization

```
OpenVM-XMSS/
├── lib/                    # Core XMSS library (workspace member)
├── host/                   # Host CLI for proof generation (workspace member)
├── guest/                  # zkVM guest program (separate workspace)
├── xmss-types/            # Shared types (workspace member)
├── .kiro/                 # Kiro steering and specs
│   ├── steering/          # Project steering documents
│   └── specs/             # Feature specifications
├── .claude/               # Claude Code configuration
│   └── commands/          # Custom slash commands
├── Cargo.toml             # Workspace root
├── Cargo.lock             # Dependency lock file
├── rust-toolchain.toml    # Rust toolchain version pinning (1.87.0)
├── README.md              # User-facing documentation
└── AGENTS.md              # Development guidelines

target/                    # Workspace build artifacts (gitignored)
```

## Workspace Structure

The project uses Cargo workspace with three main members:

### Main Workspace
```toml
[workspace]
members = ["host", "xmss-types", "lib"]
exclude = ["guest"]
```

- **lib** (`xmss-lib`): Core functionality library
- **host** (`xmss-host`): CLI application for proof operations
- **xmss-types**: Shared types with `no_std` support
- **guest** (`xmss-guest`): Separate workspace for zkVM program

### Why Guest is Excluded
The guest program has different build requirements:
- Must use `no_std` with `openvm` runtime
- Requires nightly toolchain with `rust-src`
- Built with `cargo openvm` instead of regular `cargo`
- Has its own `Cargo.toml` with `[workspace]` declaration

## Key Directories

### `lib/` - XMSS Library

Core library providing XMSS operations and zkVM integration.

```
lib/
├── src/
│   ├── lib.rs              # Public API exports
│   ├── main.rs             # Library CLI (optional)
│   ├── xmss/               # XMSS-specific modules
│   │   ├── mod.rs          # Module exports
│   │   ├── wrapper.rs      # XMSS wrapper types
│   │   ├── aggregator.rs   # Batch aggregation logic
│   │   └── conversions.rs  # hashsig conversion layer
│   └── zkvm/               # zkVM integration
│       ├── mod.rs          # Module exports
│       ├── host.rs         # Host-side operations
│       └── guest.rs        # Guest-side utilities
├── tests/
│   └── integration_test.rs # Integration tests
├── benches/                # Criterion benchmarks
│   ├── key_ops.rs          # Key generation benchmarks
│   ├── aggregate.rs        # Aggregation benchmarks
│   └── serialize.rs        # Serialization benchmarks
└── Cargo.toml
```

**Key Principles**:
- Public API centralized in `lib.rs`
- XMSS operations separated from zkVM integration
- Conversion layer abstracts hashsig library details

### `host/` - Host CLI Application

Command-line interface for proof generation and verification.

```
host/
├── src/
│   ├── main.rs             # CLI entry point (clap definitions)
│   ├── commands/           # Command handlers
│   │   ├── mod.rs          # Command exports
│   │   ├── prove.rs        # Proof generation
│   │   ├── verify.rs       # Proof verification
│   │   ├── benchmark.rs    # Library benchmarking
│   │   └── benchmark_openvm.rs  # OpenVM end-to-end benchmarks
│   └── utils/              # Utilities
│       ├── mod.rs          # Utility exports
│       ├── input.rs        # Input generation/parsing
│       ├── openvm.rs       # OpenVM CLI interactions
│       └── mem.rs          # Memory tracking (RSS)
├── benches/
│   └── aggregate.rs        # Host-level benchmarks
├── bin/                    # Additional binaries
│   ├── gen_input.rs        # Input file generation
│   ├── run_check.rs        # Validation utilities
│   └── gen_fail.rs         # Negative test case generation
└── Cargo.toml
```

**Key Principles**:
- Commands separated into individual modules
- Utilities abstracted for reusability
- CLI definitions centralized in `main.rs`
- Additional binaries for tooling support

### `guest/` - zkVM Guest Program

Zero-knowledge virtual machine guest program (separate workspace).

```
guest/
├── src/
│   ├── main.rs             # Guest program entry point
│   ├── xmss_verify.rs      # XMSS verification logic
│   ├── tsl.rs              # TSL encoding/decoding
│   └── hash.rs             # Hash utilities (SHA-256)
├── openvm.toml             # OpenVM configuration
├── Cargo.toml              # Guest dependencies (no_std)
└── target/                 # Guest build artifacts
    └── ...

# Generated artifacts (gitignored):
xmss-guest.elf              # Guest ELF binary
xmss-guest.app.proof        # Application proof
xmss-guest.app.pk           # Proving key
xmss-guest.app.vk           # Verification key
input.json                  # Test inputs
```

**Key Principles**:
- `no_std` environment with OpenVM runtime
- Uses `openvm-sha2` for accelerated hashing
- Shared types via `xmss-types` crate
- Separate build process with `cargo openvm`

### `xmss-types/` - Shared Types

Types shared between host and guest with `no_std` support.

```
xmss-types/
├── src/
│   └── lib.rs              # Type definitions
└── Cargo.toml
```

**Key Principles**:
- `no_std` compatible (works in guest)
- Serde serialization with `alloc` feature
- Minimal dependencies
- Shared between workspace members

## Code Organization Patterns

### Module Hierarchy
```
crate
├── public exports (lib.rs)
├── domain logic (xmss/, zkvm/)
└── utilities (benchmark/, utils/)
```

### Domain Separation
- **XMSS Operations**: `lib/src/xmss/` - Signature handling, aggregation
- **zkVM Integration**: `lib/src/zkvm/` - Host/guest interaction patterns
- **CLI Logic**: `host/src/commands/` - User-facing operations
- **Verification Logic**: `guest/src/` - zkVM-executed code

### Test Organization
```
package/
├── src/
│   └── module.rs
│       └── #[cfg(test)] mod tests { }    # Unit tests
└── tests/
    └── integration_test.rs                # Integration tests
```

### Benchmark Organization
```
package/
└── benches/
    ├── operation1.rs
    └── operation2.rs

[[bench]]
name = "operation1"
harness = false
```

## File Naming Conventions

### Rust Files
- **Modules**: `snake_case` (e.g., `xmss_verify.rs`, `benchmark_openvm.rs`)
- **Main entry**: `main.rs` for binaries, `lib.rs` for libraries
- **Re-exports**: `mod.rs` for directory modules
- **Tests**: `*_test.rs` or `tests.rs` (though inline tests preferred)

### Configuration Files
- **Cargo**: `Cargo.toml` (per-package) and `Cargo.lock` (workspace root)
- **Rust Toolchain**: `rust-toolchain.toml` (enforces Rust 1.87.0 with rustfmt and clippy)
- **OpenVM**: `openvm.toml` (guest configuration)
- **Git**: `.gitignore` (workspace root)

### Documentation
- **User docs**: `README.md`, `AGENTS.md` (root)
- **Steering**: `.kiro/steering/*.md`
- **Specs**: `.kiro/specs/*/` (feature directories)

## Import Organization

### Standard Pattern
```rust
// 1. Standard library
use std::error::Error;
use std::path::PathBuf;

// 2. External crates (alphabetical)
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

// 3. Workspace crates
use xmss_lib::xmss::{XmssWrapper, Aggregator};
use xmss_types::SignatureData;

// 4. Local modules
use crate::commands::prove;
use crate::utils::input;
```

### Guest Imports (no_std)
```rust
// 1. alloc for heap types
extern crate alloc;
use alloc::vec::Vec;

// 2. OpenVM runtime
use openvm::io::{read, reveal};
use openvm_sha2::Sha256;

// 3. Shared types
use xmss_types::TslParams;

// 4. Local modules
use crate::tsl::decode_tsl;
```

## Key Architectural Principles

### 1. Host-Guest Separation
- **Host**: Standard Rust with full std library, handles I/O and proof orchestration
- **Guest**: `no_std` Rust, pure computation executed in zkVM
- **Shared Types**: Common data structures via `xmss-types` crate

### 2. Library-First Design
- Core functionality in `xmss-lib` usable independently
- Host CLI wraps library for end-to-end workflows
- Guest program uses library concepts but reimplements for `no_std`

### 3. Workspace Dependencies
```toml
[workspace.dependencies]
openvm = { git = "...", tag = "v1.4.1" }
serde = { version = "1.0", features = ["derive"] }
hashsig = { git = "https://github.com/b-wagn/hash-sig.git" }
```
- Centralized version management
- Consistent dependency resolution
- Easy version updates

### 4. Feature-Based Compilation
```toml
[features]
default = []
cuda = ["openvm-sha2/cuda"]
```
- CUDA support opt-in via feature flags
- Enables different build configurations
- Controlled via `OPENVM_GUEST_FEATURES` environment variable

### 5. Public API Surface
- Library exports controlled via `lib/src/lib.rs`
- Clear separation between public and internal modules
- Re-export only stable, documented interfaces

### 6. CLI Command Pattern
```rust
#[derive(Subcommand)]
enum Commands {
    CommandName { /* args */ },
}

fn handle_command_name(args) -> Result<(), Error> {
    // Implementation
}
```
- Each command in separate module
- Handler function for testability
- Centralized error handling

### 7. Test-Driven Development
- Write tests first for new features
- Integration tests for workflows
- Unit tests for algorithms
- Benchmarks for performance-critical paths

### 8. Zero-Knowledge Proof Pattern
```
Input → Guest Program → Public Output
   ↓
Host generates proof of execution
   ↓
Verifier checks proof against public output
```
- Guest reads private inputs via `openvm::io::read`
- Guest reveals public commitments via `openvm::io::reveal`
- Host generates proof of correct execution
- Verification happens independently

### 9. Conversion Layer
`lib/src/xmss/conversions.rs` abstracts hashsig library details:
- Convert between hashsig types and internal types
- Isolate external dependency changes
- Maintain clean internal API

### 10. Benchmarking at Multiple Levels
- **Micro-benchmarks**: `cargo bench` with Criterion
- **Library-level**: `xmss-host benchmark` command
- **End-to-end**: `xmss-host benchmark-openvm` with wall-clock timing
- **Memory tracking**: RSS measurement for peak memory usage
