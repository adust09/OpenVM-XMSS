# Suggested Commands

## Build Commands
```bash
# Build entire workspace
cargo build --release

# Build specific package
cargo build -p xmss-lib --release
cargo build -p xmss-host --release
```

## Test Commands
```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_single_signature_verification
```

## Benchmark Commands
```bash
# Run CLI benchmark (from lib)
cargo run --release -- benchmark --signatures 10

# Run with custom parameters
cargo run --release -- benchmark \
  --signatures 5 \
  --tree-height 8 \
  --security-bits 128 \
  --output results.json

# Run Criterion benchmarks
cargo bench
```

## Host Program Commands (zkVM)
```bash
# Generate proof
cargo run --bin xmss-host -- prove --input signatures.bin --output proof.json

# Verify proof
cargo run --bin xmss-host -- verify --proof proof.json

# Run benchmark
cargo run --bin xmss-host -- benchmark --signatures 10
```

## Data Generation
```bash
# Generate test data for zkVM
cargo run --release -- generate --count 10 --output test_data.bin
```

## Code Quality
```bash
# Format code
cargo fmt

# Run clippy linter
cargo clippy

# Check compilation without building
cargo check
```

## Git Commands
```bash
# Clone with submodules
git clone --recursive https://github.com/your-username/xmss-for-ethereum.git

# Update submodules
git submodule update --init --recursive
```

## Development Utilities
```bash
# Watch for changes and rebuild
cargo watch -x build

# Clean build artifacts
cargo clean

# Update dependencies
cargo update
```