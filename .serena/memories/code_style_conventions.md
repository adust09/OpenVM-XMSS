# Code Style and Conventions

## Language Version
- Rust edition 2021
- Minimum Rust version: 1.70+

## Naming Conventions
- **Structs/Enums**: PascalCase (e.g., `XmssWrapper`, `SignatureAggregator`)
- **Functions/Methods**: snake_case (e.g., `generate_keypair`, `verify_all`)
- **Constants**: SCREAMING_SNAKE_CASE
- **Module names**: snake_case (e.g., `xmss`, `zkvm`, `benchmark`)

## Code Organization
- Modular structure with separate concerns (xmss, zkvm, benchmark)
- Public API in lib.rs with re-exports
- Implementation details in submodules
- Shared code in dedicated `shared` crate

## Documentation
- Triple-slash comments (///) for public API documentation
- Comments explain the "why", not just the "what"
- Example usage in documentation where appropriate
- All comments in English

## Error Handling
- Use `Result<T, Box<dyn Error>>` for functions that can fail
- Custom error types where appropriate
- Propagate errors with `?` operator
- Descriptive error messages

## Testing
- Unit tests in same file as implementation (in `mod tests`)
- Integration tests in `tests/` directory
- Test naming: descriptive function names starting with `test_`
- Use `#[cfg(test)]` for test modules

## Dependencies
- Workspace dependencies defined in root Cargo.toml
- Minimize external dependencies
- Prefer well-maintained, popular crates
- Feature flags for optional functionality

## Performance Considerations
- Use `--release` for benchmarks and production
- Tree height affects memory usage (16GB+ RAM for height 10+)
- Hypercube optimizations provide 20-40% improvement over standard Winternitz

## Security
- 128-bit security level for Ethereum compatibility
- Never expose private keys
- Validate all inputs
- Use secure random number generation

## Formatting
- Use `cargo fmt` for consistent formatting
- Standard Rust formatting rules apply
- No custom rustfmt.toml configuration
