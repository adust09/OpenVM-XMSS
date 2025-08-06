# Task Completion Checklist

When completing any development task, ensure the following steps are performed:

## Before Starting Work
1. Understand the requirements completely
2. Check existing code and patterns
3. Plan the implementation approach

## During Development
1. Follow existing code style and conventions
2. Write descriptive commit messages
3. Add appropriate documentation/comments
4. Handle errors properly
5. Consider edge cases

## Before Committing
1. **Format code**: `cargo fmt`
2. **Run linter**: `cargo clippy`
3. **Run tests**: `cargo test`
4. **Check compilation**: `cargo check`
5. **Verify no sensitive data** (keys, passwords) in code
6. **Update .gitignore** if new files shouldn't be tracked

## After Implementation
1. Test the implementation thoroughly
2. Run benchmarks if performance-critical
3. Update documentation if APIs changed
4. Commit with descriptive message
5. Push to remote branch: `git push -u origin <branch-name>`
6. Create PR if needed (using MCP tools)

## Verification Steps
- Ensure all tests pass
- Check that existing functionality isn't broken
- Verify memory usage is reasonable
- Confirm performance meets requirements

## Common Commands for Verification
```bash
# Full verification suite
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo build --release

# For zkVM-related changes
cargo build -p xmss-host
cargo build -p xmss-guest
```

## Notes
- For tree height > 10, ensure sufficient RAM (16GB+)
- Always use --release for benchmarks
- Test with small tree heights (4-8) during development
- Production should use tree height 10+ for sufficient signatures