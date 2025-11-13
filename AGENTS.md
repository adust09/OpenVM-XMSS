<!-- OPENSPEC:START -->
# OpenSpec Instructions

These instructions are for AI assistants working in this project.

Always open `@/openspec/AGENTS.md` when the request:
- Mentions planning or proposals (words like proposal, spec, change, plan)
- Introduces new capabilities, breaking changes, architecture shifts, or big performance/security work
- Sounds ambiguous and you need the authoritative spec before coding

Use `@/openspec/AGENTS.md` to learn:
- How to create and apply change proposals
- Spec format and conventions
- Project structure and guidelines

Keep this managed block so 'openspec update' can refresh the instructions.

<!-- OPENSPEC:END -->

# Repository Guidelines

## Project Structure & Module Organization
- Workspace: `lib/`, `host/`, `shared/` (with `guest/` built separately).
- `lib/src/xmss/`: XMSS primitives, wrapper, and aggregation.
- `lib/src/zkvm/`: zkVM integration hooks; `lib/src/benchmark/`: utilities.
- `lib/src/lib.rs`: public exports; `lib/src/main.rs`: CLI for library tasks.
- `lib/tests/`: integration tests; `lib/benches/`: Criterion benchmarks.
- `host/src/main.rs`: `xmss-host` CLI for proving/verifying/benchmarking.
- `shared/src/lib.rs`: shared types usable in `no_std` (used by guest).
- `guest/`: zkVM guest crate (not in workspace); see `guest/openvm.toml`.

## Build, Test, and Development Commands
- Build workspace: `cargo build` (builds `lib`, `host`, `shared`).
- Run library CLI: `cargo run -p xmss-lib -- benchmark --signatures 10`.
- Run host CLI: `cargo run -p xmss-host --bin xmss-host -- prove --input in.json`.
- Build guest separately: `cd guest && cargo build`.
- Benchmarks: `cargo bench -p xmss-lib`.
- Tests: `cargo test` or package-specific: `cargo test -p xmss-lib`.

## Coding Style & Naming Conventions
- Rust 2021; 4-space indent; `snake_case` for modules/functions, `CamelCase` for types, `SCREAMING_SNAKE_CASE` for constants.
- Format before pushing: `cargo fmt --all`.
- Lints (recommended): `cargo clippy --all-targets --all-features -D warnings`.
- Logging via `tracing`; CLI via `clap`; async via `tokio`. Prefer returning `Result<_, Box<dyn std::error::Error>>` for CLIs (as in `host`).
- Keep public re-exports centralized in `lib/src/lib.rs`.

## Testing Guidelines
- Framework: Rust built-in test harness; benches use Criterion.
- Integration tests in `lib/tests/*.rs`; per-module unit tests in `mod tests { ... }` blocks.
- Test names: describe behavior (e.g., `verifies_single_signature`, `aggregates_n_signatures`).
- Run with output: `cargo test -- --nocapture`. Aim to cover XMSS aggregation, serialization (shared), and zkVM glue.
 - Validation: guest enforces `wots_signature.len() == v` and `auth_path.len() == tree_height`; set `TslParams.tree_height` in inputs.

## Commit & Pull Request Guidelines
- Commits: imperative, concise subject (e.g., "Implement XMSS wrapper"), optional body for rationale.
- PRs must include: clear description, linked issues, CLI examples or benchmark deltas when relevant, and docs updates (README or examples) for user-facing changes.
- Ensure: `cargo fmt`, `cargo clippy`, `cargo test`, and (if perf-related) `cargo bench` on `--release` for realistic numbers.

## Security & Configuration Tips
- Do not commit private keys or large generated artifacts (proofs, test blobs).
- Guest crate targets `no_std` via `shared`; avoid `std`-only dependencies in guest paths.
- Use `--release` for benchmarking and proof generation to reflect real performance.
