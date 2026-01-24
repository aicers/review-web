# Instructions for AI Coding Agents

These instructions define the coding standards, quality gates, and review
guidelines to follow when contributing to this repository.

## Coding Standards (Rust)

- **Error Handling**: Use `anyhow::Result` for application code and `thiserror`
  for library code.
  - **No `unwrap()`**: Do not use `unwrap()` in production code. Usage in
    tests is permitted.
  - **`expect("reason")`**: Use when you are certain a panic will NOT occur.
    The message must explain why the condition is invariant.
  - **`panic!("reason")`**: Use when you intentionally need to crash the
    program to alert the user of a critical, unrecoverable state.
- **Linting**: Code MUST pass `cargo clippy` with no warnings.
- **Formatting**: Code MUST be formatted with `rustfmt` (use
  `group_imports=StdExternalCrate`).
- **Async**: Use `tokio` runtime. Avoid blocking operations in async contexts.

## Quality Gates (Strict)

**Every code change** must satisfy the following Quality Gates. You must
verify these locally before proposing any code.

<!-- markdownlint-disable MD013 -->
- **Linting (Rust)**:
  - `cargo clippy --no-default-features --features auth-jwt --all-targets -- -D warnings`
  - `cargo clippy --no-default-features --features auth-mtls --all-targets -- -D warnings`
- **Formatting**:
  - `cargo fmt -- --check --config group_imports=StdExternalCrate`
- **Testing**:
  - `cargo test --no-default-features --features auth-jwt`
  - `cargo test --no-default-features --features auth-mtls`
  - Note: the mTLS integration test binds a local port and may require network
    permissions.
- **Linting (Docs/Misc)**:
  - `markdownlint-cli2 "**/*.md" "#target"`
<!-- markdownlint-enable MD013 -->

## Code Review Guidelines

- **Constants**:
  - Use `const` for fixed values instead of "magic strings/numbers".
  - Define constants at the top of the file, not inside functions.
  - **Tests**: Keep test-only constants near the tests for readability.
- **Type Casting (`as`)**:
  - Use `as` only when the conversion is 100% safe.
  - Otherwise use `num_traits` conversions and handle errors explicitly.
- **Types**:
  - Prefer `enum` over `String` whenever a finite set of values is expected.
- **Comments**:
  - Delete redundant or "noisy" comments that just describe code syntax.
- **Documentation (Rustdoc)**:
  - Doc comments (`///`) must start with a verb in the third-person singular
    form (e.g., "Creates...", "Returns...", "Calculates...").
- **Lints (Clippy)**:
  - Avoid `#[allow(...)]` as much as possible.
  - If `allow` is necessary, you MUST add a comment explaining why.
  - Exceptions: `clippy::too_many_lines` can be treated loosely.

## Communication & Workflow Guidelines

- **Commit Messages & Issue/PR Titles**:
  - **No Prefixes**: Do NOT use prefixes like `feat:`, `chore:`, `fix:`, etc.
  - **Commits Only**:
    - **Title format**: Use the imperative mood (e.g., "Add feature",
      "Fix bug").
    - **Title limit**: 50 characters.
    - **Body limit**: Wrap at 72 characters.
