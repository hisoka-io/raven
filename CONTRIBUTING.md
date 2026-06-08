# Contributing to Raven

Raven is a general-purpose Private Information Retrieval (PIR) framework built as
an open-source public good. Contributions are welcome from anyone. This guide
covers how to build, the bar a change must clear before it merges, the commit
convention, and the repository boundary you must respect.

## Building

Raven is a Rust workspace. You need a recent stable Rust toolchain (see
rust-toolchain.toml for the pinned version).

Native build and test:

    cargo build --all-features
    cargo test --all-features

The client path MUST stay browser-compatible. Add the WebAssembly target once:

    rustup target add wasm32-unknown-unknown

Then verify the client-path crates compile to WASM:

    cargo check --target wasm32-unknown-unknown

Any change that breaks the wasm32-unknown-unknown build for a client-path crate
is rejected at review, not at release.

## Definition of Done

A change is ready to merge only when ALL of the following hold:

1. It compiles with zero errors and zero warnings across all affected crates:

       cargo check --all-features

   and, for any client-path crate:

       cargo check --target wasm32-unknown-unknown

2. Lints pass with warnings denied:

       cargo clippy --all-features --all-targets -- -D warnings

3. New logic has test coverage:
   - unit tests for the logic itself,
   - a property test (via proptest) for invariants,
   - a Known-Answer Test (KAT) wherever cryptography is involved, matched
     against the upstream reference for a fixed PRG seed.

4. Benchmarks are updated if the change touches performance-sensitive code.

5. Public API items have doc comments with at least one runnable example.

6. No TODO, FIXME, or HACK markers; no .unwrap() or .expect() in runtime paths;
   no panic! in library code. Errors are typed (via thiserror) and actionable -
   the message must carry enough context to act on.

7. WASM compatibility is preserved for every client-path crate. Native-only
   optimizations live behind feature flags with a pure-Rust fallback on the
   default feature set.

8. No application-domain leakage into crates/. The framework stays generic (see
   the boundary below).

## Commit Convention

- Short, imperative commit subject lines, under 72 characters. One line; add a
  body only when the change is genuinely hard to follow.
- Conventional-commit prefixes are acceptable but not required: feat:, fix:,
  docs:, bench:, refactor:.
- Do NOT add AI-authorship markers. No "Co-Authored-By" trailers and no
  generated-by attribution in commit messages.
- Keep commit history human and reviewable.

## Repository Boundary (two-repo philosophy)

Raven is one half of a two-repo design and MUST stay a pure, application-agnostic
PIR framework.

- crates/ is GENERIC. It must be useful to someone building PIR for DNS privacy,
  medical records, or any other keyword/index retrieval problem. Do NOT
  introduce application-specific types, naming, schemas, or assumptions here.
- adapters/ (and separate adapter repositories) hold the APPLICATION GLUE - the
  consumer-specific indexing, schemas, and integration that depend on Raven as a
  library.

A pull request that pushes application-domain types or naming into crates/ will
be redirected to an adapter or rejected. Example crates may reference generic
shapes, but they never link against an application's libraries.

## Decisions and Discussion

Raven favors conversational, bidirectional development. For anything that
materially shapes the project - public API surface, crate layout, trait
signatures, scheme selection, dependency changes, or cryptographic
correctness/parameter tradeoffs - open an issue to discuss before writing a large
change. Cryptographic code is ported from peer-reviewed references with cited
provenance, never invented; deviations from a reference must be justified in
writing.

## Reporting Security Issues

Do NOT report vulnerabilities through public issues or pull requests. See
SECURITY.md for the private responsible-disclosure process.
