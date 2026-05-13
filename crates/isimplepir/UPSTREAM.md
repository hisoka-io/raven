# Upstream attribution: raven-isimplepir

Pure-Rust implementation of **iSimplePIR Entry-level** per
eprint 2026/030 (Wang, Ren, Rachit et al.) *IncrementalPIR*
Figure 2 Construction 1, ported from the `simplepir/` Go
reference.

## Source provenance

- **Paper**: eprint 2026/030 (*IncrementalPIR: Efficient
  Update-Aware Private Information Retrieval for Dynamic
  Databases*). §4 Entry-level construction Figure 2. §4.1
  Theorem 3 correctness proof. Row-aggregation threshold
  formula at §4.1.

- **Go reference**: `github.com/ahenzinger/simplepir`
  (Henzinger et al. USENIX 2023, implementing the base
  SimplePIR scheme from eprint 2022/949). Canonical
  parameter table at `simplepir/pir/params.csv`
  (σ = 6.4, n = 2^10, q = 2^32, p per `log(m)` row).
  Gaussian sampler at `simplepir/pir/gauss.go` (129-entry
  CDF table ported verbatim).

- **Base scheme**: eprint 2022/949 (SimplePIR + DoublePIR,
  Henzinger et al. USENIX 2023). §3.2 Eq. (2) correctness
  bound; §4.2 Table 16 parameter calibration via
  lattice-estimator; Appendix C.2 Theorem C.1 formal
  correctness derivation.

## Raven-local additions (not in upstream)

- **HKDF-SHA256 A-matrix derivation**. Paper allows a
  "small seed" for deterministic A; Go reference uses
  AES-CTR with a 16-byte key. This crate uses
  HKDF-SHA256(master, label, 32) + ChaCha20 expand with the
  versioned label `"raven-isimplepir/A/v1"`, so the A
  derivation stays pure-Rust on `wasm32-unknown-unknown`
  (no AES-NI dependency).

- **Typed error hierarchy** via `thiserror` (see
  `src/error.rs`). Every failure produces an actionable
  error variant. Go reference uses `panic!` on parameter
  violation; Raven returns `IsimplePirError::InvalidParams`
  or similar typed variants.

- **Version-k state typing** (`src/version.rs`). Paper
  prescribes "verify the k" on every StateUpdate but does
  not specify recovery on mismatch. Raven enforces
  version-ordered transitions via a typed `HintVersion(u64)`
  counter + returns `VersionMismatch` as a typed error on
  out-of-order updates.

- **Weak-deletion documentation**. Paper §2.4 explicitly
  states that strong deletion is impossible in the
  preprocessing model (a pre-deletion client hint can
  recover deleted entries via related-index queries). Raven
  documents this as a public API invariant on
  `db_update_delete` in `src/update.rs`, warning callers
  that a hostile pre-deletion client cannot be defended
  against.

- **Runtime correctness asserts**. Static Setup-time
  `⌊q/p⌋ ≥ 48.2 · p · N^{1/4}` check via
  `params::LweParams::validate_eq2`, returning a typed
  error. Per-update `‖D'[i, :]‖_∞ < ⌊p/2⌋` invariant
  enforced in `update.rs`. Both are the runtime
  counterpart of paper 2022/949 Appendix C.2 Eq. (2) +
  paper 2026/030 Theorem 3.

## Pitfalls replicated verbatim from Go reference

1. **u32 wrapping IS mod-2^32 reduction.** Do NOT write
   `% q` in matmul hot paths. Use `wrapping_mul` +
   `wrapping_add`. Go reference uses plain int32 / uint32
   overflow; Rust equivalent is wrapping arithmetic.

2. **Gaussian via 129-entry CDF**. Go reference ships a
   hardcoded 129-entry table for σ = 6.4 rejection
   sampling (see `simplepir/pir/gauss.go`). Ported verbatim
   to `query.rs::CDF_TABLE_SIGMA_6_4`. DO NOT use a
   parameterized Normal distribution sampler. The CDF
   table IS the canonical σ = 6.4 discrete Gaussian.

## Not ported (divergences from Go reference)

Each of these is a deliberate simplification or platform
choice. They produce wire bytes that differ from the Go
reference even though the scheme and the final recovered
plaintext agree.

- **Squish (3 × 10-bit column packing)**. `simplepir/pir/`
  stores the DB as 3 × 10-bit limbs per u32 with
  `BASIS = 10, COMPRESSION = 3` and pads the query vector to
  a multiple of 3 before respond. `respond.rs` keeps the
  raw u32 layout (one plaintext element per slot). Squishing
  is a bandwidth optimization that does not affect
  correctness; adding it later is expected to reintroduce
  the DB + p/2 shift documented next.

- **Offset correction in Recover**. `simplepir/pir/simple_pir.go`
  adds `p/2` to every DB element at Setup and subtracts
  `offset = (p/2) · Σ_j q_j mod 2^32` at Recover, shifting
  the encoding from `[0, p)` to `[-p/2, p/2)`. `extract.rs`
  uses the paper-verbatim `[0, p)` encoding with no shift
  and no offset subtraction; the two formulations are
  correctness-equivalent. Byte-level fixtures across the
  two encodings therefore differ.

- **Go reference's AES-CTR PRG**. Replaced with
  ChaCha20 + HKDF-SHA256 so the A-matrix derivation stays
  pure-Rust on `wasm32-unknown-unknown` (no AES-NI
  dependency).

- **Go reference's matMulVecPacked SIMD C kernel**
  (`simplepir/pir/pir.c`). Replaced with pure-Rust
  `wrapping_add(wrapping_mul)` loop. Rayon optional for
  server-side parallelism; pure single-threaded path is
  the default wasm32-compatible client-path fallback.

- **Go reference's DoublePIR**. Out of scope. This crate
  implements iSimplePIR Entry-level per paper 2026/030,
  which extends single-round SimplePIR.

## kat-go scope (`--features kat-go`)

The `kat-go` Cargo feature is reserved for a future
byte-identity differential KAT against the Go `simplepir/`
binary. That KAT requires implementing the DB + p/2 shift,
3 × 10-bit column packing, and matching `(p/2) · Σ q_j`
offset correction so Raven's wire bytes align with Go's.

This crate ships unconditional determinism KATs at
`tests/kat_fixtures.rs` that lock Raven's own wire bytes
against committed fixture files, so a regression (e.g.
accidental bincode reorder, ChaCha20 seeding change) surfaces
without needing a Go toolchain. The `kat-go` feature remains
a stub pending the port of the three Go encoding conventions
listed above.

## Feature flag status

This crate ships with no catalog feature flags. Optimization
features that have been considered and deferred:

- `ypir-negacyclic`. YPIR §4.1 negacyclic preprocessing
  targets cold-start Setup, not Entry-level updates, and
  shifts the security assumption from plain LWE to RLWE.
- `wangren-relocation-ds`. Structurally incompatible with
  iSimplePIR's LWE hint: WangRen 2024/1845 keeps symmetric
  XOR parities over raw bytes, while iSimplePIR's hint is a
  matrix product over `Z_q`.
- `onionpirv2-ntt-matmul`. NTT-based preprocessing targets
  Ring-LWE architectures and shifts the security assumption.
- `cross-client-batching`. Harness-layer concern, not a
  library feature; belongs in a bench adapter.

The one reserved feature flag is `kat-go` (see
[kat-go scope](#kat-go-scope---features-kat-go) above).

## Paper-silent implementation decisions

Points where paper 2026/030 does not prescribe behavior and
this crate had to choose. These are the natural review
surface for a cryptographer pass.

1. Version-k mismatch recovery protocol. Paper silent;
   this crate surfaces a typed `VersionMismatch` and expects
   the caller to re-run `Setup`.
2. Deletion RNG source for `r ←$ Z_p`. Paper silent; the
   `db_update_delete` API takes an `RngCore` and documents
   that callers must use OS entropy.
3. `A` matrix seed / PRG. Paper allows any "small seed";
   this crate uses HKDF + ChaCha20 with a versioned label.
4. Concurrent-writer semantics. Paper assumes single-writer;
   callers needing concurrent updates should serialize
   externally.
5. Noise accumulation under incremental updates. Paper
   gives no closed-form per-update bound because there is
   none: Theorem 3 establishes `H' = D' · A` exactly with
   no LWE error injected by updates. The governing
   correctness bound is SimplePIR Eq. (2) at Setup.
6. Strong-deletion escape hatch. Paper §2.4 says
   impossible in the preprocessing model; this crate
   documents the weak-deletion invariant on
   `db_update_delete`.
7. Row-aggregation formula. Paper canon is
   `t = ⌈n · log q / (log p + log √N)⌉`, implemented in
   `update::row_aggregation_threshold`.

## License

Apache-2.0. Derivative work from `simplepir/` (Go, MIT
license per `simplepir/LICENSE`); Raven's Rust
reimplementation reorganizes the algorithm into idiomatic
Rust types + pure-Rust WASM-compatible dependencies.
Attribution preserved here. Paper 2026/030 cited as
algorithmic authority; paper 2022/949 for SimplePIR base
noise-budget derivation.
