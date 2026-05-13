# Upstream attribution. Raven-bff

Standalone pure-Rust port of the Binary Fuse Filter construction
+ serialization from
[`ChalametPIR`](https://github.com/itzmeanjan/ChalametPIR) (Anjan
Roy, BSD-3-Clause). The algorithm itself comes from the
Graf & Lemire paper *"Binary Fuse Filters: Fast and Smaller Than
Xor Filters"* (arXiv 2201.01174, 2022) via the FastFilter
reference implementations
[fastfilter_cpp](https://github.com/FastFilter/fastfilter_cpp) and
[xor_singleheader](https://github.com/FastFilter/xor_singleheader).

## Source provenance

- **Algorithm**: Graf & Lemire (2022), *Binary Fuse Filters*.
  Refer to the paper + FastFilter C++ references for the
  underlying construction + analysis.
- **Rust port base**:
  `ChalametPIR/chalametpir_common/src/binary_fuse_filter.rs`
  at commit state present in the repository snapshot. BSD-3-Clause
  per `ChalametPIR/LICENSE`. Raven redistributes under
  Apache-2.0 per Raven's framework-level license choice; no
  rights are waived on the original upstream.

## Raven-local divergences from the upstream port

All behavioral; no algorithmic changes to the construction math.

- **Scope trim.** Upstream `chalametpir_common` is a shared
  utility crate for the ChalametPIR scheme; it includes matrix
  types, PIR-specific errors, GPU backends, etc. Raven-bff
  carries only the filter: `BinaryFuseFilter` struct, the two
  construction entry points (3-wise + 4-wise), serialization,
  and supporting helpers (hash + mix + segment math + mod3/mod4).
  No PIR, no matrix, no GPU dependencies.

- **Typed error surface.** Upstream's `ChalametPIRError` has
  ~40 variants covering matrix, filter, PIR, and GPU
  operations. Raven-bff ships a filter-only `BffError` with
  three variants: `EmptyKeyValueDatabase`,
  `ExhaustedAllAttemptsToBuild { arity, attempts }`, and
  `FailedToDeserializeFilterFromBytes`. `ExhaustedAllAttemptsToBuild`
  carries both the arity and the exhausted attempt count. A
  richer error than upstream's separate 3-wise / 4-wise
  variants without data payload.

- **No WASM feature split.** Upstream gates randomness behind
  `#[cfg(feature = "wasm")]` to swap `rand_chacha::ChaCha20Rng`
  for `tinyrand::StdRand` on WASM. Raven-bff uses
  `ChaCha20Rng::try_from_os_rng()` unconditionally and
  configures `getrandom` with the `wasm_js` feature on wasm32
  targets. Same WASM compatibility, fewer code paths, no
  dependency on `tinyrand`.

- **No `unsafe` blocks.** Upstream uses `unsafe` for
  `get_unchecked` + `try_into().unwrap_unchecked()` in the
  serialization path. Raven-bff replaces these with safe
  variants (`slice.get(..).and_then(|s| s.try_into().ok())`)
  that preserve the typed-error discipline on malformed inputs
  and compile under `#![deny(unsafe_code)]`. Unchecked
  hot-path indexing in the construction loop is replaced with
  `get`/`get_mut` that no-op on out-of-range indices, which
  in combination with the unchanged algorithmic validation
  produces equivalent behavior for well-formed inputs.

- **Memory-hygiene fix: `hash_to_key` cleared per attempt.**
  Upstream declares `hash_to_key` *outside* the
  `for _ in 0..max_attempt_count` loop, so entries from failed
  attempts accumulate under different seeds. The returned map
  can contain up to `max_attempt_count × N` dead entries when
  construction takes multiple retries. **Correctness is
  unaffected**: downstream consumers (`matrix.rs:709, :841`)
  query `hash_to_key.get(&hash).unwrap_unchecked()` using
  hashes derived from the successful seed; `HashMap::insert`
  overwrites any stale entry that happens to share a `u64`
  key, so every queried hash resolves to its own key. Stale
  entries with distinct hashes are present but never queried.
  The residual incorrect-lookup risk is bounded by the
  hash-collision rate over a `u64` keyspace
  (`N² · 2^-64` worst-case) which is negligible for any
  realistic `N`, and would still be overwritten by the
  successful attempt's insert when it occurs. The fix is
  therefore memory hygiene (map capacity bounded to `N`), not
  correctness. Raven-bff calls `hash_to_key.clear()` at the
  start of each attempt so the returned map reflects only the
  successful seed's mapping. Surfaced by the property test
  `construct_*_wise_succeeds_on_random_distinct_keys` which
  asserts `hash_to_key.len() == db.len()`.

## What's in / what's out

**In scope**:

- `BinaryFuseFilter` struct + `construct_3_wise` /
  `construct_4_wise` entry points.
- `to_bytes` / `from_bytes` fixed-layout serialization.
- Helpers: `hash_of_key`, `mix256`, `murmur64`, `mix`,
  `segment_length`, `size_factor`, `hash_batch_for_*_wise_xor_filter`,
  `mod3`, `mod4`.
- Property-based tests covering construction, roundtrip, and
  edge cases.

**Out of scope**:

- **No membership `contains()` method.** Upstream's BFF
  evaluation is paired with a caller-owned fingerprint array,
  not with the filter descriptor itself. This crate returns the
  `reverse_order` + `reverse_h` + `hash_to_key` intermediate
  artefacts to let callers populate whatever fingerprint
  storage they want; the membership check is a one-line
  `xor_3(fingerprints[h0], fingerprints[h1], fingerprints[h2])
  == (hash as mat_elem_bit_len-bit value)` that's easy for a
  caller to write once they have the array.
- **No matrix integration.** Upstream's `binary_fuse_filter.rs`
  feeds into ChalametPIR's matrix-layered encoded database.
  raven-bff does not include any matrix, encoding, or PIR
  glue. The filter is the only artefact exposed.
- **No GPU backend.** Upstream includes a Vulkan-accelerated
  server path; out of scope.

## Security

The filter is **not** a cryptographic primitive. It uses
TurboShake128 internally for good avalanche properties on
arbitrary byte-keyed inputs, but the stored fingerprint is
small (caller-chosen width, typically 8-16 bits) and
collision-susceptible. Do not use BFF membership as a
secret-dependent decision primitive.

## License

Apache-2.0 (Raven framework choice). Derivative of
BSD-3-Clause upstream (ChalametPIR); see
`ChalametPIR/LICENSE` for the original notice.
