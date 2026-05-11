# raven-bff

Binary Fuse Filter. 3-wise and 4-wise XOR variants. Pure-Rust,
WASM-compatible. Standalone port of ChalametPIR's BFF
construction with a trimmed API and typed-error discipline.

## Status

Alpha. 16 tests pass (5 inline + 10 integration / property +
1 doctest). Clippy `-D warnings` clean. Builds for
`wasm32-unknown-unknown`.

## Usage

```rust
use std::collections::HashMap;
use raven_bff::BinaryFuseFilter;

let mut db: HashMap<&[u8], &[u8]> = HashMap::new();
db.insert(b"alice" as &[u8], b"value-a" as &[u8]);
db.insert(b"bob" as &[u8], b"value-b" as &[u8]);

let (filter, reverse_order, reverse_h, hash_to_key) =
    BinaryFuseFilter::construct_3_wise(&db, 8, 100)?;
// reverse_order + reverse_h: use to populate your own
// fingerprint array in dependency order.
// hash_to_key: maps the filter hash back to the original
// key bytes (handy at query time).
# Ok::<(), raven_bff::BffError>(())
```

## Algorithm

The filter is Graf & Lemire's Binary Fuse Filter (arXiv
2201.01174, 2022). Each key is hashed to three or four indices
in a size-factor-oversized array; the stored fingerprints are
chosen so that XOR-reducing the `arity` positions recovers the
fingerprint bits of the queried key. Construction is iterative
("peeling") with a randomized seed per attempt; typical
inputs succeed on the first attempt.

## What's in the crate

- `BinaryFuseFilter` descriptor + `construct_3_wise` /
  `construct_4_wise` entry points + `to_bytes` / `from_bytes`.
- Helpers exposed for callers building their own fingerprint
  arrays: `hash_of_key`, `mix256`, `hash_batch_for_3_wise_xor_filter`,
  `hash_batch_for_4_wise_xor_filter`.

## What's not in the crate

- No `contains()` membership method. The fingerprint array is
  caller-owned. Membership is a one-liner once the caller has
  their fingerprint store populated.
- No matrix, encoding, or PIR glue.

## Build

```bash
cargo test --manifest-path crates/binary-fuse-filter/Cargo.toml --release
cargo clippy --manifest-path crates/binary-fuse-filter/Cargo.toml --all-targets -- -D warnings
cargo check --manifest-path crates/binary-fuse-filter/Cargo.toml --target wasm32-unknown-unknown
```

## Upstream attribution

See [`UPSTREAM.md`](./UPSTREAM.md). Derivative of ChalametPIR
(Anjan Roy, BSD-3-Clause); redistributed under Apache-2.0.
