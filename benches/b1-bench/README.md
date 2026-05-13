# raven-b1-bench

Adapter bench driving the Raven-local fork of `inspire-rs`
(at [`../raven-inspire`](../raven-inspire)) through the
`setup` / `query` / `respond` / `extract` sequence. Emits a
[`BenchReport`](../raven-bench/src/lib.rs) JSON plus per-trial
CSV. Every run prepends a correctness smoke that halts the
bench on any byte mismatch.

The crate lives in its own `[workspace]` because the upstream
crate tree carries transitive deps (previously tokio/axum,
now just rayon via the fork plus bincode/rand) that do not
unify cleanly with the mainline workspace's wasm32 build graph.
See the top-level `Cargo.toml` for the detached-workspace
rationale.

## Build

```bash
cargo build --manifest-path crates/raven-b1-bench/Cargo.toml \
            --features inspire --release
```

## Run

### CPU pinning (required for measurement discipline)

WSL2's scheduler can migrate threads across cores under
varying load, which inflates intra-run variance on long bench
loops. Pin the rayon worker pool to the full set of logical
cores on the Ryzen 9800X3D (0-15, 8 physical cores x 2 SMT
threads):

```bash
taskset -c 0-15 ./crates/raven-b1-bench/target/release/b1-inspire \
    --entries-log2 20 --record-bytes 256 --variant two-packing \
    --full-bench --warmup 4 --measured 16 \
    --seeds 0,1,2 \
    --out-dir ./bench-results/inspire/
```

Measurement discipline note: `taskset -c 0-7` (8 physical
cores only) was tested and rejected. Restricting to the 8
physical cores drops rayon's thread count from 16 to 8 and
costs ~4% on server time at our cell shape (server 382 ms at
0-15, 399 ms at 0-7). SMT throughput wins dominate L3/V-Cache
contention savings at this workload, so the wider pin is the
right choice.

Intra-run spread remains <=1%, inter-run <=0.5% under the
0-15 pin. The Ryzen 9800X3D's single-CCX layout puts all
eight physical cores on the same L3 + 3D V-Cache, so pinning
to all 16 logical threads keeps cache locality intact while
preserving SMT parallelism.

### Variants

- `--variant no-packing` exercises the NoPacking upstream path
  (`query` + `respond_with_variant(NoPacking)` +
  `extract_with_variant(NoPacking)`).
- `--variant one-packing` exercises OnePacking tree packing.
- `--variant two-packing` (our B1 target) uses the seeded +
  InspiRING path canonical in the upstream binary pair
  (`bin/client.rs` + `bin/server.rs` with `PackingMode::Inspiring`).

### Parameters

Default parameter construction is the DEFAULT_Q struct literal:
`q = 2^60 - 2^14 + 1`, `p = 65537`, `gadget_base = 2^20`,
`gadget_len = 3`, `sigma = 6.4`, `ring_dim = 2048`.

Opt into Google adaptive parameter derivation via
`--adaptive-params 64,1024,64` for paper-matching gammas at
the 256 B record cell.

## Outputs

Per seed, per cell:

- `seed-<N>/cell-2e<entries_log2>x<record_bytes>.json` - the
  emitted `BenchReport` with `server_ms_median` +
  `client_ms_median` populated (split-timing methodology).
- `seed-<N>/cell-2e<entries_log2>x<record_bytes>.csv` -
  per-trial timings in microseconds
  (`query_gen_us + server_us + extract_us = total_us`).
