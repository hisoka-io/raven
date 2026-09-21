# Bench baselines

Checked-in reference runs for the regression gate (`scripts/bench-gate.sh`).

## Why these are generated here and never imported

A baseline is meaningful only when the producer, the config and the machine class match the
run under test. Diffing a CI runner against artifacts produced by a different harness on
unknown hardware gates hardware delta, not code delta: the gate is red on arrival, and a
gate that is red on arrival gets disabled.

The repository holds 39 older bench artifacts under `no-commit/railgun-demo/bench-results/`.
They were produced in 2026-04 by the railgun-demo harness, not by `b1`/`b2`. **None of them
is a valid baseline for this gate.** They remain useful as historical measurements.

## Regenerating

Regeneration is a deliberate, reviewed commit, never an automatic overwrite. That is what
makes a baseline shift auditable rather than silent.

```
BENCH_REPORT_ONLY=0 scripts/bench-gate.sh     # produces target/bench-gate/seed-N/cell-*.json
```

Copy the artifact to `benches/baselines/b1-<variant>-cell-2e<log2>x<bytes>.json` and commit
it with a message saying what moved and why.

**Copy the whole artifact; never edit a figure by hand.** Each byte count ships beside the
closed form its own run predicted (`<metric>_derived`), and the gate refuses a pair that
disagrees. Editing one row leaves the other stating the truth, which is the point: a pin
nobody can re-derive is a copy, not a measurement. `tools/bench-compare/tests/tracked_baseline.rs`
asserts the same property over every file in this directory, so a hand-edited or
underivable baseline reds without the bench having to run.

## What the gate does with them

- **Byte counts are exact, and both directions block.** A fall is not scored as a win: a
  differ handed two numbers cannot separate a real reduction from a truncated body, so the
  only way to land one is to re-pin. What separates them is the shape, which travels with
  the measurement in the `_derived` rows and is checked on both sides of every comparison.
  Measured 0.000% spread across 13 configs x 3 seeds and 8 same-producer seeds, and
  `query_bytes` reproduced byte-identically across four months and different hardware.
  Since 2026-08-27 the stronger form is measured: a baseline produced on the CI runner
  (4-core AMD EPYC 7763) compared against a run on a 16-core AMD Ryzen 7 9800X3D gives
  **identical `query_bytes` and `response_bytes` while timings move up to -42.5%** on
  unchanged code. Byte determinism holds ACROSS machine classes; no timing metric does,
  which is why only bytes block.
- **Timings block only on a 15% breach that is also significant** (`p < 0.05`, Welch t).
  A breach that cannot be separated from noise prints as unconfirmed and does not block.
- **Throughput is reported, never blocking.** It is `1/mean(query_latency)` over the same
  vector `query_median` already gates.
- **`setup` cannot block** because it carries no per-seed samples; it is captured once
  outside the seed loop. Sample it per seed and it becomes gateable automatically.

Thresholds and sample count are provisional until the runner's own noise floor is measured.
Re-ruling them requires a published per-metric CV for the CI runner.

## Provenance of the file on disk

`b1-two-packing-cell-2e16x32.json` was regenerated on a 16-core Ryzen 7 9800X3D, not on the
CI runner: its `hardware` string says so. The blocking half is unaffected, because byte
counts are machine-invariant and the byte rows are the only ones that can fail the gate. The
timing rows in it are this machine's, so **regenerate on the runner** before any timing
comparison against it is read as evidence.
