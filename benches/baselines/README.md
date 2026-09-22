# Bench baselines

Checked-in reference runs for the regression gate (`scripts/bench-gate.sh`).

## Read this before comparing anything against the file on disk

`b1-two-packing-cell-2e16x32.json` was produced on a **developer workstation, not on a CI
runner**, and says so in its own `hardware` field:
`os=linux; arch=x86_64; cpus=16; cpu=AMD Ryzen 7 9800X3D 8-Core Processor`.

- **The blocking half is unaffected.** Byte counts are machine-invariant and are the only
  rows whose VALUE can fail this gate, so the pin is sound exactly as committed.
- **The timing rows in it are that workstation's**, and a 4-core CI runner reproduces none
  of them on unchanged code (the measured spread is under "What the gate does with them").
  A timing delta against this file measures the machine. Regenerate on the runner before any
  timing comparison against it is read as evidence of anything.

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
- **No timing row can block this gate.** `bench-gate.sh` passes `--non-blocking` for
  `/setup`, `/query_median`, `/server_median` and `/client_median`, and `bench-compare`
  refuses to block any throughput row by unit (`GatePolicy::row_may_block`). The 15%-breach
  plus `p < 0.05` Welch rule is `bench-compare`'s DEFAULT policy, which this gate overrides;
  do not read it as the gate's behaviour. What survives an exemption is structural only, and
  none of it is a duration: a row missing from the run, a changed unit, or a byte count that
  disagrees with its own closed form (`Verdict::is_structural`).
- **Throughput is reported, never blocking.** It is `1/mean(query_latency)` over the same
  vector `query_median` already gates.
- **`setup` is exempt twice over**: `bench-gate.sh` names it `--non-blocking`, and it is
  captured once outside the seed loop so it carries no per-seed samples to test with.
  Sampling it per seed does not arm it; dropping the exemption is what would.

Thresholds and sample count are provisional until the runner's own noise floor is measured.
Re-ruling them requires a published per-metric CV for the CI runner.
