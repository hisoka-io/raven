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

## What the gate does with them

- **Byte counts are exact.** Any movement blocks. Measured 0.000% spread across 13 configs
  x 3 seeds and 8 same-producer seeds, and `query_bytes` reproduced byte-identically across
  four months and different hardware.
- **Timings block only on a 15% breach that is also significant** (`p < 0.05`, Welch t).
  A breach that cannot be separated from noise prints as unconfirmed and does not block.
- **Throughput is reported, never blocking.** It is `1/mean(query_latency)` over the same
  vector `query_median` already gates.
- **`setup` cannot block** because it carries no per-seed samples; it is captured once
  outside the seed loop. Sample it per seed and it becomes gateable automatically.

Thresholds and sample count are provisional until the runner's own noise floor is measured.
See `DECISIONS.md` B-033 for the re-rule trigger.
