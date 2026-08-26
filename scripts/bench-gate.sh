#!/usr/bin/env bash
# Run the production-shaped bench and diff it against the checked-in baseline.
#
# THIS GATE BLOCKS ON BYTE COUNTS ONLY. Timing metrics are measured, printed and
# deliberately exempt.
#
# Byte counts are exact: query_bytes and response_bytes each hold one value across every
# CI artifact measured, so any movement is a real change and needs no threshold.
#
# Timings are exempt because the SAMPLING UNIT is wrong, not because the statistics are.
# The Welch implementation is exact - cross-checked against scipy over 135 same-commit
# comparisons, agreeing to 1.78e-14 in log10 p. What it is fed is the within-job sample
# array, ten repeats inside ONE job, and it is then asked about a shift BETWEEN jobs. On
# 135 comparisons of a commit against itself, 27 breached +15% in the regression direction
# and the `p < alpha` conjunct vetoed exactly ZERO of them: it has never changed a decision
# on real data. Nor can it be recalibrated - the alpha giving a 5% realised false-positive
# rate is around 1e-32, and p tracks the delta it is supposed to cross-check
# (Spearman -0.86 to -0.91), so it restates the threshold rather than testing it.
#
# Do not "fix" this by replacing welch_p. Re-arming timing needs a between-JOB estimand and
# the run as the experimental unit.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

# The shipped Railgun cell: two-packing at 2^16 x 32 B. Byte counts from this config have
# reproduced exactly across four months and different hardware, which is why the byte gate
# is exact rather than thresholded.
ENTRIES_LOG2="${BENCH_ENTRIES_LOG2:-16}"
RECORD_BYTES="${BENCH_RECORD_BYTES:-32}"
VARIANT="${BENCH_VARIANT:-two-packing}"
WARMUP="${BENCH_WARMUP:-2}"
# Raising this does NOT make the gate more accurate, and the intuition that it does is the
# hazard. The naive standard error is sd/sqrt(n) over within-job repeats, so it shrinks
# without bound while the real between-job floor does not: measured on this corpus the gap
# between the two scales as sqrt(n), from 22.6x at n=1 to 2256x at n=10,000. More samples
# buy more CONFIDENCE ON NOISE. The check below refuses a value that does not match the
# baseline for the same reason - two runs compared at different n are not like for like.
MEASURED="${BENCH_MEASURED:-10}"
SEEDS="${BENCH_SEEDS:-0,1,2}"

CELL="cell-2e${ENTRIES_LOG2}x${RECORD_BYTES}"
BASELINE_DIR="benches/baselines"
BASELINE="${BASELINE_DIR}/b1-${VARIANT}-${CELL}.json"
OUT_DIR="${BENCH_OUT_DIR:-target/bench-gate}"
REPORT_ONLY="${BENCH_REPORT_ONLY:-0}"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

echo "bench-gate: building producer and differ"
cargo build --manifest-path benches/b1-bench/Cargo.toml --features inspire --bin b1-inspire --release
cargo build --manifest-path tools/bench-compare/Cargo.toml --release

echo "bench-gate: running ${VARIANT} ${CELL}, seeds=${SEEDS}, measured=${MEASURED}"
./benches/b1-bench/target/release/b1-inspire \
  --entries-log2 "$ENTRIES_LOG2" \
  --record-bytes "$RECORD_BYTES" \
  --variant "$VARIANT" \
  --warmup "$WARMUP" \
  --measured "$MEASURED" \
  --seeds "$SEEDS" \
  --out-dir "$OUT_DIR" \
  --full-bench

CURRENT="$(find "$OUT_DIR" -name "${CELL}.json" | sort | head -1)"
if [[ -z "$CURRENT" ]]; then
  echo "bench-gate: the producer exited 0 but wrote no ${CELL}.json under ${OUT_DIR}." >&2
  echo "bench-gate: a producer that reports success without producing is the failure this checks for." >&2
  exit 2
fi
echo "bench-gate: current = $CURRENT"

if [[ ! -f "$BASELINE" ]]; then
  echo "bench-gate: no baseline at ${BASELINE}."
  echo "bench-gate: seed one by committing the artifact above, deliberately and reviewed."
  echo "bench-gate: a baseline is only meaningful when producer, config and machine class"
  echo "bench-gate: match the run under test, so it is generated here, never imported."
  exit 0
fi

# A baseline recorded at a different sample count is not a like-for-like comparison: the
# Welch degrees of freedom and the naive standard error both move with n, so the verdict
# changes without the code changing. Fails closed, including when python3 is absent - a
# provenance check that silently skips is the dead validator this gate already carries scars
# from.
BASELINE_SAMPLES="$(python3 - "$BASELINE" <<'PY'
import json, sys
try:
    rows = json.load(open(sys.argv[1]))["results"]
except Exception as exc:
    print(f"unreadable:{exc}")
    raise SystemExit(0)
hit = [r for r in rows if r["bench"].endswith("/query_median")]
print(len(hit[0].get("samples") or []) if len(hit) == 1 else f"rows:{len(hit)}")
PY
)" || { echo "bench-gate: could not read the baseline's sample count (python3 missing?)" >&2; exit 2; }
if [[ "$BASELINE_SAMPLES" != "$MEASURED" ]]; then
  echo "bench-gate: baseline was recorded at ${BASELINE_SAMPLES} per-seed sample(s), this run takes ${MEASURED}." >&2
  echo "bench-gate: a comparison across different sample counts moves the verdict without the" >&2
  echo "bench-gate: code moving. Regenerate the baseline at this count, or set BENCH_MEASURED=${BASELINE_SAMPLES}." >&2
  exit 2
fi

ARGS=(
  "$BASELINE" "$CURRENT"
  --regression-threshold "${BENCH_THRESHOLD:-0.15}"
  --alpha "${BENCH_ALPHA:-0.05}"
  # Equals form, NOT a space. clap reads a space-separated "-k4/" as a short-flag cluster and
  # exits 2 with "unexpected argument '-k'", which `set -e` turns into a hard job failure. This
  # was dormant only because the gate returns earlier when no baseline exists, so seeding one
  # would have detonated it on the very next run.
  --non-blocking="-k4/"
  # Every timing metric, by the "<scheme>/<cell>/<metric>" name suffix. throughput needs no
  # entry: bench-compare refuses to block any queries_per_second row by unit.
  --non-blocking="/setup"
  --non-blocking="/query_median"
  --non-blocking="/server_median"
  --non-blocking="/client_median"
)
if [[ "$REPORT_ONLY" == "1" ]]; then
  ARGS+=(--report-only)
fi

echo "bench-gate: diffing against ${BASELINE}"
# `|| RC=$?` rather than a bare call, because `set -e` would abort on the differ's own
# exit 1 before the policy banner below could print - and that banner is the half an
# operator needs in order to read the verdict correctly.
DIFF_RC=0
./tools/bench-compare/target/release/bench-compare "${ARGS[@]}" || DIFF_RC=$?

echo
if [[ "$REPORT_ONLY" == "1" ]]; then
  echo "bench-gate: REPORT-ONLY. Nothing above can fail this build."
else
  echo "bench-gate: gated on BYTE COUNTS ONLY (query_bytes, response_bytes, hint_bytes)."
  echo "bench-gate: every timing row above is measured and exempt, so a green verdict here"
  echo "bench-gate: is NOT evidence that performance held. See the header of this script."
fi
exit "$DIFF_RC"
