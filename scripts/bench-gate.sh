#!/usr/bin/env bash
# Run the production-shaped bench and diff it against the checked-in baseline.
#
# Phase 1 is report-only: a regression prints and the build stays green, because the
# thresholds are derived from a quiet local machine and the runner's own noise floor has
# not been measured yet. A parse or IO failure still fails, so a broken run is never
# mistaken for a clean one.
#
# Removing --report-only requires publishing the runner's measured CV per metric and a
# threshold ruling. See DECISIONS.md B-033.
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
MEASURED="${BENCH_MEASURED:-10}"
SEEDS="${BENCH_SEEDS:-0,1,2}"

CELL="cell-2e${ENTRIES_LOG2}x${RECORD_BYTES}"
BASELINE_DIR="benches/baselines"
BASELINE="${BASELINE_DIR}/b1-${VARIANT}-${CELL}.json"
OUT_DIR="${BENCH_OUT_DIR:-target/bench-gate}"
REPORT_ONLY="${BENCH_REPORT_ONLY:-1}"

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

ARGS=(
  "$BASELINE" "$CURRENT"
  --regression-threshold "${BENCH_THRESHOLD:-0.15}"
  --alpha "${BENCH_ALPHA:-0.05}"
  --non-blocking "-k4/"
)
if [[ "$REPORT_ONLY" == "1" ]]; then
  ARGS+=(--report-only)
fi

echo "bench-gate: diffing against ${BASELINE}"
./tools/bench-compare/target/release/bench-compare "${ARGS[@]}"
