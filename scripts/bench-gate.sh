#!/usr/bin/env bash
# Run the production-shaped bench and diff it against the checked-in baseline.
#
# This gate blocks on byte counts only. Timing metrics are measured, printed and exempt.
#
# Byte counts are exact and machine-invariant: query_bytes and response_bytes reproduce
# byte-identically across runs, seeds and machine classes, so any movement is a real change
# and needs no threshold. Both directions block: the baseline is a pin, not a budget, and a
# differ handed two numbers cannot tell a real byte win from a truncated body. A win lands by
# re-pinning. Every byte count ships beside the closed form its own run predicts
# (`<metric>_derived`) and the differ refuses a pair that disagrees, so a hand-edited figure
# reds; tools/bench-compare/tests/tracked_baseline.rs checks the same over every baseline.
#
# Timings are exempt because the sampling unit is wrong, not the statistics: the Welch test
# is fed ten repeats inside one job and asked about a shift between jobs. On 135 same-commit
# comparisons, 27 breached +15% and `p < alpha` vetoed none of them. Re-arming timing needs a
# between-job estimand with the run as the experimental unit, not a different welch_p.
#
# Baselines: benches/baselines/b1-<variant>-cell-2e<log2>x<bytes>.json. The committed one
# records its producer machine in `hardware`; its timing rows are that machine's and are
# never comparable across machine classes. To re-pin, run this script with no baseline at
# the path (it writes $BENCH_OUT_DIR/seed-N/cell-*.json and exits 0), copy the whole seed-0
# artifact into benches/baselines/, and commit it saying what moved and why.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

# The served Railgun cell: one PPOI block, 2^16 rows of 512 B, two-packing.
ENTRIES_LOG2="${BENCH_ENTRIES_LOG2:-16}"
RECORD_BYTES="${BENCH_RECORD_BYTES:-512}"
VARIANT="${BENCH_VARIANT:-two-packing}"
WARMUP="${BENCH_WARMUP:-2}"
# Raising this does not make the gate more accurate: the within-job standard error shrinks
# as sqrt(n) while the between-job floor does not. It must match the baseline's count, which
# the check below enforces.
MEASURED="${BENCH_MEASURED:-10}"
SEEDS="${BENCH_SEEDS:-0,1,2}"

CELL="cell-2e${ENTRIES_LOG2}x${RECORD_BYTES}"
BASELINE_DIR="benches/baselines"
# Overridable so a red-proof can point the real gate at a deliberately broken pin without
# writing inside benches/baselines/, where a crashed run leaves a stray baseline behind.
BASELINE="${BENCH_BASELINE:-${BASELINE_DIR}/b1-${VARIANT}-${CELL}.json}"
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
  echo "bench-gate: seed one by committing the whole artifact above, deliberately and reviewed."
  echo "bench-gate: its byte rows are what this gate compares and hold on any machine;"
  echo "bench-gate: its timing rows belong to the machine recorded in its hardware field."
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
# Timing rows carry the baseline MACHINE, and no other machine class reproduces them, so the
# rows below are only readable next to whose they are.
echo "bench-gate: baseline hardware = $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("hardware") or "unrecorded")' "$BASELINE" 2>/dev/null)"
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
  echo "bench-gate: byte counts block in BOTH directions - a drop is landed by re-pinning"
  echo "bench-gate: from a producer run, not by passing silently."
  echo "bench-gate: every timing row above is measured and exempt, so a green verdict here"
  echo "bench-gate: is NOT evidence that performance held. See the header of this script."
fi
exit "$DIFF_RC"
