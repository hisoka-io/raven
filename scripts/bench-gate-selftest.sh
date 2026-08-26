#!/usr/bin/env bash
# Red-proof for the bench gate: a gate ships with proof it can fail.
#
# Two halves. The first drives the differ directly with synthetic artifacts. The second drives
# the REAL gate at a 2^10 cell, because an argument the gate builds and the differ rejects is
# invisible to the first half by construction - which is exactly what shipped once.
#
# The gate blocks on byte counts and exempts every timing metric, so both directions are proved
# here: a moved byte count must fail the build, a 10x timing regression must not, and a control
# with the exemption stripped must show that same regression blocking.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

BIN=./tools/bench-compare/target/release/bench-compare
cargo build --manifest-path tools/bench-compare/Cargo.toml --release >/dev/null 2>&1

TMP="$(mktemp -d)"
# The gate cases below seed a baseline inside the repo and copy the gate beside itself, because
# the gate resolves its own repo root from its own location. Both must die with the script even
# on a failure, or a stray baseline outlives the run.
GATE_CELL="cell-2e10x32"
GATE_BASELINE="benches/baselines/b1-two-packing-${GATE_CELL}.json"
GATE_COPY="scripts/.bench-gate-selftest-copy.sh"
trap 'rm -rf "$TMP"; rm -f "$GATE_BASELINE" "$GATE_COPY"' EXIT

FAILURES=0
CASES=0
check() { # name expected_rc actual_rc
  CASES=$((CASES + 1))
  if [[ "$2" == "$3" ]]; then
    echo "  ok    $1 (rc=$3)"
  else
    echo "  FAIL  $1: expected rc=$2, got rc=$3" >&2
    FAILURES=$((FAILURES + 1))
  fi
}

# Two tight, well-separated latency distributions: past 15% and significant.
cat > "$TMP/base.json" <<'JSON'
{"hardware":"selftest","captured_at":"","results":[
 {"bench":"s/2e16x32/query_median","value":1000000,"unit":"nanoseconds",
  "samples":[1000000,1010000,990000,1005000,995000]},
 {"bench":"s/2e16x32/query_bytes","value":98840,"unit":"bytes","samples":[]}
]}
JSON
cat > "$TMP/regressed.json" <<'JSON'
{"hardware":"selftest","captured_at":"","results":[
 {"bench":"s/2e16x32/query_median","value":2000000,"unit":"nanoseconds",
  "samples":[2000000,2010000,1990000,2005000,1995000]},
 {"bench":"s/2e16x32/query_bytes","value":98840,"unit":"bytes","samples":[]}
]}
JSON
# Same medians, but overlapping spreads: a breach that is not separable from noise.
cat > "$TMP/noisy.json" <<'JSON'
{"hardware":"selftest","captured_at":"","results":[
 {"bench":"s/2e16x32/query_median","value":2000000,"unit":"nanoseconds",
  "samples":[400000,3600000,500000,3500000]},
 {"bench":"s/2e16x32/query_bytes","value":98840,"unit":"bytes","samples":[]}
]}
JSON
# One byte different, nothing else.
cat > "$TMP/onebyte.json" <<'JSON'
{"hardware":"selftest","captured_at":"","results":[
 {"bench":"s/2e16x32/query_median","value":1000000,"unit":"nanoseconds",
  "samples":[1000000,1010000,990000,1005000,995000]},
 {"bench":"s/2e16x32/query_bytes","value":98841,"unit":"bytes","samples":[]}
]}
JSON
# The measurement vanished.
cat > "$TMP/missing.json" <<'JSON'
{"hardware":"selftest","captured_at":"","results":[
 {"bench":"s/2e16x32/query_bytes","value":98840,"unit":"bytes","samples":[]}
]}
JSON
printf '{"results": [' > "$TMP/broken.json"

echo "bench-gate selftest:"

set +e
"$BIN" "$TMP/base.json" "$TMP/base.json"      >/dev/null 2>&1; check "identical pair passes"                0 $?
"$BIN" "$TMP/base.json" "$TMP/regressed.json" >/dev/null 2>&1; check "significant 100% latency breach blocks" 1 $?
"$BIN" "$TMP/base.json" "$TMP/noisy.json"     >/dev/null 2>&1; check "unconfirmed breach does NOT block"     0 $?
"$BIN" "$TMP/base.json" "$TMP/onebyte.json"   >/dev/null 2>&1; check "one-byte structural change blocks"     1 $?
"$BIN" "$TMP/base.json" "$TMP/missing.json"   >/dev/null 2>&1; check "vanished measurement blocks"           1 $?
"$BIN" "$TMP/base.json" "$TMP/broken.json"    >/dev/null 2>&1; check "malformed input exits 2, not 0"        2 $?
"$BIN" "$TMP/nope.json" "$TMP/base.json"      >/dev/null 2>&1; check "missing file exits 2, not 0"           2 $?
# --report-only must suppress a real regression but NOT a parse failure.
"$BIN" --report-only "$TMP/base.json" "$TMP/regressed.json" >/dev/null 2>&1; check "--report-only suppresses a regression" 0 $?
"$BIN" --report-only "$TMP/base.json" "$TMP/broken.json"    >/dev/null 2>&1; check "--report-only still exits 2 on garbage" 2 $?
set -e

# ---------------------------------------------------------------------------
# The cases above prove the DIFFER can fail. None of them proves the GATE can RUN.
#
# This file previously contained zero references to bench-gate.sh, --non-blocking,
# --regression-threshold or --alpha, so an argument the gate BUILDS but the differ REJECTS was
# invisible to it. That is exactly what shipped: `--non-blocking "-k4/"` space-separated parses
# as a short-flag cluster and exits 2 with "unexpected argument '-k'", which `set -e` turns into
# a hard job failure. It was dormant only because the gate returns earlier when no baseline
# exists - so seeding one, the very next planned act, would have detonated it.
#
# A red-proof that does not invoke the thing it guards is a proxy assertion. These cases drive
# the real gate, at a tiny cell so they stay affordable per commit.
gate_run() { # out_dir ; returns the gate's rc
  BENCH_ENTRIES_LOG2=10 BENCH_RECORD_BYTES=32 BENCH_MEASURED=1 BENCH_WARMUP=0 BENCH_SEEDS=0 \
    BENCH_OUT_DIR="$1" ./scripts/bench-gate.sh >/dev/null 2>&1
}

# `set -e` was re-enabled above; the control case deliberately exits 2, so it must be off here
# exactly as it is for the differ cases.
set +e

rm -f "$GATE_BASELINE"
gate_run "$TMP/gate-noseed"; check "the gate runs end to end and reports a missing baseline" 0 $?

if [[ -f "$TMP/gate-noseed/seed-0/${GATE_CELL}.json" ]]; then
  cp "$TMP/gate-noseed/seed-0/${GATE_CELL}.json" "$GATE_BASELINE"
  gate_run "$TMP/gate-seeded"
  check "the gate reaches the differ with the arguments IT builds" 0 $?

  # CONTROL: the same path with the argument written the broken way must exit 2. Without this,
  # the case above proves only that something returned 0.
  sed 's|--non-blocking="-k4/"|--non-blocking "-k4/"|' scripts/bench-gate.sh > "$GATE_COPY"
  chmod +x "$GATE_COPY"
  BENCH_ENTRIES_LOG2=10 BENCH_RECORD_BYTES=32 BENCH_MEASURED=1 BENCH_WARMUP=0 BENCH_SEEDS=0 \
    BENCH_OUT_DIR="$TMP/gate-broken" "./$GATE_COPY" >/dev/null 2>&1
  check "(control) a space-separated non-blocking value exits 2, not 0" 2 $?
  rm -f "$GATE_COPY"

  # The bytes-block / timing-exempt policy, proved in BOTH directions through the real gate.
  # One direction alone is not a policy: "bytes block" without "timing does not" is satisfied by
  # a gate that blocks on everything, and "timing does not block" on its own is satisfied by a
  # gate that blocks on nothing.
  #
  # Scaling the baseline DOWN, not up, is load-bearing. A baseline scaled up makes the current
  # run look faster, and an improvement never blocks whatever the policy says - the case would
  # pass without exercising the exemption at all. The samples array is scaled with the value for
  # the same class of reason: leave it alone and the significance test sees no shift, the verdict
  # is "unconfirmed", and that never blocks either. Three measured queries, because welch_p
  # returns None below two samples and a None p-value cannot reach the blocking branch.
  gate_run_n() { # out_dir  measured  [script] ; returns the gate's rc
    BENCH_ENTRIES_LOG2=10 BENCH_RECORD_BYTES=32 BENCH_MEASURED="$2" BENCH_WARMUP=0 BENCH_SEEDS=0 \
      BENCH_OUT_DIR="$1" "${3:-./scripts/bench-gate.sh}" >/dev/null 2>&1
  }
  # Seeded from a THREE-measured run, not from the one-measured artifact the cases above use.
  # A baseline carrying one sample makes welch_p return None, the verdict degrades to
  # "unconfirmed", and unconfirmed never blocks - so both the exemption case and its control
  # would pass on sample count while proving nothing about the exemption. Caught by the control.
  gate_run_n "$TMP/gate-seed3" 3
  SEED3="$TMP/gate-seed3/seed-0/${GATE_CELL}.json"

  seed_scaled() { # field  multiplier
    cp "$SEED3" "$GATE_BASELINE"
    python3 - "$GATE_BASELINE" "$1" "$2" <<'PY'
import json, sys
path, field, mult = sys.argv[1], sys.argv[2], float(sys.argv[3])
d = json.load(open(path))
hit = [r for r in d["results"] if r["bench"].endswith("/" + field)]
assert len(hit) == 1, f"expected exactly one {field} row, got {len(hit)}"
row = hit[0]
# The fixture has to be capable of producing the verdict the case is about, or the case
# passes on the degraded verdict instead. welch_p returns None below two samples and the
# row then reads "unconfirmed", which no policy blocks.
if row["unit"] != "bytes":
    assert len(row.get("samples") or []) >= 2, (
        f"{field} baseline carries {len(row.get('samples') or [])} sample(s); a timing row "
        "needs >= 2 to reach a blocking verdict, so this fixture cannot test an exemption"
    )
assert mult < 1.0, (
    f"multiplier {mult} scales the baseline UP, which makes the current run look faster; "
    "an improvement never blocks under any policy and the case would prove nothing"
)
row["value"] *= mult
row["samples"] = [s * mult for s in row.get("samples") or []]
json.dump(d, open(path, "w"))
PY
  }

  seed_scaled response_bytes 0.5
  gate_run_n "$TMP/gate-bytes" 3
  check "a byte count that moved BLOCKS the gate" 1 $?

  seed_scaled server_median 0.1
  gate_run_n "$TMP/gate-timing" 3
  check "a 10x timing REGRESSION does not block the gate" 0 $?

  # CONTROL for the case above: with the timing exemptions stripped, that same 10x regression
  # must block. Otherwise "did not block" is evidence of nothing.
  grep -v -- '--non-blocking="/' scripts/bench-gate.sh > "$GATE_COPY"
  chmod +x "$GATE_COPY"
  gate_run_n "$TMP/gate-timing-armed" 3 "./$GATE_COPY"
  check "(control) the same regression DOES block once the exemption is removed" 1 $?
  rm -f "$GATE_COPY"

  # The sample-count guard, both directions. Raising BENCH_MEASURED "for accuracy" is the
  # intuitive move and it makes the naive standard error shrink as sqrt(n) against a floor
  # that does not move, so it must not be silently possible against an old baseline.
  cp "$SEED3" "$GATE_BASELINE"
  gate_run_n "$TMP/gate-n-match" 3
  check "a baseline recorded at the same sample count is accepted" 0 $?
  gate_run_n "$TMP/gate-n-mismatch" 10
  check "a baseline recorded at a different sample count is REFUSED" 2 $?

  # And the gate has to SAY it gates bytes only, or a green run reads as a performance pass.
  cp "$TMP/gate-noseed/seed-0/${GATE_CELL}.json" "$GATE_BASELINE"
  BANNER="$(BENCH_ENTRIES_LOG2=10 BENCH_RECORD_BYTES=32 BENCH_MEASURED=1 BENCH_WARMUP=0 \
    BENCH_SEEDS=0 BENCH_OUT_DIR="$TMP/gate-banner" ./scripts/bench-gate.sh 2>&1 || true)"
  case "$BANNER" in
    *"BYTE COUNTS ONLY"*) check "the gate states that it gates bytes only" 0 0 ;;
    *)                    check "the gate states that it gates bytes only" 0 1 ;;
  esac

  rm -f "$GATE_BASELINE"
else
  echo "  FAIL  the gate produced no artifact to seed a baseline from" >&2
  FAILURES=$((FAILURES + 1))
fi
set -e

if [[ "$FAILURES" -ne 0 ]]; then
  echo "bench-gate selftest: ${FAILURES} case(s) failed" >&2
  exit 1
fi
echo "bench-gate selftest: all ${CASES} cases behaved as specified"
