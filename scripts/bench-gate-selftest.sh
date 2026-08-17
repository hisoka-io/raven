#!/usr/bin/env bash
# Red-proof for the bench gate (O-019). Runs no bench: it drives the differ directly with
# synthetic artifacts, so it is fast enough to gate every commit.
#
# Phase 1 ships --report-only, which means CI never observes the blocking path. Without
# this, the day --report-only is removed would be the first time anyone learns whether the
# gate can fail at all.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

BIN=./tools/bench-compare/target/release/bench-compare
cargo build --manifest-path tools/bench-compare/Cargo.toml --release >/dev/null 2>&1

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

FAILURES=0
check() { # name expected_rc actual_rc
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

if [[ "$FAILURES" -ne 0 ]]; then
  echo "bench-gate selftest: ${FAILURES} case(s) failed" >&2
  exit 1
fi
echo "bench-gate selftest: all 9 cases behaved as specified"
