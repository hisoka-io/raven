#!/usr/bin/env bash
# Red-proof for assert-lane-counts.sh.
#
# That gate shipped with TWO counting bugs its prose red-proof missed, both found by reading its
# source rather than running it (M-065):
#   - its row anchor required `::` before the space, so it dropped every in-src lib test
#     (`pkg imt::tests::name`) and undercounted the one lane whose filter depends on one;
#   - correcting that broke bench rows (`pkg::bench/name test`, a slash in the binary segment) and
#     silently dropped the two SLO benches this build had just enrolled.
# Both are counting errors, not resolution errors, so the cases below mutate the EXPECTATIONS and
# check the comparison — the half that decides whether a shrinking lane is caught.
#
# COST: each case runs the gate, which invokes `cargo nextest list` per lane. Warm target dir,
# ~1-2 min total; cold, a full build. It is wired into the lane-counts CI job, which already pays
# that build.
set -uo pipefail
cd "$(dirname "$0")/.."

GATE=scripts/assert-lane-counts.sh
EXPECTED=.github/expected-lane-counts.tsv
FIXTURES=scripts/fixtures/assert-lane-counts
[ -f "$EXPECTED" ] || { echo "missing ${EXPECTED}; run ${GATE} --update" >&2; exit 1; }

BE=$(mktemp)
ROWS=$(mktemp)
cp "$EXPECTED" "$BE"
trap 'cp "$BE" "$EXPECTED"; rm -f "$BE" "$ROWS"' EXIT

fails=0
expect() {  # expect <want-nonzero:0|1> <label>
  bash "$GATE" > /dev/null 2>&1
  local rc=$? want="$1" label="$2"
  if [ "$want" = 1 ] && [ "$rc" -eq 0 ]; then
    echo "SELFTEST FAIL: ${label} did not trip the gate" >&2; fails=1
  elif [ "$want" = 0 ] && [ "$rc" -ne 0 ]; then
    echo "SELFTEST FAIL: ${label} tripped the gate but should not have (exit ${rc})" >&2; fails=1
  else
    echo "  ok: ${label} -> exit ${rc}"
  fi
  cp "$BE" "$EXPECTED"
}

# The lane this file mutates. Picked because its filter carries a bare `test(...)` term resolving
# to an IN-SRC lib test, which is the row shape the gate was originally blind to.
LANE='durability-and-closure/engine-ignored'
/usr/bin/grep -q "^${LANE}	" "$EXPECTED" || {
  echo "SELFTEST FIXTURE STALE: no row for '${LANE}' in ${EXPECTED}; these cases would prove" >&2
  echo "  NOTHING. Re-point LANE at a row that exists." >&2; exit 1; }

echo "assert-lane-counts-selftest.sh: three ways a lane goes quiet, plus the control"

cat > "$ROWS" <<'ROWS'
raven-railgun-engine::integration_target integration_test
raven-railgun-engine in_src::tests::unit_test
raven-railgun-engine::bench/latency_bench bench_test
    Finished listing tests
ROWS

row_count=$(bash "$GATE" --count-fixture < "$ROWS")
if [ "$row_count" -ne 3 ]; then
  echo "SELFTEST FAIL: parser fixture counted ${row_count}, expected integration + lib + bench = 3" >&2
  exit 1
fi
echo "  ok: parser recognizes integration, in-src lib, and bench rows"

for marker in integration_target ' in_src::' bench/latency_bench; do
  observed=$(sed "/${marker//\//\\/}/d" "$ROWS" | bash "$GATE" --count-fixture)
  if [ "$observed" -ne 2 ]; then
    echo "SELFTEST FAIL: dropping '${marker}' produced ${observed}, expected 2" >&2
    exit 1
  fi
  echo "  ok: dropping ${marker} changes the parser count 3 -> 2"
done

bash "$GATE" --check-name-fixture \
  "$FIXTURES/expected-with-removed-lane.tsv" "$FIXTURES/current-lanes.tsv" \
  > /dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "SELFTEST FAIL: an expectation for a lane removed from ci.yml did not trip the gate" >&2
  fails=1
else
  echo "  ok: a recorded lane absent from ci.yml trips the gate"
fi

bash "$GATE" > /dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "SELFTEST CANNOT RUN: the gate already fails on the unmutated tree." >&2
  echo "  Reconcile the counts (${GATE} --update, explaining any drop) and re-run." >&2
  exit 1
fi
echo "  ok: the unmutated tree -> exit 0"

# 1. The lane SHRANK: raise the expectation, so the measured count now falls short. This is the
#    real defect - tests deleted out of a lane that still resolves and still reports success.
cur=$(/usr/bin/grep "^${LANE}	" "$EXPECTED" | cut -f2)
awk -F'\t' -v l="$LANE" -v n="$((cur + 1000))" 'BEGIN{OFS="\t"} $1==l{$2=n} {print}' "$BE" > "$EXPECTED"
expect 1 "a lane selecting fewer tests than recorded (the shrink this gate exists for)"

# 2. A lane with NO recorded expectation - a new lane added to ci.yml and never seeded, which
#    would otherwise pass unexamined.
/usr/bin/grep -v "^${LANE}	" "$BE" > "$EXPECTED"
expect 1 "a lane present in ci.yml with no expected count recorded"

# 3. The live in-src row floor supplements the shape fixture with the current lane.
if [ "$cur" -lt 9 ]; then
  echo "SELFTEST FAIL: ${LANE} is recorded at ${cur}; it must be >= 9, because its filter's bare" >&2
  echo "  test() term resolves to an in-src lib test. A lower number means the row anchor in" >&2
  echo "  ${GATE} stopped counting lib rows again - see M-065." >&2
  fails=1
else
  echo "  ok: ${LANE} counts its in-src lib row (${cur} >= 9)"
fi

if [ "$fails" -ne 0 ]; then
  echo "assert-lane-counts-selftest.sh: the gate is not discriminating." >&2
  exit 1
fi
echo "assert-lane-counts-selftest.sh: all cases behaved as required."
