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
# The third bug was worse, because it made the gate LIE: CI 35579440775 reported six lanes as
# "selects ZERO tests" while all six were healthy (colour escapes ahead of the row anchor). A gate
# that can misattribute is worse than no gate, so the stub cases below drive the four outcomes
# apart — build broken, filterset malformed, lane empty, lane shrunk — by injecting an exit code
# through LANE_COUNTS_FAKE_CARGO instead of breaking the tree. They need no build and run first.
#
# COST: the stub cases are instant. The cases that mutate EXPECTATIONS run the real gate, which
# invokes `cargo nextest list` per lane: ~1-2 min on a warm target dir, a full build when cold.
# It is wired into the lane-counts CI job, which already pays that build.
set -uo pipefail
cd "$(dirname "$0")/.."

GATE=scripts/assert-lane-counts.sh
EXPECTED=.github/expected-lane-counts.tsv
FIXTURES=scripts/fixtures/assert-lane-counts
[ -f "$EXPECTED" ] || { echo "missing ${EXPECTED}; run ${GATE} --update" >&2; exit 1; }

BE=$(mktemp)
ROWS=$(mktemp)
STUBS=$(mktemp -d)
cp "$EXPECTED" "$BE"
trap 'cp "$BE" "$EXPECTED"; rm -f "$BE" "$ROWS"; rm -rf "$STUBS"' EXIT

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

echo "assert-lane-counts-selftest.sh: three ways a lane goes quiet, four ways the gate could"
echo "  misattribute one, plus the control"

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

# Colour immunity. `--color never` is pinned at the call site, but it was absent for the whole life
# of the gate and its loss is silent: the count goes to 0 on a healthy tree and the gate then
# accuses every filter. The counter must survive the flag going missing again.
coloured=$(/usr/bin/sed -e 's/^\([^ ]*\) \(.*\)$/\x1b[35;1m\1\x1b[0m \x1b[34;1m\2\x1b[0m/' "$ROWS" \
  | bash "$GATE" --count-fixture)
if [ "$coloured" -ne 3 ]; then
  echo "SELFTEST FAIL: ANSI-coloured rows counted ${coloured}, expected 3. Losing --color never" >&2
  echo "  would make every lane read 0 and the gate would blame the filters - CI 35579440775." >&2
  exit 1
fi
echo "  ok: ANSI-coloured rows still count (3)"

# --- the four outcomes must not be confusable -------------------------------------------------
# A stub stands in for cargo so an exit code and a stderr body can be injected without breaking the
# tree. Each case asserts the message the operator acts on, and the message they must NOT be given.
cat > "$STUBS/build-fail" <<'STUB'
#!/usr/bin/env bash
cat >&2 <<'CARGO'
   Compiling raven-railgun-engine v0.1.0
error: linking with `cc` failed: exit status: 1
  = note: collect2: fatal error: cannot find 'ld'
          compilation terminated.
error: could not compile `raven-railgun-engine` (lib test) due to 1 previous error
error: command `cargo test --no-run` exited with code 101
CARGO
exit 101
STUB
cat > "$STUBS/filterset-bad" <<'STUB'
#!/usr/bin/env bash
echo "  error: operator didn't match any binary names" >&2
exit 94
STUB
cat > "$STUBS/lists-nothing" <<'STUB'
#!/usr/bin/env bash
echo "    Finished \`ci-test\` profile [unoptimized] target(s)" >&2
exit 0
STUB
cat > "$STUBS/lists-one" <<'STUB'
#!/usr/bin/env bash
echo "    Finished \`ci-test\` profile [unoptimized] target(s)" >&2
echo "raven-railgun-engine::one_binary the_only_surviving_test"
exit 0
STUB
cat > "$STUBS/lists-coloured" <<'STUB'
#!/usr/bin/env bash
echo "    Finished \`ci-test\` profile [unoptimized] target(s)" >&2
for i in $(seq 1 200); do
  printf '\033[35;1mraven-railgun-engine::b\033[0m \033[34;1mtest_%s\033[0m\n' "$i"
done
exit 0
STUB
chmod +x "$STUBS"/*

stub_case() {  # stub_case <stub> <want-nonzero:0|1> <forbidden-text|-> <label> <required-text>...
  local stub="$1" wantfail="$2" forbid="$3" label="$4"; shift 4
  local out rc bad=0 need
  out=$(LANE_COUNTS_FAKE_CARGO="$STUBS/$stub" bash "$GATE" 2>&1); rc=$?
  if [ "$wantfail" = 1 ] && [ "$rc" -eq 0 ]; then
    echo "SELFTEST FAIL: ${label}: expected a non-zero exit, got 0" >&2; bad=1
  elif [ "$wantfail" = 0 ] && [ "$rc" -ne 0 ]; then
    echo "SELFTEST FAIL: ${label}: expected exit 0, got ${rc}" >&2; bad=1
  fi
  for need in "$@"; do
    if ! printf '%s\n' "$out" | /usr/bin/grep -qF -- "$need"; then
      echo "SELFTEST FAIL: ${label}: output never says '${need}'" >&2; bad=1
    fi
  done
  if [ "$forbid" != "-" ] && printf '%s\n' "$out" | /usr/bin/grep -qF -- "$forbid"; then
    echo "SELFTEST FAIL: ${label}: output claims '${forbid}', which is a false cause here" >&2; bad=1
  fi
  if [ "$bad" -ne 0 ]; then fails=1; else echo "  ok: ${label} -> exit ${rc}"; fi
}

stub_case build-fail 1 "selects ZERO tests" \
  "a failed build is reported as a build failure, never as an empty filter" \
  "BUILD FAILED" "collect2: fatal error: cannot find 'ld'"
stub_case filterset-bad 1 "BUILD FAILED" \
  "a rejected filterset is reported as a filter fault, not a build fault" \
  "FILTERSET REJECTED"
stub_case lists-nothing 1 "BUILD FAILED" \
  "a filter that genuinely selects nothing still trips the zero-selection failure" \
  "selects ZERO tests"
stub_case lists-one 1 "selects ZERO tests" \
  "a lane below its pinned count is reported as a SHRINK, not as an empty filter" \
  "it SHRANK by"
stub_case lists-coloured 0 "selects ZERO tests" \
  "coloured rows end to end: the gate passes instead of accusing every filter"

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
