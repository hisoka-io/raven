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
# invokes `cargo nextest list` per lane: seconds on a warm target dir, the lanes' builds when cold.
# One case lists every lane from its full build, to prove the narrowed listing counts the same
# tests; that pays every lane's full build. It is wired into the lane-counts CI job, whose
# --selected pass builds the whole workspace anyway.
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
  # shellcheck disable=SC2086
  out=$(LANE_COUNTS_FAKE_CARGO="$STUBS/$stub" bash "$GATE" ${GATE_ARGS:-} 2>&1); rc=$?
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
# The per-lane form a lane's own job runs must attribute the same way.
GATE_ARGS="--lane ${LANE}" stub_case build-fail 1 "selects ZERO tests" \
  "--lane: a failed build is reported as a build failure" \
  "BUILD FAILED" "collect2: fatal error: cannot find 'ld'"
GATE_ARGS="--lane durability-and-closure/cli-ignored" stub_case lists-one 1 "selects ZERO tests" \
  "--lane: a lane below its pinned count is reported as a SHRINK" \
  "LANE durability-and-closure/cli-ignored: selects 1 tests" "it SHRANK by"
# The gate is exact, so this stub's 200 rows pass only against pins of 200; what is under test is
# that coloured rows are counted at all.
awk -F'\t' 'BEGIN{OFS="\t"} /^#/ || NF<2 {print; next} {print $1, 200}' .github/expected-lane-counts.tsv \
  > "$STUBS/expected-200.tsv"
LANE_COUNTS_EXPECTED="$STUBS/expected-200.tsv" stub_case lists-coloured 0 "selects ZERO tests" \
  "coloured rows end to end: the gate passes instead of accusing every filter"

# --- each lane is counted under the --run-ignored mode it runs with ---------------------------
# The gate once listed every lane under a hard-coded `all`, so a lane switched to `only` would have
# been measured against tests it no longer runs. The mode now comes from the matrix entry the
# workflow reads, and these copies prove the gate refuses a workflow where that link is broken.
workflow_case() {  # workflow_case <workflow-copy> <label> <required-text>...
  local copy="$1" label="$2"; shift 2
  local out rc bad=0 need
  if cmp -s "$copy" .github/workflows/ci.yml; then
    echo "SELFTEST CANNOT RUN: ${label}: the mutation no longer applies to ci.yml" >&2; fails=1; return
  fi
  out=$(LANE_COUNTS_WORKFLOW="$copy" bash "$GATE" 2>&1); rc=$?
  [ "$rc" -ne 0 ] || { echo "SELFTEST FAIL: ${label}: the gate passed (exit 0)" >&2; bad=1; }
  for need in "$@"; do
    if ! printf '%s\n' "$out" | /usr/bin/grep -qF -- "$need"; then
      echo "SELFTEST FAIL: ${label}: output never says '${need}'" >&2; bad=1
    fi
  done
  if [ "$bad" -ne 0 ]; then fails=1; printf '%s\n' "$out" | tail -20 >&2; else echo "  ok: ${label} -> exit ${rc}"; fi
}

awk '/^          - name: cli-ignored$/ { lane = 1 } lane && /^ +run_ignored: / { lane = 0; next } { print }' \
  .github/workflows/ci.yml > "$STUBS/ci-no-mode.yml"
workflow_case "$STUBS/ci-no-mode.yml" "a filtered matrix entry with no run_ignored field" \
  "LANE MODE NOT READ: durability-and-closure/cli-ignored: run_ignored is None"

sed 's/--run-ignored ${{ matrix.lane.run_ignored }}/--run-ignored all/' \
  .github/workflows/ci.yml > "$STUBS/ci-constant-mode.yml"
workflow_case "$STUBS/ci-constant-mode.yml" "a lane command that ignores its run_ignored field" \
  "LANE MODE NOT READ: durability-and-closure: its nextest command does not pass --run-ignored"

awk '/^          - name: cli-ignored$/ { lane = 1 } lane && /^ +run_ignored: / { sub(/only$/, "default"); lane = 0 } { print }' \
  .github/workflows/ci.yml > "$STUBS/ci-default-mode.yml"
workflow_case "$STUBS/ci-default-mode.yml" "a lane whose run_ignored is default" \
  "LANE MODE NOT READ: durability-and-closure/cli-ignored: run_ignored is 'default', not one of only, all"

awk '{ line = $0 }
     /^ +--run-ignored \$\{\{ matrix\.lane\.run_ignored \}\} \\$/ {
       indent = line; sub(/--.*/, "", indent)
       print indent "# --run-ignored ${{ matrix.lane.run_ignored }}"
       sub(/\$\{\{ matrix\.lane\.run_ignored \}\}/, "all", line)
     }
     { print line }' .github/workflows/ci.yml > "$STUBS/ci-comment-mode.yml"
workflow_case "$STUBS/ci-comment-mode.yml" "a hard-coded mode with the template only in a comment" \
  "LANE MODE NOT READ: durability-and-closure: its nextest command does not pass --run-ignored"

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

# 0. The narrowed listing builds only the binaries a binary()-union filter names. It must count
#    what the lane's full build counts, lane for lane, or the exact pins mean nothing.
out=$(bash "$GATE" 2>&1)
if ! /usr/bin/grep -qF "named target(s)" <<< "$out"; then
  echo "SELFTEST FAIL: no lane was listed from its named targets, so the narrowing is untested" >&2
  fails=1
elif ! LANE_COUNTS_FULL_LISTING=1 bash "$GATE" > /dev/null 2>&1; then
  echo "SELFTEST FAIL: listed from their full builds, the lanes miss the pins the narrowed listing" >&2
  echo "  meets. The narrowing changed a count." >&2
  fails=1
else
  echo "  ok: every lane counts the same from its named targets as from its full build"
fi

# 0a. A binary() term naming no target cannot be narrowed, so nextest still judges the filter.
sed 's/binary(chain_event_closure)/binary(chain_event_closure_renamed)/' .github/workflows/ci.yml > "$STUBS/ci-renamed.yml"
if cmp -s "$STUBS/ci-renamed.yml" .github/workflows/ci.yml; then
  echo "SELFTEST CANNOT RUN: the renamed-binary plant no longer applies to ci.yml" >&2; fails=1
elif out=$(LANE_COUNTS_WORKFLOW="$STUBS/ci-renamed.yml" bash "$GATE" --lane durability-and-closure/closure 2>&1) \
     || ! /usr/bin/grep -qF "LANE durability-and-closure/closure: FILTERSET REJECTED" <<< "$out"; then
  echo "SELFTEST FAIL: a binary() naming no target was not rejected as a filter fault" >&2
  printf '%s\n' "$out" | tail -5 >&2; fails=1
else
  echo "  ok: a binary() naming no target -> listed in full, FILTERSET REJECTED by nextest"
fi

# 0b. --lane lists that lane alone, still against the whole ci.yml and the whole pin file.
if out=$(bash "$GATE" --lane no-such/lane 2>&1) || ! /usr/bin/grep -qF "no lane named no-such/lane" <<< "$out"; then
  echo "SELFTEST FAIL: --lane accepted a lane ci.yml does not have" >&2; fails=1
else
  echo "  ok: --lane with an unknown lane -> refused by name"
fi
OTHER='durability-and-closure/closure'
/usr/bin/grep -q "^${OTHER}	" "$EXPECTED" || {
  echo "SELFTEST FIXTURE STALE: no row for '${OTHER}' in ${EXPECTED}" >&2; exit 1; }
cur=$(/usr/bin/grep "^${LANE}	" "$EXPECTED" | cut -f2)
awk -F'\t' -v l="$LANE" -v n="$((cur + 1))" 'BEGIN{OFS="\t"} $1==l{$2=n} {print}' "$BE" > "$EXPECTED"
if bash "$GATE" --lane "$LANE" > /dev/null 2>&1; then
  echo "SELFTEST FAIL: --lane ${LANE} passed with its own pin one above its count" >&2; fails=1
elif ! bash "$GATE" --lane "$OTHER" > /dev/null 2>&1; then
  echo "SELFTEST FAIL: --lane ${OTHER} failed on another lane's pin; it must list only its own" >&2; fails=1
else
  echo "  ok: --lane trips on its own lane's shrink and ignores another lane's"
fi
cp "$BE" "$EXPECTED"
printf 'durability-and-closure/removed-lane\t3\n' >> "$EXPECTED"
if out=$(bash "$GATE" --lane "$LANE" 2>&1) \
   || ! /usr/bin/grep -qF "LANE durability-and-closure/removed-lane: expected count is recorded" <<< "$out"; then
  echo "SELFTEST FAIL: --lane did not report a pin whose lane left ci.yml" >&2; fails=1
else
  echo "  ok: --lane still reports a pin whose lane left ci.yml"
fi
cp "$BE" "$EXPECTED"

# 1. The lane SHRANK: raise the expectation, so the measured count now falls short. This is the
#    real defect - tests deleted out of a lane that still resolves and still reports success.
cur=$(/usr/bin/grep "^${LANE}	" "$EXPECTED" | cut -f2)
awk -F'\t' -v l="$LANE" -v n="$((cur + 1000))" 'BEGIN{OFS="\t"} $1==l{$2=n} {print}' "$BE" > "$EXPECTED"
expect 1 "a lane selecting fewer tests than recorded (the shrink this gate exists for)"

# 1b. ONE test deleted from a lane whose pin had slack. Under the old floor rule this passed: lower
#     the pin by one (the lane now looks one test richer than recorded, i.e. unrecorded growth) and
#     the gate must refuse, because that slack is exactly what a later single deletion hides in.
awk -F'\t' -v l="$LANE" -v n="$((cur - 1))" 'BEGIN{OFS="\t"} $1==l{$2=n} {print}' "$BE" > "$EXPECTED"
expect 1 "a lane that grew by one without recording it (slack a deletion would hide in)"

# 1c. And a single deletion at an exact pin: raise the pin by exactly one.
awk -F'\t' -v l="$LANE" -v n="$((cur + 1))" 'BEGIN{OFS="\t"} $1==l{$2=n} {print}' "$BE" > "$EXPECTED"
expect 1 "a lane one test short of its pin (a single deletion)"

# 2. A lane with NO recorded expectation - a new lane added to ci.yml and never seeded, which
#    would otherwise pass unexamined.
/usr/bin/grep -v "^${LANE}	" "$BE" > "$EXPECTED"
expect 1 "a lane present in ci.yml with no expected count recorded"

# 3. The live in-src row floor supplements the shape fixture with the current lane: its filter is
#    a bare test() term naming one in-src lib test, and nothing else.
if [ "$cur" -lt 1 ]; then
  echo "SELFTEST FAIL: ${LANE} is recorded at ${cur}; it must be >= 1, because its filter's bare" >&2
  echo "  test() term resolves to an in-src lib test. A lower number means the row anchor in" >&2
  echo "  ${GATE} stopped counting lib rows again - see M-065." >&2
  fails=1
else
  echo "  ok: ${LANE} counts its in-src lib row (${cur} >= 1)"
fi

# 4. A matrix entry whose mode and the recorded count disagree, in both directions: cli-ignored
#    flipped to `all` re-selects the non-ignored tests the per-push shard runs, and
#    wal-and-snapshot-chaos flipped to `only` selects nothing, since none of its tests is ignored.
awk '/^          - name: / { lane = $3 }
     lane == "cli-ignored" && /^ +run_ignored: only$/ { sub(/only$/, "all") }
     lane == "wal-and-snapshot-chaos" && /^ +run_ignored: all$/ { sub(/all$/, "only") }
     { print }' .github/workflows/ci.yml > "$STUBS/ci-flipped-mode.yml"
workflow_case "$STUBS/ci-flipped-mode.yml" "a lane mode flipped without recounting (both directions)" \
  "LANE durability-and-closure/cli-ignored: selects" "- it GREW by" \
  "LANE durability-and-closure/wal-and-snapshot-chaos: selects ZERO tests"

if [ "$fails" -ne 0 ]; then
  echo "assert-lane-counts-selftest.sh: the gate is not discriminating." >&2
  exit 1
fi
echo "assert-lane-counts-selftest.sh: all cases behaved as required."
