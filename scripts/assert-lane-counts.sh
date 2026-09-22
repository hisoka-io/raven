#!/usr/bin/env bash
# Every filtered CI lane must select the number of tests it is supposed to select.
#
# A nextest filter can stop selecting tests without anything going red. Measured on this repo,
# 0.9.129: a `test(Y)` term naming a nonexistent test contributes nothing while the lane stays
# green whenever another term still matches, and a lane whose binaries were all deleted can
# shrink to a handful without a single failure. Both happened here inside one week:
#   - a test split renamed `production_cell_round_trip_and_batch_within_budget`, orphaning the
#     subtraction term that named it;
#   - two whole test files were deleted while ci.yml still named their binaries.
# scripts/check-ci-filter-names.sh catches a term that resolves to NOTHING. It cannot catch a
# lane that still resolves but now runs 12 tests where it used to run 65. This does.
#
# It must also never blame a filter for something else. CI 35579440775 printed six "selects ZERO
# tests" lines against six healthy lanes, and a reader who believed it would have gone editing
# filters. Three failures are therefore reported as three different things: BUILD FAILED (nothing
# was listed, no lane was measured), FILTERSET REJECTED (this one lane's filter is malformed), and
# selects ZERO / SHRANK (the filter resolved and the tests are gone).
#
# The counts are a ratchet, not a pin: a lane may only GROW silently. A DROP is a hard failure
# that must be explained by editing .github/expected-lane-counts.tsv in the same change, so a
# deletion has to be stated rather than absorbed.
#
# Usage:
#   scripts/assert-lane-counts.sh            # verify against the checked-in expectations
#   scripts/assert-lane-counts.sh --update   # rewrite expectations from the current tree
#
# CARGO_TARGET_DIR is honoured; a warm one makes this cheap, a cold one pays a full build once.
set -uo pipefail
cd "$(dirname "$0")/.."

CI=.github/workflows/ci.yml
EXPECTED=.github/expected-lane-counts.tsv
MANIFEST=adapters/railgun/Cargo.toml
MODE="${1:-check}"
# Fault-injection seam, used only by scripts/assert-lane-counts-selftest.sh: it points this at a
# stub that exits 101 or 94, so the build-failure and filterset messages below can be red-proved
# without breaking the shared tree. A real run must never set it; if it is set, the loop below says
# so loudly, because a green from an injected run means nothing.
CARGO="${LANE_COUNTS_FAKE_CARGO:-cargo}"

count_nextest_rows() {
  # Strip SGR escapes first. `--color never` is pinned at the call site, but losing it is invisible:
  # a coloured row starts with an escape, misses the column-0 anchor, and every lane reads 0 while
  # the build was fine. That is CI 35579440775 verbatim. This is the belt to that flag's braces.
  /usr/bin/sed -e 's/\x1b\[[0-9;]*m//g' \
    | /usr/bin/grep -cE '^[A-Za-z0-9_-]+(::[A-Za-z0-9_/-]+)? ' || true
}

check_lane_name_completeness() {
  local expected_file="$1" current_file="$2" missing=0 name count

  while IFS=$'\t' read -r name count; do
    case "$name" in
      ""|'#'*) continue ;;
    esac
    if ! /usr/bin/grep -Fqx -- "$name" "$current_file"; then
      echo "LANE ${name}: expected count is recorded, but the lane is absent from ${CI}." >&2
      missing=1
    fi
  done < "$expected_file"

  while IFS= read -r name; do
    [ -z "$name" ] && continue
    if ! awk -F'\t' -v lane="$name" '$1 == lane { found=1 } END { exit !found }' "$expected_file"; then
      echo "LANE ${name}: no expected count recorded. Add it to ${EXPECTED}." >&2
      missing=1
    fi
  done < "$current_file"

  return "$missing"
}

if [ "$MODE" = "--count-fixture" ]; then
  count_nextest_rows
  exit 0
fi

if [ "$MODE" = "--check-name-fixture" ]; then
  [ "$#" -eq 3 ] || { echo "usage: $0 --check-name-fixture EXPECTED CURRENT" >&2; exit 2; }
  check_lane_name_completeness "$2" "$3"
  exit $?
fi

# Emit one TSV row per filtered lane: name, packages, cargo flags, extra flags, filter.
# Sourced from ci.yml itself so a new lane cannot be added without this gate seeing it.
lanes=$(python3 - "$CI" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
rows = []
for jn, job in (d.get('jobs') or {}).items():
    mat = ((job.get('strategy') or {}).get('matrix') or {})
    for _key, entries in mat.items():
        if not isinstance(entries, list):
            continue
        for e in entries:
            if isinstance(e, dict) and e.get('filter'):
                rows.append((
                    f"{jn}/{e.get('name','?')}",
                    e.get('packages', ''),
                    e.get('cargo_flags', '') or '',
                    '--run-ignored all',
                    e['filter'],
                ))
    # Steps that carry an inline -E filterset (the nightly production-cell lane).
    for s in (job.get('steps') or []):
        run = s.get('run') or ''
        if 'nextest' not in run or "-E '" not in run:
            continue
        body = ' '.join(run.split())
        filt = body.split("-E '", 1)[1].rsplit("'", 1)[0]
        # The matrix jobs template their filter in as ${{ matrix.lane.filter }}; the real
        # values were already collected from the matrix above, and the literal template is
        # not a filterset (nextest exits 94 on it).
        if '${{' in filt:
            continue
        pkgs = ' '.join(f"-p {t}" for t in body.split() if t.startswith('raven-railgun-'))
        extra = '--run-ignored all'
        if '--all-targets' in body:
            extra += ' --all-targets'
        rows.append((f"{jn}/inline", pkgs, '', extra, filt))
# Empty fields are emitted as "-", never as "". Tab is IFS *whitespace* to bash, so
# `IFS=$'\t' read a b c d e` COLLAPSES a run of tabs into one delimiter and drops empty
# fields entirely — every lane with no cargo_flags had its columns shift left and handed
# nextest a truncated filterset, which then blamed the filter. Placeholders keep the arity fixed.
for r in rows:
    print('\t'.join((x.replace('\t', ' ') or '-') for x in r))
PY
) || { echo "assert-lane-counts.sh: could not parse ${CI}" >&2; exit 1; }

[ -n "$lanes" ] || { echo "assert-lane-counts.sh: no filtered lanes found - parser drift?" >&2; exit 1; }

tmp=$(mktemp)
lane_names=$(mktemp)
# Cargo's stderr is kept OUT of the counted stream and off the success path, but whole on failure:
# the old `2>&1 | tail -3` showed only cargo's `could not compile` summary, which names the crate
# and never the cause - a `-fuse-ld` linker error sits a dozen lines above it.
lane_err=$(mktemp)
trap 'rm -f "$tmp" "$lane_names" "$lane_err"' EXIT
fail=0

while IFS=$'\t' read -r -u 3 name _rest; do
  [ -z "$name" ] || printf '%s\n' "$name" >> "$lane_names"
done 3<<< "$lanes"

if [ "$MODE" != "--update" ]; then
  [ -f "$EXPECTED" ] || { echo "assert-lane-counts.sh: missing ${EXPECTED}; run with --update" >&2; exit 1; }
  if ! check_lane_name_completeness "$EXPECTED" "$lane_names"; then
    fail=1
  fi
fi

# One line, because the build under this loop was silent for seven minutes in CI and a reader
# could not tell a cold build from a hang. The success path stays quiet after it.
echo "assert-lane-counts.sh: listing $(wc -l < "$lane_names") lanes; the first pays the test build." >&2
if [ -n "${LANE_COUNTS_FAKE_CARGO:-}" ]; then
  echo "  FAULT INJECTION ACTIVE (LANE_COUNTS_FAKE_CARGO=${CARGO}): this run proves NOTHING" >&2
  echo "  about the real tree. Only the selftest may set it." >&2
fi

# The lane list is fed on FD 3 and cargo's stdin is closed. Both matter: cargo reads stdin, and
# on the first version of this script it swallowed the rest of the here-string, so every lane
# after the first got a truncated line and nextest reported "failed to parse filterset" — a
# message that blames the filter for a bug in the loop.
while IFS=$'\t' read -r -u 3 name pkgs flags extra filter; do
  [ -z "$name" ] && continue
  [ "$pkgs" = "-" ] && pkgs=""
  [ "$flags" = "-" ] && flags=""
  [ "$extra" = "-" ] && extra=""
  # shellcheck disable=SC2086
  # `ci.yml:14` sets CARGO_TERM_COLOR: always workflow-wide, and nextest does NOT suppress
  # colour when stdout is a pipe: measured 30 rows unset, 0 with `always`, 30 with `never`.
  # Every lane then took the count==0 branch, so this gate has been unconditionally red since
  # it was added and has never protected anything. Pin it here rather than trusting the env.
  out=$("$CARGO" nextest list --color never --manifest-path "$MANIFEST" $pkgs $flags $extra \
        --cargo-profile ci-test -E "$filter" 2>"$lane_err" < /dev/null)
  rc=$?
  # Three failures, three operator actions, so three distinct messages: the build is broken / this
  # filter is malformed / this lane lost tests. Collapsing the first two into one made the gate
  # blame filters for a broken linker. nextest 0.9.129 exit codes, measured: 94 = filterset
  # rejected (parse error, or a term matching no binary/test name), 101 = test build failed.
  # Anything else also means nothing was listed, so it is handled as a build failure.
  if [ "$rc" -eq 94 ]; then
    echo "LANE ${name}: FILTERSET REJECTED by nextest (exit 94). The build is fine; the filter is not." >&2
    echo "  filter: ${filter}" >&2
    cat "$lane_err" >&2
    fail=1
    continue
  elif [ "$rc" -ne 0 ]; then
    echo "BUILD FAILED: '${CARGO} nextest list' exited ${rc} while listing lane ${name}." >&2
    echo "  NOTHING was listed, so this gate measured NO lane and is making NO claim about any" >&2
    echo "  filter. Fix the build. Do not edit ${EXPECTED} and do not touch a lane's filter." >&2
    echo "  --- cargo/nextest stderr follows, in full ---" >&2
    cat "$lane_err" >&2
    exit 1
  fi
  # `nextest list` prints one unindented row per test, in TWO shapes:
  #   integration/bench target:  `raven-railgun-engine::some_binary the_test_name`
  #   lib (in-src #[cfg(test)]): `raven-railgun-engine imt::tests::the_test_name`
  # The second has NO `::` before the space, so an anchor of `^[A-Za-z0-9_-]+::` silently drops
  # every in-src test — which undercounted the engine-ignored lane (its filter carries a bare
  # `test(...)` term that resolves to a lib test) and would have let that lane shrink to nothing
  # while this gate reported a healthy number. Cargo's own progress lines are INDENTED, so
  # anchoring at column 0 on "token, optional ::token, space" counts tests and nothing else.
  # The binary segment may carry a kind prefix with a slash — a bench target lists as
  # `raven-railgun-cli::bench/production_cell_budget_bench <test>` — so `/` belongs in the class.
  # Omitting it silently dropped exactly the two SLO benches this build enrolled in the nightly
  # lane, i.e. the check would have gone quiet about the tests it was added to protect.
  count=$(printf '%s\n' "$out" | count_nextest_rows)
  printf '%s\t%s\n' "$name" "$count" >> "$tmp"
done 3<<< "$lanes"

if [ "$MODE" = "--update" ]; then
  # A lane that failed above never reached "$tmp", and --update ignores $fail, so rewriting from a
  # broken run would silently DELETE that lane's pin - the gate erasing its own evidence.
  if [ "$fail" -ne 0 ]; then
    echo "assert-lane-counts.sh: refusing to rewrite ${EXPECTED} from a run with failing lanes." >&2
    exit 1
  fi
  {
    echo "# Expected test count per filtered CI lane. Regenerate: scripts/assert-lane-counts.sh --update"
    echo "# A lane may GROW silently; a DROP is a hard failure and must be explained by editing"
    echo "# this file in the same change that removes the tests."
    cat "$tmp"
  } > "$EXPECTED"
  echo "assert-lane-counts.sh: wrote ${EXPECTED}"
  cat "$tmp"
  exit 0
fi

while IFS=$'\t' read -r name count; do
  want=$(/usr/bin/grep -P "^\Q${name}\E\t" "$EXPECTED" | cut -f2)
  if [ -z "$want" ]; then
    echo "LANE ${name}: no expected count recorded. Add it to ${EXPECTED}." >&2
    fail=1
  elif [ "$count" -eq 0 ]; then
    echo "LANE ${name}: selects ZERO tests. The lane is running nothing and reporting success." >&2
    fail=1
  elif [ "$count" -lt "$want" ]; then
    echo "LANE ${name}: selects ${count} tests, expected ${want} - it SHRANK by $((want - count))." >&2
    echo "  If tests were deliberately deleted, say so by updating ${EXPECTED} in the same change." >&2
    fail=1
  fi
done < "$tmp"

if [ "$fail" -ne 0 ]; then
  echo "scripts/assert-lane-counts.sh: at least one lane does not select what it should." >&2
  exit 1
fi
echo "scripts/assert-lane-counts.sh: clean ($(wc -l < "$tmp") lanes checked)."
