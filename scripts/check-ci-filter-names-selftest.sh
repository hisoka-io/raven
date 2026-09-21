#!/usr/bin/env bash
# Red-proof for check-ci-filter-names.sh. The gate ships with the proof that it can fail.
#
# The first draft of the gate PASSED this file's case 1, because its name class was [a-z_0-9] and
# the mutation introduced an uppercase letter, so the term was silently skipped. A gate that cannot
# see part of its own input is worse than no gate; that is why this selftest exists.
set -uo pipefail
cd "$(dirname "$0")/.."

# `--selected` asks nextest, so it is proven where the test binaries are built, not in the hygiene
# job. It reads copies through FILTER_GATE_*: nothing tracked is mutated on this path.
if [ "${1:-}" = "--selected" ]; then
  scratch=$(mktemp -d)
  trap 'rm -rf "$scratch"' EXIT
  adapter=adapters/railgun/.config/nextest.toml
  real_configs=".config/nextest.toml=Cargo.toml ${adapter}=adapters/railgun/Cargo.toml"
  fails=0

  # One red run carries all four plants - each gate run lists every binary ~40 times - and each
  # headline is asserted by itself, so one check going quiet cannot hide behind the other three.
  sed 's/^\[test-groups\]$/[test-groups]\nplanted-empty-group = { max-threads = 1 }/' "$adapter" \
    > "$scratch/nextest.toml"
  cat >> "$scratch/nextest.toml" <<'PLANT'

[[profile.default.overrides]]
filter = "test(/no_such_test_planted/)"
retries = 0
PLANT
  cp .github/workflows/ci.yml "$scratch/ci.yml"
  cat >> "$scratch/ci.yml" <<'PLANT'
  planted-dead-regex-term:
    runs-on: ubuntu-latest
    steps:
      - run: cargo nextest run --manifest-path adapters/railgun/Cargo.toml --cargo-profile ci-test -E 'test(/./) + test(/no_such_test_planted/)'
  planted-shell-variable-filter:
    runs-on: ubuntu-latest
    steps:
      - run: cargo nextest run --manifest-path adapters/railgun/Cargo.toml --cargo-profile ci-test -E "$FILTER"
PLANT

  echo "check-ci-filter-names-selftest.sh --selected: four plants the gate must name, then the control"
  red=$(FILTER_GATE_WORKFLOW="$scratch/ci.yml" \
        FILTER_GATE_NEXTEST_CONFIGS=".config/nextest.toml=Cargo.toml $scratch/nextest.toml=adapters/railgun/Cargo.toml" \
        bash scripts/check-ci-filter-names.sh --selected 2>&1 > /dev/null)
  rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "SELFTEST FAIL: the planted copies did not trip the gate (exit 0)" >&2
    fails=1
  fi
  while IFS= read -r headline; do
    if /usr/bin/grep -qF -- "$headline" <<< "$red"; then
      echo "  ok: named -> ${headline}"
    else
      echo "SELFTEST FAIL: the gate did not report '${headline}'" >&2
      fails=1
    fi
  done <<EXPECTED
FILTER SELECTS NOTHING: $scratch/nextest.toml profile.default.overrides
TEST GROUP HOLDS NOTHING: $scratch/nextest.toml test-groups.planted-empty-group
FILTER TERM SELECTS NOTHING: $scratch/ci.yml planted-dead-regex-term
FILTER NOT EVALUATED: $scratch/ci.yml planted-shell-variable-filter
EXPECTED
  # exactly the four: a gate that fails everything would name them too
  named=$(/usr/bin/grep -cE '^[A-Z][A-Z ]+: ' <<< "$red" || true)
  if [ "$named" -ne 4 ]; then
    echo "SELFTEST FAIL: expected exactly 4 failures from 4 plants, the gate reported ${named}" >&2
    printf '%s\n' "$red" >&2
    fails=1
  fi

  # the same overrides aimed at the real files: if this is red, the run above proved nothing
  if FILTER_GATE_WORKFLOW=.github/workflows/ci.yml FILTER_GATE_NEXTEST_CONFIGS="$real_configs" \
       bash scripts/check-ci-filter-names.sh --selected > /dev/null 2>&1; then
    echo "  ok: unmutated tree -> exit 0"
  else
    echo "SELFTEST FAIL: --selected rejects the UNMUTATED tree" >&2
    fails=1
  fi

  if [ "$fails" -ne 0 ]; then
    echo "check-ci-filter-names-selftest.sh --selected: the gate is not discriminating." >&2
    exit 1
  fi
  echo "check-ci-filter-names-selftest.sh --selected: all cases behaved as required."
  exit 0
fi

CI=.github/workflows/ci.yml
BAK=$(mktemp)
cp "$CI" "$BAK"
# Case 5 hides a real test file, so its restore is part of the same trap.
VICTIM=adapters/railgun/engine/tests/t1_status_closure.rs
VBAK=$(mktemp)
cp "$VICTIM" "$VBAK"
# Restore installed BEFORE any mutation: a killed run must not leave one applied.
trap 'cp "$BAK" "$CI"; cp "$VBAK" "$VICTIM"; rm -f "$BAK" "$VBAK"' EXIT

fails=0
expect_fail() {
  local label="$1"
  bash scripts/check-ci-filter-names.sh > /dev/null 2>&1
  local rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "SELFTEST FAIL: ${label} did not trip the gate (exit 0)" >&2
    fails=1
  else
    echo "  ok: ${label} -> exit ${rc}"
  fi
  cp "$BAK" "$CI"
}

echo "check-ci-filter-names-selftest.sh: six cases the gate must fail on"

sed -i 's/test(insert_rejects_overflow_past_capacity)/test(insert_rejects_overflow_past_capacity_RENAMED)/' "$CI"
expect_fail "a test() term renamed to a nonexistent test (uppercase in the name)"

sed -i 's/test(insert_rejects_overflow_past_capacity)/test(no_such_test_anywhere)/' "$CI"
expect_fail "a test() term renamed to a nonexistent test (lowercase)"

sed -i 's/binary(offline_packing_keys_cache)/binary(a_target_that_does_not_exist)/' "$CI"
expect_fail "a binary() term naming a deleted target"

sed -i '/-p raven-railgun-testkit/d' "$CI"
expect_fail "a workspace member dropped from every -p list"

cp scripts/fixtures/check-ci-filter-names/workspace-member-outside-lanes.yml "$CI"
expect_fail "a workspace member named only outside the fmt and test jobs"

# Case 6: the file a binary() names is deleted in the WORKING TREE but still in the index -
# exactly what an uncommitted lane deletion looks like. The gate's first version resolved
# names with `git ls-files`, which answers from the index, so it stayed green while the
# nightly lane would have died at nextest exit 94. ci.yml is untouched here on purpose:
# the mutation is the missing file, not the filter.
rm -f "$VICTIM"
expect_fail "a binary() whose file is deleted in the working tree but still in the index"
cp "$VBAK" "$VICTIM"

# And the control: unmutated, the gate must PASS. A gate that always fails is not a gate.
bash scripts/check-ci-filter-names.sh > /dev/null 2>&1
rc=$?
if [ "$rc" -ne 0 ]; then
  echo "SELFTEST FAIL: the gate rejects the UNMUTATED tree (exit ${rc})" >&2
  fails=1
else
  echo "  ok: unmutated tree -> exit 0"
fi

if [ "$fails" -ne 0 ]; then
  echo "check-ci-filter-names-selftest.sh: the gate is not discriminating." >&2
  exit 1
fi
echo "check-ci-filter-names-selftest.sh: all cases behaved as required."
