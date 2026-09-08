#!/usr/bin/env bash
# Red-proof for check-ci-filter-names.sh. The gate ships with the proof that it can fail.
#
# The first draft of the gate PASSED this file's case 1, because its name class was [a-z_0-9] and
# the mutation introduced an uppercase letter, so the term was silently skipped. A gate that cannot
# see part of its own input is worse than no gate; that is why this selftest exists.
set -uo pipefail
cd "$(dirname "$0")/.."
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

echo "check-ci-filter-names-selftest.sh: five cases the gate must fail on"

sed -i 's/test(insert_rejects_overflow_past_capacity)/test(insert_rejects_overflow_past_capacity_RENAMED)/' "$CI"
expect_fail "a test() term renamed to a nonexistent test (uppercase in the name)"

sed -i 's/test(insert_rejects_overflow_past_capacity)/test(no_such_test_anywhere)/' "$CI"
expect_fail "a test() term renamed to a nonexistent test (lowercase)"

sed -i 's/binary(offline_packing_keys_cache)/binary(a_target_that_does_not_exist)/' "$CI"
expect_fail "a binary() term naming a deleted target"

sed -i '/-p raven-railgun-testkit/d' "$CI"
expect_fail "a workspace member dropped from every -p list"

# Case 5: the file a binary() names is deleted in the WORKING TREE but still in the index -
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
