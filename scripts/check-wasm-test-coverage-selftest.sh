#!/usr/bin/env bash
# Red-proof for check-wasm-test-coverage.sh.
#
# That gate exists because the tree's only #[wasm_bindgen_test] was compiled on every push,
# executed by nothing, and WRONG when finally run — then a second wasm file landed the same day
# and was invisible for the same reason. The cases below are that shape: a wasm test present in
# the tree that no CI job names.
set -uo pipefail
cd "$(dirname "$0")/.."

GATE=scripts/check-wasm-test-coverage.sh
FIXTURES=scripts/fixtures/check-wasm-test-coverage

fails=0
expect() {  # expect <want-nonzero:0|1> <workflow> <test-file> <label>
  local want="$1" workflow="$2" test_file="$3" label="$4"
  bash "$GATE" "$workflow" "$test_file" > /dev/null 2>&1
  local rc=$?
  if [ "$want" = 1 ] && [ "$rc" -eq 0 ]; then
    echo "SELFTEST FAIL: ${label} did not trip the gate" >&2; fails=1
  elif [ "$want" = 0 ] && [ "$rc" -ne 0 ]; then
    echo "SELFTEST FAIL: ${label} tripped the gate but should not have (exit ${rc})" >&2; fails=1
  else
    echo "  ok: ${label} -> exit ${rc}"
  fi
}

echo "check-wasm-test-coverage-selftest.sh: five ways a wasm test goes unrun, plus the control"

bash "$GATE" > /dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "SELFTEST CANNOT RUN: the gate already fails on the unmutated tree." >&2; exit 1
fi
echo "  ok: the unmutated tree -> exit 0"

expect 1 "$FIXTURES/uncovered.yml" "$FIXTURES/exact_target.rs" \
  "a new #[wasm_bindgen_test] file named by no CI step"

expect 1 "$FIXTURES/uncovered.yml" "$FIXTURES/cfg_attr_target.rs" \
  "a new cfg_attr wasm_bindgen_test file named by no CI step"

expect 1 "$FIXTURES/prefix-only.yml" "$FIXTURES/exact_target.rs" \
  "a wasm target matching only another target's name prefix"

expect 1 "$FIXTURES/native-only.yml" "$FIXTURES/exact_target.rs" \
  "a wasm target named only by a native cargo test invocation"

expect 1 "$FIXTURES/other-target.yml" "$FIXTURES/exact_target.rs" \
  "an existing wasm target dropped from the CI step"

expect 0 "$FIXTURES/covered.yml" "$FIXTURES/exact_target.rs" \
  "an exact target in a wasm-pack test command"

if [ "$fails" -ne 0 ]; then
  echo "check-wasm-test-coverage-selftest.sh: the gate is not discriminating." >&2
  exit 1
fi
echo "check-wasm-test-coverage-selftest.sh: all cases behaved as required."
