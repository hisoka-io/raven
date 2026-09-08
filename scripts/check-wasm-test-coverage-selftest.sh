#!/usr/bin/env bash
# Red-proof for check-wasm-test-coverage.sh.
#
# That gate exists because the tree's only #[wasm_bindgen_test] was compiled on every push,
# executed by nothing, and WRONG when finally run — then a second wasm file landed the same day
# and was invisible for the same reason. Both cases below are that shape: a wasm test present in
# the tree that no CI job names.
set -uo pipefail
cd "$(dirname "$0")/.."

GATE=scripts/check-wasm-test-coverage.sh
CI=.github/workflows/ci.yml
NEWFILE=crates/client/tests/zz_selftest_wasm_probe.rs
BC=$(mktemp)
cp "$CI" "$BC"
trap 'cp "$BC" "$CI"; rm -f "$BC" "$NEWFILE"' EXIT

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
  cp "$BC" "$CI"; rm -f "$NEWFILE"
}

echo "check-wasm-test-coverage-selftest.sh: two ways a wasm test goes unrun, plus the control"

bash "$GATE" > /dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "SELFTEST CANNOT RUN: the gate already fails on the unmutated tree." >&2; exit 1
fi
echo "  ok: the unmutated tree -> exit 0"

# 1. A NEW wasm test file that no CI step names. This is the case that actually happened.
#    It is untracked on purpose: the gate greps --untracked precisely so a brand-new file counts.
cat > "$NEWFILE" <<'RS'
#![cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;
#[wasm_bindgen_test]
fn zz_selftest_probe() {}
RS
expect 1 "a new #[wasm_bindgen_test] file named by no CI step"

# 2. An EXISTING wasm target dropped from the CI step - the list rotting rather than the tree
#    growing. Anchored on the target name, and asserted to have applied so a rename upstream
#    cannot turn this case into a silent no-op.
sed -i '/--test session_params_drift/d' "$CI"
if /usr/bin/grep -q -- '--test session_params_drift' "$CI"; then
  echo "SELFTEST FIXTURE STALE: could not remove the session_params_drift target from ${CI};" >&2
  echo "  this case proved NOTHING. Re-point it at a target the step actually names." >&2
  fails=1
  cp "$BC" "$CI"
else
  expect 1 "an existing wasm target dropped from the CI step"
fi

if [ "$fails" -ne 0 ]; then
  echo "check-wasm-test-coverage-selftest.sh: the gate is not discriminating." >&2
  exit 1
fi
echo "check-wasm-test-coverage-selftest.sh: all cases behaved as required."
