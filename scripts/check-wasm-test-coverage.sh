#!/usr/bin/env bash
# Every file carrying a wasm_bindgen_test attribute must be named in ci.yml's wasm-pack step.
#
# `wasm-pack test --node <crate>` without `--test` was measured (2026-09-07) to stop after the
# first target reporting "no tests to run!", so the CI step names each target explicitly. That
# list is exactly the kind of hand-maintained enumeration this repo has been bitten by: the tree's
# only wasm test went years compiled-but-never-executed, and when finally run it FAILED. A second
# wasm test file landed the same day and was invisible to CI for the same reason.
set -uo pipefail
cd "$(dirname "$0")/.."
CI=.github/workflows/ci.yml
fail=0

# --untracked: a brand-new wasm test file is the case this exists to catch, and it is not in the
# index yet. git grep answers from the working tree; a plain `git ls-files` would not see it.
while IFS= read -r f; do
  [ -z "$f" ] && continue
  stem=$(basename "$f" .rs)
  if ! /usr/bin/grep -q -- "--test ${stem}" "$CI"; then
    echo "WASM TEST NOT RUN BY CI: ${f}" >&2
    echo "  It carries a wasm_bindgen_test attribute but no '--test ${stem}' appears in ${CI}." >&2
    echo "  A wasm test no job names is compiled and never executed - which is how the only" >&2
    echo "  other one in this tree stayed broken and green." >&2
    fail=1
  fi
done < <(git grep -l --untracked -E '#\[(wasm_bindgen_test|cfg_attr\([^]]*wasm_bindgen_test[^]]*\))\]' -- '*/tests/*.rs' 2>/dev/null | sort -u)

if [ "$fail" -ne 0 ]; then
  echo "scripts/check-wasm-test-coverage.sh: a wasm test runs in no lane." >&2
  exit 1
fi
echo "scripts/check-wasm-test-coverage.sh: clean."
