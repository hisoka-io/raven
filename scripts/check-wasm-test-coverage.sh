#!/usr/bin/env bash
# Every file carrying a wasm_bindgen_test attribute must be named in ci.yml's wasm-pack step.
#
# `wasm-pack test --node <crate>` without `--test` was measured (2026-09-07) to stop after the
# first target reporting "no tests to run!", so the CI step names each target explicitly. That
# list is exactly the kind of hand-maintained enumeration this repo has been bitten by: the tree's
# only wasm test went years compiled-but-never-executed, and when finally run it FAILED. A second
# wasm test file landed the same day and was invisible to CI for the same reason.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"
CI="${1:-.github/workflows/ci.yml}"
fail=0

if [ "$#" -gt 0 ]; then
  shift
  if [ "$#" -eq 0 ]; then
    echo "usage: $0 [WORKFLOW TEST_FILE...]" >&2
    exit 2
  fi
  test_files=$(printf '%s\n' "$@")
else
  # --untracked: a brand-new wasm test file is the case this exists to catch, and it is not in the
  # index yet. git grep answers from the working tree; a plain `git ls-files` would not see it.
  #
  # Every .rs, and the submodule too: restricting the census to */tests/*.rs made an in-src
  # #[cfg(test)] or a benches/ wasm test invisible to the gate bought to make that impossible.
  # scripts/fixtures/ holds this gate's own red-proof inputs, which no real job names.
  attribute='#\[(wasm_bindgen_test|cfg_attr\([^]]*wasm_bindgen_test[^]]*\))\]'
  test_files=$(
    { git grep -l --untracked -E "$attribute" -- '*.rs' ':(exclude)scripts/fixtures/*'
      git -C crates/inspire grep -l --untracked -E "$attribute" -- '*.rs' \
        | sed 's|^|crates/inspire/|'
    } 2>/dev/null | sort -u)
fi

if [ ! -f "$CI" ]; then
  echo "WASM TEST COVERAGE CONFIGURATION ERROR: workflow does not exist: ${CI}" >&2
  exit 2
fi

while IFS= read -r f; do
  [ -z "$f" ] && continue
  if [ ! -f "$f" ]; then
    echo "WASM TEST COVERAGE CONFIGURATION ERROR: test file does not exist: ${f}" >&2
    fail=1
    continue
  fi
  stem=$(basename "$f" .rs)
  # wasm-pack forwards these to cargo test, so demanding `--test <stem>` for an in-src or
  # benches wasm test would demand an invocation that cannot run it
  case "$f" in
    */src/*) flag="--lib"; target="" ;;
    */benches/*) flag="--bench"; target="$stem" ;;
    *) flag="--test"; target="$stem" ;;
  esac
  want="${flag}${target:+ $target}"
  if ! awk -v flag="$flag" -v target="$target" '
    $1 == "wasm-pack" && $2 == "test" {
      for (field = 3; field <= NF; field++) {
        if (target == "") {
          if ($field == flag) found = 1
        } else if (($field == flag && $(field + 1) == target) || $field == flag "=" target) {
          found = 1
        }
      }
    }
    END { exit !found }
  ' "$CI"; then
    echo "WASM TEST NOT RUN BY CI: ${f}" >&2
    echo "  It carries a wasm_bindgen_test attribute but no wasm-pack test command invokes the exact '${want}' target in ${CI}." >&2
    echo "  A wasm test no job names is compiled and never executed - which is how the only" >&2
    echo "  other one in this tree stayed broken and green." >&2
    fail=1
  fi
done <<< "$test_files"

if [ "$fail" -ne 0 ]; then
  echo "scripts/check-wasm-test-coverage.sh: a wasm test runs in no lane." >&2
  exit 1
fi
echo "scripts/check-wasm-test-coverage.sh: clean."
