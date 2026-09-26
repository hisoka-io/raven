#!/usr/bin/env bash
# Red-proof for check-wasm-test-coverage.sh.
#
# That gate exists because the tree's only #[wasm_bindgen_test] was compiled on every push,
# executed by nothing, and WRONG when finally run - then a second wasm file landed the same day
# and was invisible for the same reason. The cases below are that shape: a wasm test present in
# the tree that no CI job names, or that the census never counts.
set -uo pipefail
cd "$(dirname "$0")/.."

GATE=scripts/check-wasm-test-coverage.sh
FIXTURES=scripts/fixtures/check-wasm-test-coverage
CLIENT=$FIXTURES/client
CLIENT_WASM=$FIXTURES/client-wasm

fails=0
verdict() {  # verdict <want-exit> <got-exit> <label>
  if [ "$2" -eq "$1" ]; then
    echo "  ok: $3 -> exit $2"
  else
    echo "SELFTEST FAIL: $3: expected exit $1, got $2" >&2; fails=1
  fi
}
expect() {  # expect <want-exit> <workflow> <test-file> <label>
  bash "$GATE" "$2" "$3" > /dev/null 2>&1
  verdict "$1" "$?" "$4"
}

echo "check-wasm-test-coverage-selftest.sh: ways a wasm test goes unrun or uncounted, with controls"

bash "$GATE" > /dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "SELFTEST CANNOT RUN: the gate already fails on the unmutated tree." >&2; exit 1
fi
echo "  ok: the unmutated tree -> exit 0"

expect 1 "$FIXTURES/uncovered.yml" "$CLIENT/tests/exact_target.rs" \
  "a new #[wasm_bindgen_test] file named by no CI step"

expect 1 "$FIXTURES/uncovered.yml" "$CLIENT/tests/cfg_attr_target.rs" \
  "a new cfg_attr wasm_bindgen_test file named by no CI step"

expect 1 "$FIXTURES/prefix-only.yml" "$CLIENT/tests/exact_target.rs" \
  "a wasm target matching only another target's name prefix"

expect 1 "$FIXTURES/native-only.yml" "$CLIENT/tests/exact_target.rs" \
  "a wasm target named only by a native cargo test invocation"

expect 1 "$FIXTURES/other-target.yml" "$CLIENT/tests/exact_target.rs" \
  "an existing wasm target dropped from the CI step"

expect 0 "$FIXTURES/covered.yml" "$CLIENT/tests/exact_target.rs" \
  "an exact target in a wasm-pack test command"

expect 1 "$FIXTURES/covered.yml" "$CLIENT_WASM/tests/exact_target.rs" \
  "a wasm test whose name matches a covered test in another crate"

expect 0 "$FIXTURES/covered.yml" "$CLIENT/src/lib.rs" \
  "an in-src wasm test under its own crate's --lib"

expect 1 "$FIXTURES/covered.yml" "$CLIENT_WASM/src/lib.rs" \
  "an in-src wasm test in a crate no --lib command runs, beside one that does"

expect 1 "$FIXTURES/after-separator.yml" "$CLIENT/tests/exact_target.rs" \
  "a target named only after --, which selects no target"

expect 1 "$FIXTURES/other-package.yml" "$CLIENT/tests/exact_target.rs" \
  "a command -p points at another package"

expect 1 "$FIXTURES/module-stem.yml" "$CLIENT/tests/common/mod.rs" \
  "a module under tests/ that no single target owns"

expect 1 "$FIXTURES/option-after-test.yml" "$CLIENT/tests/exact_target.rs" \
  "a crate path after an option wasm-pack test does not know, so it goes to cargo"

expect 0 "$FIXTURES/continued.yml" "$CLIENT/tests/exact_target.rs" \
  "a command continued over lines with a backslash"

expect 1 "$FIXTURES/trailing-comment.yml" "$CLIENT/tests/exact_target.rs" \
  "a target named only in a trailing comment"

expect 0 "$FIXTURES/trailing-comment.yml" "$CLIENT/src/lib.rs" \
  "the command ahead of that comment"

expect 1 "$FIXTURES/continued-comment.yml" "$CLIENT/tests/exact_target.rs" \
  "a target named only in a comment the command is continued into"

expect 0 "$FIXTURES/after-comment-backslash.yml" "$CLIENT/tests/exact_target.rs" \
  "a command after a comment ending in a backslash, which continues nothing"

expect 1 "$FIXTURES/continued-from-comment.yml" "$CLIENT/tests/exact_target.rs" \
  "a target on the line after a trailing comment ending in a backslash"

expect 1 "$FIXTURES/next-command-semicolon.yml" "$CLIENT/tests/exact_target.rs" \
  "a target named only by another command after ;"

expect 0 "$FIXTURES/next-command-semicolon.yml" "$CLIENT/src/lib.rs" \
  "the command ahead of that ;"

expect 1 "$FIXTURES/next-command-and.yml" "$CLIENT/tests/exact_target.rs" \
  "a target named only by another command after &&"

expect 1 "$FIXTURES/next-command-pipe.yml" "$CLIENT/tests/exact_target.rs" \
  "a target named only by another command after |"

expect 1 "$FIXTURES/continued-past-operator.yml" "$CLIENT/tests/exact_target.rs" \
  "a wasm-pack line a backslash after ; joins to echo's arguments"

expect 0 "$FIXTURES/continued-past-operator.yml" "$CLIENT/src/lib.rs" \
  "the command on the line after those two"

expect 1 "$FIXTURES/redirect-stderr-package.yml" "$CLIENT/tests/exact_target.rs" \
  "a -p after 2>&1"

expect 1 "$FIXTURES/redirect-both-package.yml" "$CLIENT/tests/exact_target.rs" \
  "a --package after &>file"

expect 1 "$FIXTURES/redirect-stdout-manifest.yml" "$CLIENT/tests/exact_target.rs" \
  "a --manifest-path after >&2"

expect 1 "$FIXTURES/redirect-append-package.yml" "$CLIENT/tests/exact_target.rs" \
  "a -p after &>>file"

expect 1 "$FIXTURES/redirect-clobber-package.yml" "$CLIENT/tests/exact_target.rs" \
  "a -p after >|file"

expect 1 "$FIXTURES/redirect-glued-package.yml" "$CLIENT/tests/exact_target.rs" \
  "a -p written against a redirect, as -p>&2"

expect 1 "$FIXTURES/redirect-continued-manifest.yml" "$CLIENT/tests/exact_target.rs" \
  "a --manifest-path on the line a backslash after 2>&1 continues to"

expect 1 "$FIXTURES/redirect-target-file.yml" "$CLIENT/tests/exact_target.rs" \
  "a target that is only the file a redirect writes to"

expect 0 "$FIXTURES/redirect-no-selector.yml" "$CLIENT/tests/exact_target.rs" \
  "a target after a redirect with no selector"

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

# Written here because whitespace cleanup would strip the space from a tracked fixture.
printf '%s\n' 'jobs:' '  wasm:' '    steps:' '      - run: |' \
  "          wasm-pack test --node $CLIENT --lib \\ " '          --test exact_target' \
  > "$scratch/escaped-space.yml"
expect 1 "$scratch/escaped-space.yml" "$CLIENT/tests/exact_target.rs" \
  "a target on the line after a backslash and a space, which ends the command"

# The census half needs a checkout of its own: a submodule, and a git that can fail.
work="$scratch/checkout"
mkdir -p "$work/scripts" "$work/.github/workflows" "$scratch/bin"
cp -R "$FIXTURES/checkout/." "$work/"
cp "$GATE" "$work/scripts/"
git -C "$work" init -q
git -C "$work/vendor/sub" init -q
git -C "$work" update-index --add --cacheinfo \
  160000,1111111111111111111111111111111111111111,vendor/sub
cp "$FIXTURES/failing-git.sh" "$scratch/bin/git"
chmod +x "$scratch/bin/git"
REAL_GIT=$(command -v git)
export REAL_GIT

census() {  # census <want-exit> <workflow> <label> [stderr-must-contain...]
  local want="$1" workflow="$2" label="$3" err rc needle
  shift 3
  cp "$workflow" "$work/.github/workflows/ci.yml"
  err=$(bash "$work/$GATE" 2>&1 >/dev/null)
  rc=$?
  verdict "$want" "$rc" "$label"
  for needle in "$@"; do
    grep -Fq -- "$needle" <<< "$err" \
      || { echo "SELFTEST FAIL: ${label}: output lacks '${needle}'" >&2; fails=1; }
  done
}

census 0 "$FIXTURES/checkout-covered.yml" \
  "a checkout whose every wasm test is named"

census 1 "$FIXTURES/uncovered.yml" \
  "wasm tests in an attribute with arguments, a split attribute and a submodule" \
  "WASM TEST NOT RUN BY CI: lib/tests/args_form.rs" \
  "WASM TEST NOT RUN BY CI: lib/tests/split_attribute.rs" \
  "WASM TEST NOT RUN BY CI: vendor/sub/tests/in_submodule.rs"

FAIL_GREP_IN=$(cd "$work" && pwd -P) PATH="$scratch/bin:$PATH" census 2 \
  "$FIXTURES/checkout-covered.yml" "a git grep that fails at the top level" \
  "git grep exited 128 in ."

FAIL_GREP_IN=$(cd "$work/vendor/sub" && pwd -P) PATH="$scratch/bin:$PATH" census 2 \
  "$FIXTURES/checkout-covered.yml" "a git grep that fails inside a submodule" \
  "git grep exited 128 in vendor/sub"

mkdir "$work/vendor/unfetched"
git -C "$work" update-index --add --cacheinfo \
  160000,2222222222222222222222222222222222222222,vendor/unfetched
census 2 "$FIXTURES/checkout-covered.yml" "a submodule that was never checked out" \
  "submodule vendor/unfetched is not checked out"

if [ "$fails" -ne 0 ]; then
  echo "check-wasm-test-coverage-selftest.sh: the gate is not discriminating." >&2
  exit 1
fi
echo "check-wasm-test-coverage-selftest.sh: all cases behaved as required."
