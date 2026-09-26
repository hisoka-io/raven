#!/usr/bin/env bash
# Every .rs file mentioning wasm_bindgen_test must be named by a `wasm-pack test` command in
# ci.yml: its own crate, and its exact target among the words that command hands to cargo.
#
# Named is not executed. The gate still passes a command that `if:`, `if false; then`, an uncalled
# function or an earlier `exit 0` never reaches; one under `continue-on-error`, `|| true` or a
# trailing `&`; one whose `-- <filter>` selects no test; and one with a non-wasm `--target` or
# `--no-run`. It parses no YAML or quoting: a wasm-pack line in a heredoc, quoted string, folded or
# plain multi-line scalar or `env:` value passes; a quoted `#` ends the scan and hides a
# continuation; a quoted "-p" is not seen; and a word ending in `\` is not joined to the next line.
# Nor does it expand the shell: process substitution, combined short flags such as `-qp`, and
# `$VAR` or `$(...)` that inject a selector or a bare filter word are not seen.
#
# The census reads text. An alias defined in the same file spells wasm_bindgen_test and is counted;
# a file whose attribute arrives through an alias or macro defined in another file is not.
#
# `wasm-pack test --node <crate>` without `--test` was measured (2026-09-07) to stop after the
# first target reporting "no tests to run!", so the CI step names each target explicitly. That
# list is exactly the kind of hand-maintained enumeration this repo has been bitten by: the tree's
# only wasm test went years compiled-but-never-executed, and when finally run it FAILED. A second
# wasm test file landed the same day and was invisible to CI for the same reason.
#
# The crate is part of the match: on the target name alone, a test in one crate passed on the
# strength of a same-named test in another, and any crate's --lib covered every crate's.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"
CI="${1:-.github/workflows/ci.yml}"
fail=0

refuse() {
  echo "WASM TEST COVERAGE CONFIGURATION ERROR: $*" >&2
  exit 2
}

# The substring, not the attribute: `#[wasm_bindgen_test(unsupported = test)]` and a cfg_attr
# rustfmt splits over several lines both slipped past an attribute regex.
census() {
  local dir="$1" hits hit rc links link top here
  local -a pathspec=('*.rs')
  # scripts/fixtures/ holds this gate's own red-proof inputs, which no real job names.
  [ -n "$dir" ] || pathspec+=(':(exclude)scripts/fixtures/*')
  # --untracked: a brand-new wasm test file is the case this exists to catch, and it is not in
  # the index yet.
  hits=$(git -C "${dir:-.}" grep -l --untracked -F -e wasm_bindgen_test -- "${pathspec[@]}")
  rc=$?
  # 0 is a match and 1 is none; anything else is git failing, which must not read as zero files
  [ "$rc" -le 1 ] || refuse "git grep exited ${rc} in ${dir:-.}"
  if [ -n "$hits" ]; then
    while IFS= read -r hit; do printf '%s%s\n' "${dir:+$dir/}" "$hit"; done <<< "$hits"
  fi
  # A top-level grep never enters a submodule, so each one is searched in its own right.
  links=$(git -C "${dir:-.}" ls-files --stage | awk '$1 == "160000" { sub(/^[^\t]*\t/, ""); print }') \
    || refuse "git ls-files failed in ${dir:-.}"
  while IFS= read -r link; do
    [ -n "$link" ] || continue
    link="${dir:+$dir/}$link"
    # An uninitialised submodule is an empty directory inside the parent repo: grepping it
    # succeeds and finds nothing.
    top=$(git -C "$link" rev-parse --show-toplevel) && here=$(cd "$link" && pwd -P) \
      && [ "$top" = "$here" ] \
      || refuse "submodule ${link} is not checked out, so its wasm tests cannot be counted"
    census "$link"
  done <<< "$links"
}

if [ "$#" -gt 0 ]; then
  shift
  if [ "$#" -eq 0 ]; then
    echo "usage: $0 [WORKFLOW TEST_FILE...]" >&2
    exit 2
  fi
  test_files=$(printf '%s\n' "$@")
else
  test_files=$(census "") || exit 2
fi

if [ ! -f "$CI" ]; then
  refuse "workflow does not exist: ${CI}"
fi

# Exits 0 when some `wasm-pack test` in the workflow names FLAG [TARGET] in CRATE. The crate is
# wasm-pack's first argument after its own test options, and "." when that argument is absent:
# anything it does not recognise, `-v` included, starts cargo's arguments. Nothing after `--`
# selects a target, and -p or --manifest-path points cargo at another package. A redirect such as
# 2>&1, &> log or >| log is dropped with its target and the words go on; they stop at a comment and
# at `;`, `&`, `&&`, `|` or `||`. A backslash continues a line only as its last character and never
# inside a comment. Lines it joins past an operator are skipped, since they may be echo's arguments.
covers='
function keep(w) {
  if (w == "") return
  if (target_next) { target_next = 0; return }
  word[++n] = w
}
function lex(s,    pre, op) {
  while (s != "" && !cut) {
    if (!match(s, /[;&|<>]/)) { keep(s); return }
    pre = substr(s, 1, RSTART - 1)
    s = substr(s, RSTART)
    if (!match(s, /^(&>>?|[<>]&|>[|]|<<[<-]?|<>|>>|[<>])/)) { keep(pre); cut = 1; return }
    op = substr(s, 1, RLENGTH)
    s = substr(s, RLENGTH + 1)
    if (pre !~ /^[0-9]*$/ || op ~ /^&/) keep(pre)
    match(s, /^[^;&|<>]*/)
    if (RLENGTH == 0) target_next = 1
    s = substr(s, RLENGTH + 1)
  }
}
{
  n = 0
  cut = 0
  target_next = 0
  for (;;) {
    continued = sub(/\\$/, "")
    for (i = 1; i <= NF && $i !~ /^#/; i++) lex($i)
    if (i > NF && continued && (getline) > 0) continue
    break
  }
  if (n < 2 || word[1] != "wasm-pack" || word[2] != "test") next
  i = 3
  while (i <= n) {
    if (word[i] ~ /^(--node|--firefox|--chrome|--safari|--headless|--release|-r|--panic-unwind)$/) i++
    else if (word[i] ~ /^(--geckodriver|--chromedriver|--safaridriver|--mode|-m)$/) i += 2
    else if (word[i] ~ /^--(geckodriver|chromedriver|safaridriver|mode)=/) i++
    else break
  }
  path = "."
  if (i <= n && word[i] !~ /^-/) { path = word[i]; i++ }
  while (path ~ /^\.\//) path = substr(path, 3)
  while (path ~ /.\/$/) path = substr(path, 1, length(path) - 1)
  if (path == "") path = "."
  if (path != crate) next
  hit = 0
  redirected = 0
  for (; i <= n && word[i] != "--"; i++) {
    a = word[i]
    if (a ~ /^(-p|--package|--workspace|--all|--manifest-path)$/ || a ~ /^(-p.|--package=|--manifest-path=)/) redirected = 1
    if (target == "") {
      if (a == flag) hit = 1
    } else if ((a == flag && i < n && word[i + 1] == target) || a == flag "=" target) {
      hit = 1
    }
  }
  if (hit && !redirected) found = 1
}
END { exit !found }
'

while IFS= read -r f; do
  [ -z "$f" ] && continue
  [ -f "$f" ] || refuse "test file does not exist: ${f}"
  case "$f" in "$REPO_ROOT"/*) f="${f#"$REPO_ROOT"/}" ;; esac
  f="${f#./}"
  crate=$(dirname "$f")
  until [ -f "$crate/Cargo.toml" ]; do
    { [ "$crate" != . ] && [ "$crate" != / ]; } || refuse "no Cargo.toml above ${f}"
    crate=$(dirname "$crate")
  done
  if [ "$crate" = . ]; then rel="$f"; else rel="${f#"$crate"/}"; fi
  # wasm-pack forwards these to cargo test. Only the layouts cargo discovers by itself map to
  # one target; a module under tests/ can be compiled into any number of them, or none.
  flag=""
  target=""
  case "$rel" in
    src/main.rs | src/bin/*) ;;
    src/*) flag="--lib" ;;
    tests/* | benches/*)
      rest="${rel#*/}"
      case "$rest" in
        */*/*) ;;
        */main.rs) target="${rest%/main.rs}" ;;
        */*) ;;
        *.rs) target="${rest%.rs}" ;;
      esac
      if [ -n "$target" ]; then
        case "$rel" in tests/*) flag="--test" ;; *) flag="--bench" ;; esac
      fi
      ;;
  esac
  if [ -z "$flag" ]; then
    echo "WASM TEST IN NO NAMEABLE TARGET: ${f}" >&2
    echo "  Crate ${crate} compiles it into no target this gate can tie to one wasm-pack command." >&2
    echo "  Put it in src/, tests/<name>.rs, tests/<name>/main.rs, benches/<name>.rs or" >&2
    echo "  benches/<name>/main.rs." >&2
    fail=1
    continue
  fi
  want="${flag}${target:+ $target}"
  if ! awk -v crate="$crate" -v flag="$flag" -v target="$target" "$covers" "$CI"; then
    echo "WASM TEST NOT RUN BY CI: ${f}" >&2
    echo "  It mentions wasm_bindgen_test but no wasm-pack test command in ${CI} runs '${want}' in its crate, ${crate}." >&2
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
