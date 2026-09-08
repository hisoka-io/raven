#!/usr/bin/env bash
# Every binary()/test() name in a CI nextest filter must resolve to something in the tree.
#
# nextest 0.9.129 fails loudly when a `binary(X)` names a target that does not exist, but a
# `test(Y)` naming a test that does not exist exits 0 and QUIETLY reduces the run. ci.yml carries
# an additive `test(insert_rejects_overflow_past_capacity)` in the engine-ignored lane: rename that
# unit test and the lane keeps passing while no longer running it.
#
# Measured 2026-09-01, which is why this exists as a gate rather than a comment.
#
# The name classes below are [A-Za-z_0-9], not [a-z_0-9]: the first draft used the narrow class
# and its own red-proof passed, because the mutation renamed a term to something containing an
# uppercase letter and the extraction silently skipped it. A gate that cannot see part of its
# own input is worse than no gate.
set -uo pipefail
cd "$(dirname "$0")/.."
CI=.github/workflows/ci.yml
fail=0

# `test(...)` names: must appear as a `fn <name>` somewhere in a .rs file ON DISK.
# --untracked, because a lane's brand-new test file is not in the index yet and a gate that
# cannot see it fails on correct work.
while IFS= read -r name; do
  [ -z "$name" ] && continue
  if ! git grep --untracked -qE "fn +${name}\b" -- '*.rs' 2>/dev/null; then
    echo "CI FILTER LEAK: test(${name}) in ${CI} matches no 'fn ${name}' in the tree." >&2
    echo "  A test() term naming a nonexistent test exits 0 and silently shrinks the lane." >&2
    fail=1
  fi
done < <(/usr/bin/grep -oE 'test\([A-Za-z_0-9]+\)' "$CI" | sed -E 's/test\((.*)\)/\1/' | sort -u)

# `binary(...)` names: must match a tests/ or benches/ file that EXISTS ON DISK.
#
# The existence test is `-f`, not `git ls-files | grep -q .`, and that distinction is the whole
# point: `git ls-files` reports the INDEX, so a test file deleted in the working tree and not yet
# committed still resolves. A lane deleted pir_cell_width_law.rs, this gate stayed green, and the
# nightly production-cell lane would have died at exit 94 on a binary() naming nothing. A gate
# that answers from the index while nextest answers from the disk is not checking the same tree.
# Untracked candidates count, so a lane's new test file resolves before it is committed.
while IFS= read -r name; do
  [ -z "$name" ] && continue
  found=0
  while IFS= read -r cand; do
    [ -n "$cand" ] && [ -f "$cand" ] && { found=1; break; }
  done < <(git ls-files "*/tests/${name}.rs" "*/benches/${name}.rs" "*/src/bin/${name}.rs"; \
           git ls-files --others --exclude-standard \
             "*/tests/${name}.rs" "*/benches/${name}.rs" "*/src/bin/${name}.rs")
  if [ "$found" -eq 0 ]; then
    echo "CI FILTER LEAK: binary(${name}) in ${CI} matches no test/bench target on disk." >&2
    echo "  nextest fails the whole lane (exit 94) on a binary() that names nothing." >&2
    fail=1
  fi
done < <(/usr/bin/grep -oE 'binary\([A-Za-z_0-9]+\)' "$CI" | sed -E 's/binary\((.*)\)/\1/' | sort -u)

# Every workspace member must appear in the fmt list and in a test shard - both are enumerated
# by hand with -p, and a new member is silently uncovered. That already happened once.
members=$(python3 - <<'PY'
import re, pathlib
m = re.search(r'members = \[(.*?)\]', pathlib.Path('adapters/railgun/Cargo.toml').read_text(), re.S)
print('\n'.join('raven-railgun-' + x.strip().strip('"') for x in m.group(1).split(',') if x.strip()))
PY
)
for pkg in $members; do
  if ! /usr/bin/grep -q -- "-p ${pkg}" "$CI"; then
    echo "CI COVERAGE LEAK: workspace member ${pkg} is named by no -p flag in ${CI}." >&2
    echo "  The fmt step and the test shards both enumerate packages by hand." >&2
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "scripts/check-ci-filter-names.sh: at least one CI filter or package name does not resolve." >&2
  exit 1
fi
echo "scripts/check-ci-filter-names.sh: clean."
