#!/usr/bin/env bash
# Red-proof for check-hygiene.sh: a gate ships with proof it can fail.
#
# The gate had two defects that a passing run could never reveal. Its scope was a literal list
# that had drifted away from the workspace members, so `mock-ppoi` was CI-gated and unscanned.
# And `if matches=$(grep ...)` treats an invalid pattern as "no matches", because grep exits 2
# and the `if` is false: a broken regex, a missing directory and a clean tree were the same
# observable.
#
# Runs against a scratch copy so the real tree is never mutated.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GATE_REL="adapters/railgun/scripts/check-hygiene.sh"
failed=0

check() { # expected actual name
  if [[ "$1" == "$2" ]]; then
    echo "  ok    $3 (exit $2)"
  else
    echo "  FAIL  $3: expected exit $1, got $2" >&2
    failed=1
  fi
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# Tracked files at their WORKING-TREE content, not `git archive HEAD`. The gate scans the
# working tree, so seeding from HEAD gave the selftest a different oracle than the thing it
# validates: an uncommitted leak read as "clean tree passes" while the real gate refused.
( cd "$ROOT" && git ls-files -z | tar --null -T - -cf - ) | tar -xf - -C "$work"
cp "$ROOT/$GATE_REL" "$work/$GATE_REL"

run_gate() { ( cd "$work" && ./"$GATE_REL" >/dev/null 2>&1; echo $?; ); }

echo "check-hygiene selftest:"
check 0 "$(run_gate)" "a clean tree passes"

# Each pattern class must fire. An internal label in a crate that WAS already scanned.
printf '\n// see no-commit/PLAN.md for the rationale\n' >> "$work/adapters/railgun/core/src/lib.rs"
check 1 "$(run_gate)" "a no-commit path leak is refused"
git -C "$work" checkout -- adapters/railgun/core/src/lib.rs 2>/dev/null \
  || cp "$ROOT/adapters/railgun/core/src/lib.rs" "$work/adapters/railgun/core/src/lib.rs"

# The drift itself: mock-ppoi is a workspace member and CI-gated, and was never scanned.
printf '\n// per B012 the caller retries\n' >> "$work/adapters/railgun/mock-ppoi/src/lib.rs"
check 1 "$(run_gate)" "a leak in mock-ppoi is refused (the dir the literal list omitted)"
cp "$ROOT/adapters/railgun/mock-ppoi/src/lib.rs" "$work/adapters/railgun/mock-ppoi/src/lib.rs"

# A hyphenated ledger ID. The unhyphenated rule never matched these, so this class of label
# shipped into the tree through a gate written to catch it.
printf '\n// the G-999 distinction: a transient error self-heals\n' >> "$work/adapters/railgun/core/src/lib.rs"
check 1 "$(run_gate)" "a hyphenated ledger label is refused"
git -C "$work" checkout -- adapters/railgun/core/src/lib.rs 2>/dev/null \
  || cp "$ROOT/adapters/railgun/core/src/lib.rs" "$work/adapters/railgun/core/src/lib.rs"

# A broken pattern must fail closed rather than read as clean.
sed -i "s|^PATTERNS=(|PATTERNS=(\n  'amendment(|" "$work/$GATE_REL"
check 2 "$(run_gate)" "an invalid pattern fails closed, not clean"
cp "$ROOT/$GATE_REL" "$work/$GATE_REL"

# An emptied scope must fail closed too: a gate that scans nothing passes everything.
sed -i 's|^mapfile -t SOURCE_DIRS.*|mapfile -t SOURCE_DIRS < <(true)|' "$work/$GATE_REL"
sed -i 's|^SOURCE_DIRS+=.*||' "$work/$GATE_REL"
check 2 "$(run_gate)" "an empty scan scope fails closed"
cp "$ROOT/$GATE_REL" "$work/$GATE_REL"

if [[ "$failed" -ne 0 ]]; then
  echo "check-hygiene-selftest.sh: FAILED - the gate does not catch what it claims." >&2
  exit 1
fi
echo "check-hygiene-selftest.sh: the gate fires on every class it claims."
