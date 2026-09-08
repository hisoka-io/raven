#!/usr/bin/env bash
# Mutation testing must leave NOTHING behind in production source.
#
# A mutation is applied to src, the suite runs, the mutation is restored. If the run is killed
# between apply and restore - which has happened here - the corruption stays and every later
# measurement is taken over poisoned code. The restore belongs in an EXIT trap; this is the backstop.
#
# Pattern-matching for corruption idioms does not work: `*c ^= 1;` is legitimate production code in
# crates/binary-fuse-filter. So this asks a different question - which src files have uncommitted
# changes, and were they intended? Intended edits are listed in the allowlist. Anything else is
# residue until someone says otherwise.
set -uo pipefail
cd "$(dirname "$0")/.."
ALLOW=scripts/src-change-allowlist.txt
fail=0

changed=$( { git diff --name-only -- '*/src/*.rs' '*/src/**/*.rs';
             git -C crates/inspire diff --name-only -- 'src/*.rs' 'src/**/*.rs' 2>/dev/null \
               | sed 's|^|crates/inspire/|'; } | sort -u )

allowed=$( [ -f "$ALLOW" ] && /usr/bin/grep -v '^#' "$ALLOW" | /usr/bin/grep -v '^$' | sort -u || true )

unexpected=$(comm -23 <(printf '%s\n' "$changed" | /usr/bin/grep -v '^$' | sort -u) \
                      <(printf '%s\n' "$allowed"))
if [ -n "$unexpected" ]; then
  echo "UNEXPECTED PRODUCTION SOURCE CHANGE - mutation residue, or an unrecorded edit:" >&2
  printf '  %s\n' $unexpected >&2
  echo "" >&2
  echo "If a mutation run was interrupted, restore these from HEAD before trusting any measurement." >&2
  echo "If the change is intended, add the path to ${ALLOW} in the same commit." >&2
  fail=1
fi

# A failing proptest persists a regressions file that survives a byte-identical restore and then
# seeds every later run with the injected case.
#
# proptest writes these in TWO shapes and this check only saw one of them until 2026-09-07:
#   integration test under tests/  ->  tests/<name>.proptest-regressions   (suffix form)
#   in-src #[cfg(test)] proptest   ->  <crate>/proptest-regressions/<module>.txt   (DIRECTORY form)
# The glob '*.proptest-regressions' matches a file ENDING in that string, never a file INSIDE a
# directory named that, so every in-src proptest's seed was invisible to the gate whose entire
# job is catching them. A live one was sitting in adapters/railgun/http/ when this was found —
# written by a mutation run, surviving a byte-identical src restore, exactly the scenario the
# comment above describes. Both forms are checked now.
while IFS= read -r f; do
  [ -z "$f" ] && continue
  echo "NEW proptest regressions file: ${f}" >&2
  echo "  A failing proptest wrote this; it seeds later runs with the injected case." >&2
  fail=1
done < <(git ls-files --others --exclude-standard -- '*.proptest-regressions' 'proptest-regressions/*' '*/proptest-regressions/*')

[ "$fail" -ne 0 ] && { echo "scripts/check-no-mutation-residue.sh: residue found." >&2; exit 1; }
echo "scripts/check-no-mutation-residue.sh: clean."
