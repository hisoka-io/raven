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

# The allowlist answers "is this file expected to differ from HEAD?". That is a DIFFERENT question
# from "does this file carry a planted mutation?", and conflating them left a permanent hole: once a
# path is allowlisted it is exempt forever, and the paths that end up allowlisted are exactly the
# ones active work keeps touching. Measured instance: every shim-wiring red proof must mutate
# `cli/src/serve_production_multi.rs`, and that file has been on the allowlist for weeks, so an
# interrupted run there was invisible to the gate whose whole job is catching it.
#
# So: scan for the short-circuit idioms a red proof actually uses, over EVERY file, allowlisted or
# not -- and into the crypto submodule, where red proofs are applied too. This is not the
# pattern-matching the header rejects -- `*c ^= 1;` is real code and is not matched here.
# `false &&`, `true ||` and `if false` are not idioms anyone writes on purpose; they are what you
# type to disable a branch for ninety seconds.
#
# The first version of this scan ran `git grep` without `--recurse-submodules`, so it never read
# crates/inspire, and piped it through `2>/dev/null || true`, so a scan that could not run reported
# clean. git grep exits 0 on a match, 1 on none, and >1 on an error; only the first two are verdicts.
idiom_hits=$(git grep --recurse-submodules -n -E \
  '(^|[^&|])(false[[:space:]]*&&|true[[:space:]]*\|\|)|if[[:space:]]+false[[:space:]]*\{' \
  -- '*/src/*.rs' '*/src/**/*.rs' 2>&1)
idiom_rc=$?
case "$idiom_rc" in
  0)
    while IFS= read -r hit; do
      [ -z "$hit" ] && continue
      echo "MUTATION IDIOM in production source: ${hit}" >&2
      echo "  A red proof disables a branch this way. Restore it before trusting any measurement." >&2
    done <<< "$idiom_hits"
    fail=1 ;;
  1) ;;
  *)
    echo "MUTATION IDIOM SCAN COULD NOT RUN (git grep exit ${idiom_rc}); refusing to report clean:" >&2
    printf '  %s\n' "$idiom_hits" >&2
    fail=1 ;;
esac

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
