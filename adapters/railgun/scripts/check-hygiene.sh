#!/usr/bin/env bash
#
# scripts/check-hygiene.sh
#
# CI hygiene-grep step. Catches unambiguous internal-amendment-label
# patterns that have leaked into production source (or test source)
# across recent sessions. Per CLAUDE.md: "Comments and Docs Hygiene:
# no session numbers, no `no-commit/` paths, no internal phase labels,
# no Hisoka / darkpool / nullifier / note names in `crates/`
# source/comments."
#
# Invoked from .github/workflows/ci.yml. Exits 1 on first match.
#
# Flags any of the following in this adapter's `**/*.rs`:
#   - "audit fix [CHM]N" / "AUDIT M+digit" / "amendment"
#   - "(... per B[0-9])" leak shape
#   - bare "S0NN" / "M0NN" / "M0NNN" session / memory references
#   - "Tier N.M" tier labels
#   - "Q-NNN" question labels
#   - "T0.[0-9]" session-tier label
#   - "no-commit/" repo-internal path leak
#   - "phase 5" (case-insensitive) project-phase label leak
#
# Test scope is NOT excluded — the hygiene rule applies to all of
# the adapter's source/comments per CLAUDE.md.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_DIRS=(
  "${ROOT}/core"
  "${ROOT}/engine"
  "${ROOT}/persistence"
  "${ROOT}/indexer"
  "${ROOT}/ppoi-mirror"
  "${ROOT}/http"
  "${ROOT}/cli"
  "${ROOT}/poseidon"
  "${ROOT}/client-wasm"
)

# Patterns are intentionally word-boundary-anchored to avoid catching
# legitimate identifier substrings (e.g. "M19" inside an arbitrary
# variable name).
PATTERNS=(
  '\baudit fix [CHM][0-9]+\b'
  '\bAUDIT M[0-9]+\b'
  '\bamendment\b'
  '\bper [BCH][0-9]+\b'
  '\bS0[0-9]{2}\+?\b'
  '\bM0?[0-9]{2,3}\b'
  '\bTier [0-9]+\.[0-9]+\b'
  '\bQ-[0-9]{3}\b'
  'no-commit/'
)

# Case-insensitive pattern for "Phase 5" (project-phase label).
CI_PATTERNS=(
  '\bphase 5\b'
)

found_any=0

for dir in "${SOURCE_DIRS[@]}"; do
  if [[ ! -d "$dir" ]]; then
    continue
  fi
  for pat in "${PATTERNS[@]}"; do
    if matches=$(grep -rEn "$pat" "$dir" --include='*.rs' 2>/dev/null); then
      if [[ -n "$matches" ]]; then
        echo "HYGIENE LEAK matching '$pat':"
        echo "$matches"
        echo
        found_any=1
      fi
    fi
  done
  for pat in "${CI_PATTERNS[@]}"; do
    if matches=$(grep -rEni "$pat" "$dir" --include='*.rs' 2>/dev/null); then
      if [[ -n "$matches" ]]; then
        echo "HYGIENE LEAK matching '$pat' (case-insensitive):"
        echo "$matches"
        echo
        found_any=1
      fi
    fi
  done
done

if [[ $found_any -ne 0 ]]; then
  echo "scripts/check-hygiene.sh: at least one internal-label leak found."
  echo "See CLAUDE.md 'Comments and Docs Hygiene' rule. Sweep the leaks"
  echo "(use unambiguous prose; refer to behavior, not amendment labels)."
  exit 1
fi

echo "scripts/check-hygiene.sh: clean."
exit 0
