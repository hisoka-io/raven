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
# Derived from the workspace members, never hand-maintained. The previous literal list had
# drifted: `mock-ppoi` is a member and is CI-gated (ci.yml:198) yet was never scanned. A gate
# whose scope is a copy of another file's list stops covering the thing it names.
mapfile -t SOURCE_DIRS < <(
  sed -n '/^members = \[/,/\]/p' "${ROOT}/Cargo.toml" \
    | grep -oE '"[^"]+"' | tr -d '"' | sed "s|^|${ROOT}/|"
)
# `client-wasm` declares its own workspace, so it is not a member and must be added by name.
SOURCE_DIRS+=("${ROOT}/client-wasm")
# Non-Cargo source roots. Deriving the scope from workspace members alone left the ENTIRE
# TypeScript SDK, the adapter's own scripts and the CI workflow unscanned -- and that is
# where the labels actually leaked. A gate whose scope is derived from one language cannot
# see a repo written in three.
SOURCE_DIRS+=("${ROOT}/sdk/src" "${ROOT}/sdk/tests" "${ROOT}/scripts")
REPO_ROOT="$(cd "${ROOT}/../.." && pwd)"
if [[ -d "${REPO_ROOT}/.github/workflows" ]]; then
  SOURCE_DIRS+=("${REPO_ROOT}/.github/workflows")
fi

if [[ ${#SOURCE_DIRS[@]} -lt 2 ]]; then
  echo "check-hygiene.sh: derived only ${#SOURCE_DIRS[@]} source dir(s) from the workspace members." >&2
  echo "  An empty or near-empty scope is a broken gate, not a clean tree." >&2
  exit 2
fi

# A Rust-only scan could not see the leak it exists to catch: the labels landed in
# `.ts`, `.yml` and `.sh` as well. Build artefacts and vendored wasm glue are excluded by
# scanning only source extensions rather than by path.
SCAN_INCLUDES=(
  --include='*.rs' --include='*.ts' --include='*.mjs'
  --include='*.sh' --include='*.yml' --include='*.yaml' --include='*.toml'
  --exclude-dir=node_modules --exclude-dir=target
  --exclude-dir=pkg-node --exclude-dir=pkg-bundler
  # The gate and its selftest necessarily CONTAIN every label they hunt for -- the
  # patterns are literals in one and planted fixtures in the other.
  --exclude=check-hygiene.sh --exclude=check-hygiene-selftest.sh
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
  # Hyphenated builder-ledger IDs. The unhyphenated `M0NN` rule above never matched these,
  # so every `O-NNN` / `B-NNN` / `G-NNN` label passed a scan that exists to catch exactly them.
  '\b[BDGLMO]-[0-9]{3}[a-z]?\b'
  # Batch-corpus IDs. The class above covers the builder ledger's own letters and missed
  # every label a BATCH uses, so a run could cite `OQ-021` or `A-002` in public source and
  # pass a gate that exists to stop exactly that. `no-commit/` is gitignored, so these
  # point an external reader at documents that do not exist.
  '\bOQ-[0-9]{3}\b'
  '\bA-[0-9]{3}\b'
  '\bF-[0-9]{3}\b'
  '\bW[0-9]{1,2}-[0-9]{2}[a-z]?\b'
  # Bare record filenames. Seven files named FINDINGS.md exist in the corpus, so the
  # citation is ambiguous even to someone holding the private tree.
  '[^"](FINDINGS|AUDIT|DOUBTS|EVIDENCE|TASKLIST|DECISIONS|MISTAKES|OPEN-QUESTIONS)\.md\b'
  'no-commit/'
)

# Case-insensitive pattern for "Phase 5" (project-phase label).
CI_PATTERNS=(
  '\bphase 5\b'
)

found_any=0

# `if matches=$(grep ...)` treats an INVALID PATTERN as "no matches": grep exits 2, the `if` is
# false, and a broken regex is indistinguishable from a clean tree. Branch on the status
# instead - 0 is a hit, 1 is clean, anything else is a broken gate.
scan_dir() { # dir pattern extra-flags
  local dir="$1" pat="$2" extra="$3" out rc
  if [[ -n "$extra" ]]; then
    out="$(grep -rEn "$extra" "$pat" "$dir" "${SCAN_INCLUDES[@]}")"
  else
    out="$(grep -rEn "$pat" "$dir" "${SCAN_INCLUDES[@]}")"
  fi
  rc=$?
  case "$rc" in
    0)
      echo "HYGIENE LEAK matching '$pat':"
      echo "$out"
      echo
      return 1
      ;;
    1) return 0 ;;
    *)
      echo "check-hygiene.sh: grep exited $rc on pattern '$pat' in $dir." >&2
      echo "  A broken gate is not a clean tree." >&2
      exit 2
      ;;
  esac
}

for dir in "${SOURCE_DIRS[@]}"; do
  if [[ ! -d "$dir" ]]; then
    continue
  fi
  for pat in "${PATTERNS[@]}"; do
    scan_dir "$dir" "$pat" "" || found_any=1
  done
  for pat in "${CI_PATTERNS[@]}"; do
    scan_dir "$dir" "$pat" "-i" || found_any=1
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
