#!/usr/bin/env bash
#
# Repo-level hygiene gate for things a Rust lint cannot see. Complements
# adapters/railgun/scripts/check-hygiene.sh, which greps adapter source.
#
# 1. .gitmodules must use https. An `ssh://` or `git@` URL makes
#    `git submodule update --init` fail for any anonymous clone, and the root
#    workspace does not resolve without crates/inspire.
# 2. Public policy files must carry no unresolved owner-action marker.
# 3. No document outside the vendored submodule may claim 128-bit security for
#    the shipped InsPIRe parameters: the lattice-estimator measurement at the
#    shipped modulus is 121.5 bits.
# 4. No tracked file may carry an internal ledger label. The adapter gate greps
#    `*.rs` under the adapter workspace, which is 2 of the 10 places labels have
#    actually leaked from; the other eight were .yml, .md and .sh, most of them
#    outside the adapter. `no-commit/` needs no exclusion here - it is untracked,
#    so `git ls-files` cannot reach it.
# 5. No runtime data directory may sit untracked-and-unignored inside a source
#    tree. A test that derives its data_dir relative to the crate instead of a
#    temp dir leaves a full node state behind - manifest, snapshots, WAL, packing
#    keys. One measured instance reached 155 MB under adapters/railgun/cli/,
#    named after the list key, and `git check-ignore` did not cover it: a single
#    `git add -A` would have put it in this PUBLIC repo's history permanently,
#    where it cannot be removed without a rewrite. The test is the bug; this is
#    the net under it.

# Every scan below captures its output and tests the TEXT, and the `|| true` is load-bearing.
# Two measured reasons, and the first is the general one:
#   1. `xargs` returns 123 when ANY grep invocation exits 1, and a plain no-match IS exit 1.
#      So the pipeline's status is not a usable signal here even with no directory involved.
#   2. `git ls-files` additionally emits the submodule gitlink `crates/inspire` as a path with
#      no file behind it; a `:!:crates/inspire/*` pathspec cannot exclude a path with no
#      trailing component, and grep handed that directory returns non-zero even when other
#      files matched - so a status test could never fire in either direction.
# A `*.md`-filtered scan never lists the gitlink, which is why the security-claim check
# survived on status alone and a whole-tree scan silently did not.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

failed=0

fail() {
  echo "REPO HYGIENE: $1"
  failed=1
}

if [[ -f .gitmodules ]]; then
  while read -r url; do
    case "$url" in
      https://*) ;;
      "") ;;
      *) fail ".gitmodules submodule url is not https, so an anonymous clone cannot init it: $url" ;;
    esac
  done < <(git config --file .gitmodules --get-regexp '^submodule\..*\.url$' | awk '{print $2}')
fi

for doc in SECURITY.md README.md CONTRIBUTING.md; do
  [[ -f "$doc" ]] || continue
  if grep -nE 'ACTION-REQUIRED|<FILL IN>|TKTK' "$doc"; then
    fail "$doc carries an unresolved owner-action marker"
  fi
done

# crates/inspire is a vendored submodule with its own history; its docs are
# corrected through a submodule change, not here.
sec_hits="$(git ls-files -- '*.md' ':!:crates/inspire' ':!:crates/inspire/*' \
  | xargs grep -nE '128-bit secur|128 bits of secur' 2>/dev/null || true)"
if [[ -n "$sec_hits" ]]; then
  echo "$sec_hits"
  fail "a tracked document claims 128-bit security; the measured floor at the shipped modulus is 121.5 bits"
fi

# Selftests are excluded because planting a label is what they are for: the adapter red-proof
# writes one into a throwaway worktree and has to keep being able to.
LABEL_RE='\b[BDGLMOS]-[0-9]{3}[a-z]?\b'
label_hits="$(git ls-files -- ':!:crates/inspire' ':!:crates/inspire/*' ':!:*selftest*' \
  | xargs grep -nE "$LABEL_RE" 2>/dev/null || true)"
if [[ -n "$label_hits" ]]; then
  echo "$label_hits"
  fail "a tracked file carries an internal ledger label; those are records, not shipped prose"
fi

# 5. Stray runtime data directories. Fingerprinted on CONTENT, not on name: a data dir
# carries a manifest beside a `wal/` or `snapshots/` directory, and nothing legitimate in a
# source tree looks like that. Matching on the name would have caught only the one instance,
# which happened to be 64 hex chars because it was a list key.
while IFS= read -r manifest; do
  [[ -n "$manifest" ]] || continue
  dir="$(dirname "$manifest")"
  # Only a data dir has the sibling state beside the manifest; a package manifest does not.
  if [[ -d "$dir/wal" || -d "$dir/snapshots" ]]; then
    size="$(du -sh "$dir" 2>/dev/null | cut -f1)"
    fail "runtime data directory left in a source tree: ${dir} (${size:-unknown}). \
A test derived its data_dir relative to the crate instead of a temp dir. It is neither \
tracked nor ignored, so \`git add -A\` would commit it to this public repo forever. \
Point the test at a temp dir and delete this."
  fi
done < <(git ls-files --others --exclude-standard -- 'adapters/**/manifest.json' 'crates/**/manifest.json' 'examples/**/manifest.json' 2>/dev/null || true)

if [[ $failed -ne 0 ]]; then
  echo "scripts/check-repo-hygiene.sh: failed."
  exit 1
fi


echo "scripts/check-repo-hygiene.sh: clean."
exit 0
