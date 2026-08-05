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
if git ls-files -- '*.md' ':!:crates/inspire/*' | xargs grep -nE '128-bit secur|128 bits of secur' 2>/dev/null; then
  fail "a tracked document claims 128-bit security; the measured floor at the shipped modulus is 121.5 bits"
fi

if [[ $failed -ne 0 ]]; then
  echo "scripts/check-repo-hygiene.sh: failed."
  exit 1
fi

echo "scripts/check-repo-hygiene.sh: clean."
exit 0
