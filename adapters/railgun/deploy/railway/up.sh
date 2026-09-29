#!/usr/bin/env bash
# Deploys this checkout to a Railway service configured by configure.sh. It stages the files git
# tracks under the Dockerfile's COPY paths, as they are in the working tree, and uploads them with
# `railway up`. An untracked file there stops it: nothing git does not know leaves the machine,
# and nothing the build needs is silently left out. Every argument goes to `railway up`:
#   up.sh --service raven-mainnet --project <project id> --environment production --detach
#   up.sh --stage-only DIR     write the staged context to DIR (empty or new) and stop
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(git -C "$here" rev-parse --show-toplevel)
die() { echo "error: $*" >&2; exit 1; }

paths=(rust-toolchain.toml Cargo.toml Cargo.lock README.md crates benches adapters/railgun)

stage_to() {  # dir
  local dir=$1 untracked
  # Submodules too: a gitlink would otherwise pull in its whole directory, ignored files included.
  untracked=$(git -C "$repo" ls-files --others --exclude-standard -- "${paths[@]}"
    git -C "$repo" submodule foreach --quiet --recursive \
      'git ls-files --others --exclude-standard | sed "s|^|$displaypath/|"')
  [[ -z $untracked ]] || die "untracked files under the build paths; commit or remove them:
$untracked"
  mkdir -p "$dir"
  [[ -z $(ls -A "$dir") ]] || die "$dir is not empty"
  git -C "$repo" ls-files -z --cached --recurse-submodules -- "${paths[@]}" \
    | tar -C "$repo" --null -T - -cf - | tar -C "$dir" -xf -
}

if [[ ${1:-} == --stage-only ]]; then
  [[ -n ${2:-} ]] || die "--stage-only needs a directory"
  stage_to "$2"
  exit 0
fi

command -v railway >/dev/null || die "the railway CLI is not installed"
stage=$(mktemp -d "${TMPDIR:-/tmp}/raven-railway.XXXXXX")
trap 'rm -rf "$stage"' EXIT
stage_to "$stage"
rev=$(git -C "$repo" rev-parse --short HEAD)
[[ -z $(git -C "$repo" status --porcelain -- adapters/railgun crates) ]] || rev="$rev+local"
railway up "$stage" --path-as-root --no-gitignore --message "raven-railgun $rev" "$@"
