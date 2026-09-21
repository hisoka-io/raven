#!/usr/bin/env bash
# Red-proof for check-sdk-pack.sh. A packaging gate that cannot fail is the same shape of
# nothing as the green suite it was added to cover, so this reintroduces the two defects
# the gate exists for, in a COPY, and requires the gate to name each one.
#
#   mutation A: main/types back to ./src/index.ts with no exports map - the consumer
#               resolves TypeScript at runtime, which is the state this repo shipped.
#   mutation B: the files allowlist removed - the whole test tier ships to consumers.
#
# The real tree is never written to and no git command is run.
set -uo pipefail

ADAPTER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK="${ADAPTER_ROOT}/sdk"
GATE="${ADAPTER_ROOT}/scripts/check-sdk-pack.sh"

[[ -d "${SDK}/node_modules" ]] || { echo "check-sdk-pack-selftest: ${SDK}/node_modules missing - run pnpm install first" >&2; exit 3; }

owns_scratch=0
if [[ -n "${SDK_PACK_SELFTEST_SCRATCH:-}" ]]; then
  mkdir -p "$SDK_PACK_SELFTEST_SCRATCH"
  SCRATCH="$(cd "$SDK_PACK_SELFTEST_SCRATCH" && pwd)"
else
  SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/sdk-pack-selftest.XXXXXX")"
  owns_scratch=1
fi
cleanup() { if [[ "$owns_scratch" -eq 1 ]]; then rm -rf "$SCRATCH"; fi; }
trap cleanup EXIT

# The package.json build step reaches ../scripts, so every staged copy lives one level
# under a directory holding that sibling.
PKGS="${SCRATCH}/pkgs"
mkdir -p "${PKGS}/scripts"
ln -sf "${ADAPTER_ROOT}/scripts/finalize-sdk-build.mjs" "${PKGS}/scripts/finalize-sdk-build.mjs"

stage() { # name -> prints the staged package dir
  local dest="${PKGS}/$1"
  rm -rf "$dest"
  mkdir -p "$dest"
  cp -a "${SDK}/src" "${SDK}/README.md" "${SDK}/package.json" "$dest/"
  cp -a "${SDK}"/tsconfig*.json "$dest/"
  ln -s "${SDK}/node_modules" "${dest}/node_modules"
  # Stands in for the real test tier, so mutation B shows the defect class it names.
  mkdir -p "${dest}/tests"
  printf 'export const packedTestTierMarker = true;\n' > "${dest}/tests/marker.test.ts"
  printf '%s' "$dest"
}

run_gate() { # package-dir logfile
  SDK_PACK_PACKAGE_DIR="$1" SDK_PACK_SCRATCH="${SCRATCH}/work" "$GATE" >"$2" 2>&1
}

pristine="$(stage pristine)"
if ! run_gate "$pristine" "${SCRATCH}/pristine.log"; then
  echo "check-sdk-pack-selftest: the gate fails on an UNMUTATED copy - the red-proof below would prove nothing" >&2
  tail -n 30 "${SCRATCH}/pristine.log" >&2
  exit 1
fi
echo "  ok    unmutated copy passes the gate"

expect_red() { # label python-mutation needle
  local label="$1" mutation="$2" needle="$3"
  local dest
  dest="$(stage "$label")"
  python3 - "$dest/package.json" <<PYEOF
import collections, io, json, sys
path = sys.argv[1]
manifest = json.load(io.open(path, encoding="utf-8"), object_pairs_hook=collections.OrderedDict)
${mutation}
io.open(path, "w", encoding="utf-8").write(json.dumps(manifest, indent=2) + "\n")
PYEOF
  if run_gate "$dest" "${SCRATCH}/${label}.log"; then
    echo "check-sdk-pack-selftest: ${label}: the gate PASSED a package it must refuse" >&2
    exit 1
  fi
  if ! /usr/bin/grep -q "$needle" "${SCRATCH}/${label}.log"; then
    echo "check-sdk-pack-selftest: ${label}: the gate failed, but not for the reason under test (wanted ${needle})" >&2
    tail -n 30 "${SCRATCH}/${label}.log" >&2
    exit 1
  fi
  echo "  ok    ${label}: refused, naming ${needle}"
}

expect_red ts-entrypoint \
  'manifest["main"] = "./src/index.ts"
manifest["types"] = "./src/index.ts"
manifest.pop("exports", None)
manifest["files"] = ["dist", "src"]' \
  "commonjs-consumer"

expect_red no-files-allowlist \
  'manifest.pop("files", None)' \
  "pack-contents"

echo "check-sdk-pack-selftest: the pack gate refuses a TypeScript entry point and an unrestricted pack."
