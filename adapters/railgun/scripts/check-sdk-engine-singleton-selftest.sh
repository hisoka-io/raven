#!/usr/bin/env bash
# Red-proof for check-sdk-engine-singleton.sh. Stages COPIES of the SDK with one defect each and
# requires the gate to refuse each one by name:
#
#   hard-dependency:   engine as a runtime dependency at a version the wallet's exact pin excludes.
#                      npm nests the wallet's copy and `npm ls` stays green, so only the
#                      single-instance instrument sees it.
#   peer-excludes-pin: a peer range that reads right and excludes the wallet's prerelease pin
#                      (`^9.6.0` does not admit 9.7.0-rc.0). One copy lands on disk, so only the
#                      edge check sees it.
#   return-shape:      the engine-facing getPOIsPerList answers with the SDK's literal-union map.
#
# Needs the npm registry, like the gate. The real tree is never written to and no git command is run.
set -uo pipefail

ADAPTER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK="${ADAPTER_ROOT}/sdk"
GATE="${ADAPTER_ROOT}/scripts/check-sdk-engine-singleton.sh"

[[ -d "${SDK}/node_modules" ]] || { echo "check-sdk-engine-singleton-selftest: ${SDK}/node_modules missing - run pnpm install first" >&2; exit 3; }

owns_scratch=0
if [[ -n "${SDK_ENGINE_SELFTEST_SCRATCH:-}" ]]; then
  mkdir -p "$SDK_ENGINE_SELFTEST_SCRATCH"
  SCRATCH="$(cd "$SDK_ENGINE_SELFTEST_SCRATCH" && pwd)"
else
  SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/sdk-engine-singleton-selftest.XXXXXX")"
  owns_scratch=1
fi
cleanup() { if [[ "$owns_scratch" -eq 1 ]]; then rm -rf "$SCRATCH"; fi; }
trap cleanup EXIT

# The build step reaches ../scripts, so every staged copy sits one level under that sibling.
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
  printf '%s' "$dest"
}

mutate_manifest() { # dir python-statements
  python3 - "$1/package.json" <<PYEOF
import collections, io, json, sys
path = sys.argv[1]
manifest = json.load(io.open(path, encoding="utf-8"), object_pairs_hook=collections.OrderedDict)
$2
io.open(path, "w", encoding="utf-8").write(json.dumps(manifest, indent=2) + "\n")
PYEOF
}

# One install mode is enough to prove the gate can fail; the gate itself runs both.
run_gate() { # package-dir logfile
  SDK_ENGINE_PACKAGE_DIR="$1" SDK_ENGINE_SCRATCH="${SCRATCH}/work" SDK_ENGINE_MODES=default \
    "$GATE" >"$2" 2>&1
}

expect_red() { # label dir needle
  local label="$1" dir="$2" needle="$3" log="${SCRATCH}/$1.log"
  if run_gate "$dir" "$log"; then
    echo "check-sdk-engine-singleton-selftest: ${label}: the gate PASSED a package it must refuse" >&2
    exit 1
  fi
  if ! /usr/bin/grep -qF "$needle" "$log"; then
    echo "check-sdk-engine-singleton-selftest: ${label}: the gate failed, but not for the reason under test (wanted ${needle})" >&2
    tail -n 30 "$log" >&2
    exit 1
  fi
  echo "  ok    ${label}: refused, naming ${needle}"
}

pristine="$(stage pristine)"
if ! run_gate "$pristine" "${SCRATCH}/pristine.log"; then
  echo "check-sdk-engine-singleton-selftest: the gate fails on an UNMUTATED copy - the red-proof below would prove nothing" >&2
  tail -n 30 "${SCRATCH}/pristine.log" >&2
  exit 1
fi
echo "  ok    unmutated copy passes the gate"

dir="$(stage hard-dependency)"
mutate_manifest "$dir" 'manifest["dependencies"]["@railgun-community/engine"] = "9.8.0"' || exit 3
expect_red hard-dependency "$dir" "single-instance (default)"

dir="$(stage peer-excludes-pin)"
mutate_manifest "$dir" 'manifest["peerDependencies"]["@railgun-community/engine"] = "^9.6.0"' || exit 3
expect_red peer-excludes-pin "$dir" "engine-edges (default)"

dir="$(stage return-shape)"
python3 - "${dir}/src/raven-poi-node-interface.ts" <<'PYEOF' || exit 3
import io, sys
path = sys.argv[1]
source = io.open(path, encoding="utf-8").read()
engine_shaped = "  ): Promise<{ [blindedCommitment: string]: EnginePOIsPerList }>;\n"
if source.count(engine_shaped) != 1:
    raise SystemExit(f"return-shape: expected one engine-shaped overload, found {source.count(engine_shaped)}")
source = source.replace(engine_shaped, "  ): Promise<PoisPerListResponse>;\n")
source = source.replace('import type { POIsPerList as EnginePOIsPerList } from "@railgun-community/engine";\n', "")
io.open(path, "w", encoding="utf-8").write(source)
PYEOF
expect_red return-shape "$dir" "types (default)"
/usr/bin/grep -q "The types returned by 'getPOIsPerList(...)' are incompatible" "${SCRATCH}/return-shape.log" \
  || { echo "check-sdk-engine-singleton-selftest: return-shape: the refusal does not name getPOIsPerList" >&2; exit 1; }

echo "check-sdk-engine-singleton-selftest: the gate refuses a second engine, a peer range that excludes the pin, and a return shape engine rejects."
