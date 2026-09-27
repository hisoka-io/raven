#!/usr/bin/env bash
# Red-proof for check-sdk-engine-singleton.sh. Stages COPIES of the SDK with one defect each and
# requires the gate to refuse each one by name:
#
#   hard-dependency:   engine as a runtime dependency at a version the wallet's exact pin excludes.
#                      npm nests the wallet's copy and `npm ls` stays green, so only the
#                      single-instance instrument sees it.
#   required-peer:     engine a required peer again. With engine left out, npm meets the peer with
#                      the newest version the range admits and nests the wallet's pin: two copies.
#   peer-excludes-pin: a peer range that reads right and excludes the wallet's prerelease pin
#                      (`^9.6.0` does not admit 9.7.0-rc.0). Listed at the pin, npm refuses the
#                      install; left out, or under --legacy-peer-deps, one copy lands and only the
#                      edge check sees it.
#   return-shape:      the engine-facing getPOIsPerList answers with the SDK's literal-union map.
#                      The per-chain router holds the interface as engine's type, so the SDK's own
#                      build already refuses it.
#   install-unguarded: PerChainPOINodeInterface.install takes whatever the consumer's engine holds
#                      as the stock interface. On a second copy the router lands where the wallet
#                      never reads; only the split install-refuses instrument sees it.
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

# One install mode per defect is enough to prove the gate can fail; the unmutated copy runs them all.
run_gate() { # package-dir logfile [modes]
  SDK_ENGINE_PACKAGE_DIR="$1" SDK_ENGINE_SCRATCH="${SCRATCH}/work" SDK_ENGINE_MODES="${3:-wallet-only default legacy-peer-deps split}" \
    "$GATE" >"$2" 2>&1
}

expect_red() { # label dir needle modes
  local label="$1" dir="$2" needle="$3" log="${SCRATCH}/$1.log"
  if run_gate "$dir" "$log" "$4"; then
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
echo "  ok    unmutated copy passes the gate in every mode"

dir="$(stage hard-dependency)"
mutate_manifest "$dir" 'manifest["dependencies"]["@railgun-community/engine"] = "9.8.0"' || exit 3
expect_red hard-dependency "$dir" "single-instance (wallet-only)" wallet-only

dir="$(stage required-peer)"
mutate_manifest "$dir" 'manifest.pop("peerDependenciesMeta")' || exit 3
expect_red required-peer "$dir" "single-instance (wallet-only)" wallet-only

dir="$(stage peer-excludes-pin)"
mutate_manifest "$dir" 'manifest["peerDependencies"]["@railgun-community/engine"] = "^9.6.0"' || exit 3
expect_red peer-excludes-pin-wallet-only "$dir" "engine-edges (wallet-only)" wallet-only
expect_red peer-excludes-pin "$dir" "install (default)" default
expect_red peer-excludes-pin-legacy "$dir" "engine-edges (legacy-peer-deps)" legacy-peer-deps

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
expect_red return-shape "$dir" "build: the dual-format emit did not complete" wallet-only
/usr/bin/grep -q "The types returned by 'getPOIsPerList(...)' are incompatible" "${SCRATCH}/return-shape.log" \
  || { echo "check-sdk-engine-singleton-selftest: return-shape: the refusal does not name getPOIsPerList" >&2; exit 1; }

dir="$(stage install-unguarded)"
python3 - "${dir}/src/per-chain-poi-node-interface.ts" <<'PYEOF' || exit 3
import io, sys
path = sys.argv[1]
source = io.open(path, encoding="utf-8").read()
guard = "function isNodeInterface(value: unknown): value is POINodeInterface {\n"
if source.count(guard) != 1:
    raise SystemExit(f"install-unguarded: expected one isNodeInterface guard, found {source.count(guard)}")
source = source.replace(guard, guard + "  return true;\n")
io.open(path, "w", encoding="utf-8").write(source)
PYEOF
expect_red install-unguarded "$dir" "install-refuses (split)" split

echo "check-sdk-engine-singleton-selftest: the gate refuses a second engine, a required peer, a peer range that excludes the pin, a return shape engine rejects, and an install that lands where the wallet never reads."
