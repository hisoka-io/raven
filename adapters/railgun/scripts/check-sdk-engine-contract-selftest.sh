#!/usr/bin/env bash
# Red-proof for the engine contract in sdk/tests/upstream_class_contract.test.ts. Only the
# typecheck can fail that file (vitest strips types), so this stages a COPY of the SDK and
# requires `tsc` to redden IN THAT FILE for each defect:
#
#   return-shape:     the engine-facing getPOIsPerList answers with the SDK's own literal-union
#                     map again, which engine's nominal status enum rejects.
#   engine-unresolved: every engine export resolves to nothing. Under skipLibCheck, which every
#                     engine consumer needs, that is a silent `any` and the assignment passes.
#   engine-member-degraded: the real engine with one declaration file missing, so a single
#                     parameter degrades to `any` while the class itself stays real.
#
# Offline. The real tree is never written to and no git command is run.
set -uo pipefail

ADAPTER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK="${ADAPTER_ROOT}/sdk"
TSC="${SDK}/node_modules/.bin/tsc"
CONTRACT="tests/upstream_class_contract.test.ts"

fail() { echo "check-sdk-engine-contract-selftest: $*" >&2; exit 1; }

[[ -x "$TSC" && -d "${SDK}/node_modules/@railgun-community/engine" ]] \
  || { echo "check-sdk-engine-contract-selftest: ${SDK}/node_modules lacks tsc or engine - run pnpm install first" >&2; exit 3; }

owns_scratch=0
if [[ -n "${SDK_ENGINE_CONTRACT_SELFTEST_SCRATCH:-}" ]]; then
  mkdir -p "$SDK_ENGINE_CONTRACT_SELFTEST_SCRATCH"
  SCRATCH="$(cd "$SDK_ENGINE_CONTRACT_SELFTEST_SCRATCH" && pwd)"
else
  SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/sdk-engine-contract-selftest.XXXXXX")"
  owns_scratch=1
fi
cleanup() { if [[ "$owns_scratch" -eq 1 ]]; then rm -rf "$SCRATCH"; fi; }
trap cleanup EXIT

# node_modules is a farm of links so one package can be swapped without touching the real one.
stage() { # name -> prints the staged dir
  local dest="${SCRATCH}/$1" entry
  rm -rf "$dest"
  mkdir -p "${dest}/node_modules/@railgun-community"
  cp -a "${SDK}/src" "${SDK}/tests" "${SDK}/tsconfig.json" "${SDK}/package.json" "$dest/"
  shopt -s dotglob nullglob
  for entry in "${SDK}"/node_modules/*; do
    [[ "$(basename "$entry")" == "@railgun-community" ]] && continue
    ln -s "$entry" "${dest}/node_modules/$(basename "$entry")"
  done
  for entry in "${SDK}"/node_modules/@railgun-community/*; do
    ln -s "$entry" "${dest}/node_modules/@railgun-community/$(basename "$entry")"
  done
  shopt -u dotglob nullglob
  printf '%s' "$dest"
}

typecheck() { # dir logfile
  ( cd "$1" && "$TSC" --noEmit -p tsconfig.json --pretty false ) >"$2" 2>&1
}

# The degradation canary is an @ts-expect-error that an intact declaration satisfies; a degraded
# one leaves it unused, reported as TS2578 on the directive's own line.
canary_line="$(/usr/bin/grep -n 'const degraded: ContractTypes' "${SDK}/${CONTRACT}" | cut -d: -f1)"
[[ "$canary_line" =~ ^[0-9]+$ ]] || { echo "check-sdk-engine-contract-selftest: no degradation canary in ${CONTRACT}" >&2; exit 3; }
canary="${CONTRACT}($((canary_line - 1)),"

expect_red() { # label dir needle
  local label="$1" dir="$2" needle="$3" log="${SCRATCH}/$1.log"
  if typecheck "$dir" "$log"; then
    fail "${label}: the typecheck PASSED a contract it must refuse"
  fi
  if ! /usr/bin/grep -F "$needle" "$log" | /usr/bin/grep -q 'error TS'; then
    tail -n 30 "$log" >&2
    fail "${label}: the typecheck failed, but not with ${needle}"
  fi
  echo "  ok    ${label}: refused in ${CONTRACT} (${needle})"
}

pristine="$(stage pristine)"
if ! typecheck "$pristine" "${SCRATCH}/pristine.log"; then
  tail -n 30 "${SCRATCH}/pristine.log" >&2
  fail "the typecheck fails on an UNMUTATED copy - the red-proof below would prove nothing"
fi
echo "  ok    unmutated copy typechecks against the real engine declaration"

dir="$(stage return-shape)"
python3 - "${dir}/src/raven-poi-node-interface.ts" <<'PYEOF'
import io, sys
path = sys.argv[1]
source = io.open(path, encoding="utf-8").read()
engine_shaped = "  ): Promise<{ [blindedCommitment: string]: EnginePOIsPerList }>;\n"
if source.count(engine_shaped) != 1:
    raise SystemExit(f"return-shape: expected one engine-shaped overload, found {source.count(engine_shaped)}")
io.open(path, "w", encoding="utf-8").write(source.replace(engine_shaped, "  ): Promise<PoisPerListResponse>;\n"))
PYEOF
[[ $? -eq 0 ]] || exit 3
expect_red return-shape "$dir" "${CONTRACT}("
/usr/bin/grep -q "The types returned by 'getPOIsPerList(...)' are incompatible" "${SCRATCH}/return-shape.log" \
  || fail "return-shape: the refusal does not name getPOIsPerList"

dir="$(stage engine-unresolved)"
engine="${dir}/node_modules/@railgun-community/engine"
rm "$engine"
mkdir -p "$engine"
printf '{"name":"@railgun-community/engine","version":"0.0.0","types":"index.d.ts"}\n' > "${engine}/package.json"
printf 'export { POI, POINodeInterface, POIsPerList, TXOPOIListStatus } from "an-unresolvable-module";\n' \
  > "${engine}/index.d.ts"
expect_red engine-unresolved "$dir" "$canary"

dir="$(stage engine-member-degraded)"
engine="${dir}/node_modules/@railgun-community/engine"
real_engine="$(readlink -f "$engine")"
rm "$engine"
cp -a "$real_engine" "$engine"
[[ -f "${engine}/dist/models/prover-types.d.ts" ]] || exit 3
rm "${engine}/dist/models/prover-types.d.ts"
expect_red engine-member-degraded "$dir" "$canary"

echo "check-sdk-engine-contract-selftest: the contract refuses a wrong return shape and an engine that degraded to any, whole or in part."
