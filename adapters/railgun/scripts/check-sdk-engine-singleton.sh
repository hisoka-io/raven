#!/usr/bin/env bash
# Proves that the packed SDK, installed beside the Railgun wallet it plugs into, leaves exactly one
# @railgun-community/engine in the tree, that its declarations typecheck against that one, and that
# PerChainPOINodeInterface.install lands on the copy the wallet reads.
#
# Engine's injection seam is a static on a class (`POI.init`). A second engine copy carries its own
# static, so an interface installed through one copy is never read through the other: wrong state
# and no error. The SDK's own tree cannot show this, because engine is only a devDependency there.
#
# Engine is an optional peer: npm installs no copy for the SDK, and the SDK's types resolve against
# the engine the wallet brings. A required peer would be met with the newest version the range
# admits, beside the wallet's exact pin: two engines.
#
# Instruments, because each misses a defect another catches: a second engine copy leaves `npm ls`
# green, and a peer range that excludes the wallet's pin leaves one copy on disk.
#   single-instance  exactly one engine directory, and the consumer, the SDK and the wallet all
#                    resolve engine to the same file
#   engine-edges     `npm ls` finds every edge into engine valid, the SDK's peer edge included
#   types            a CommonJS and an ESM consumer assign the SDK to engine's POINodeInterface
#                    under skipLibCheck, which every engine consumer needs; and with it off, no
#                    diagnostic lands outside engine's own declarations
#   install-lands    after the wallet's copy is given a stock interface, as startRailgunEngine
#                    does, install through the consumer's engine leaves the router on that copy
#   install-refuses  with a second copy forced, install through the consumer's copy refuses with
#                    InvalidQuery, and the wallet's copy keeps its stock interface
#
# Needs the npm registry for the wallet's tree, so it stays out of the offline pack gate. Modes:
#   wallet-only       the SDK and the wallet alone, which is what a consumer installs
#   default           engine also listed at the wallet's version
#   legacy-peer-deps  the same under --legacy-peer-deps (how the terminal wallet installs)
#   split             engine listed at another version the peer range admits, forcing two copies
#
# Overrides, all used by check-sdk-engine-singleton-selftest.sh:
#   SDK_ENGINE_PACKAGE_DIR  package to pack (default: the real SDK)
#   SDK_ENGINE_SCRATCH      working directory (default: a fresh mktemp dir)
#   SDK_ENGINE_WALLET       wallet to install beside it (default: the version the terminal wallet pins)
#   SDK_ENGINE_MODES        install modes (default: "wallet-only default legacy-peer-deps split")
set -uo pipefail

ADAPTER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG="$(cd "${SDK_ENGINE_PACKAGE_DIR:-${ADAPTER_ROOT}/sdk}" && pwd)"
WALLET="${SDK_ENGINE_WALLET:-@railgun-community/wallet@10.10.0-rc.1}"
MODES="${SDK_ENGINE_MODES:-wallet-only default legacy-peer-deps split}"
TSC="${PKG}/node_modules/.bin/tsc"

fail() { echo "check-sdk-engine-singleton: FAIL $*" >&2; exit 1; }

[[ -x "$TSC" ]] || { echo "check-sdk-engine-singleton: ${TSC} missing - run pnpm install first" >&2; exit 3; }

owns_scratch=0
if [[ -n "${SDK_ENGINE_SCRATCH:-}" ]]; then
  mkdir -p "$SDK_ENGINE_SCRATCH"
  WORK="$(cd "$SDK_ENGINE_SCRATCH" && pwd)"
else
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/sdk-engine-singleton.XXXXXX")"
  owns_scratch=1
fi
cleanup() { if [[ "$owns_scratch" -eq 1 ]]; then rm -rf "$WORK"; fi; }
trap cleanup EXIT

rm -rf "${WORK}/tar"
mkdir -p "${WORK}/tar"

( cd "$PKG" && npm run build ) >"${WORK}/build.log" 2>&1 \
  || { cat "${WORK}/build.log" >&2; fail "build: the dual-format emit did not complete"; }

sdk_name="$(node -p 'require(process.argv[1]).name' "${PKG}/package.json")" || exit 3
tarball="${WORK}/tar/$( cd "$PKG" && npm pack --json --ignore-scripts --pack-destination "${WORK}/tar" 2>"${WORK}/pack.err" \
  | node -e 'let s="";process.stdin.on("data",(d)=>{s+=d}).on("end",()=>{
      const entries = JSON.parse(s.slice(s.indexOf("[")));
      process.stdout.write(entries[0].filename);
    });' )"
[[ -f "$tarball" ]] || { cat "${WORK}/pack.err" >&2; fail "npm pack named a tarball that is not there: ${tarball}"; }

write_consumers() { # dir
  local dir="$1" source
  # An unresolved declaration is an error type under skipLibCheck: it passes every assignment and
  # silences every check built on it. An unused @ts-expect-error is still reported, so the canary
  # is a directive that only an intact engine declaration satisfies.
  source="$(cat <<CONSUMEREOF
import type { POI, POINodeInterface } from "@railgun-community/engine";
import { RavenPOINodeInterface } from "${sdk_name}";

type Leaves<T, Depth extends unknown[] = []> = Depth["length"] extends 3
  ? T
  : T extends readonly (infer E)[]
    ? T | Leaves<E, [...Depth, 0]>
    : T extends object
      ? T | Leaves<T[keyof T], [...Depth, 0]>
      : T;
type ContractTypes = {
  [K in keyof POINodeInterface]: POINodeInterface[K] extends (...args: infer A) => infer R
    ? Leaves<A[number] | Awaited<R>>
    : never;
}[keyof POINodeInterface];
class Foreign {
  readonly foreignBrand = Symbol("foreign");
}

export const x: POINodeInterface = new RavenPOINodeInterface({ endpoint: "https://raven.example.com" });
export const injected: Parameters<typeof POI.init>[1] = x;
// @ts-expect-error only an \`any\` somewhere in engine's contract admits a foreign instance
export const degraded: ContractTypes = new Foreign();
CONSUMEREOF
)"
  printf '%s\n' "$source" > "${dir}/consumer.ts"
  printf '%s\n' "$source" > "${dir}/consumer.mts"
  cat > "${dir}/tsconfig.json" <<'TSCONFIGEOF'
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "noEmit": true,
    "skipLibCheck": true,
    "types": []
  },
  "include": ["consumer.ts", "consumer.mts"]
}
TSCONFIGEOF
  cat > "${dir}/tsconfig.libcheck.json" <<'TSCONFIGEOF'
{
  "extends": "./tsconfig.json",
  "compilerOptions": { "skipLibCheck": false }
}
TSCONFIGEOF
}

install_probe() { # dir mode expect(lands|refuses)
  local dir="$1" mode="$2" expect="$3" instrument
  if [[ "$expect" == lands ]]; then instrument=install-lands; else instrument=install-refuses; fi
  PROBE_OUTCOME="$( cd "$dir" && node -e '
const { realpathSync } = require("node:fs");
const { join } = require("node:path");
const [sdkName, expect] = process.argv.slice(1);
const sdk = require(sdkName);
const walletEngine = require(require.resolve("@railgun-community/engine", {
  paths: [realpathSync(join("node_modules", "@railgun-community", "wallet"))],
}));
let consumerEngine;
try {
  consumerEngine = require("@railgun-community/engine");
} catch (cause) {
  console.error(`the consumer cannot import engine, so it cannot call install: ${cause}`);
  process.exit(1);
}
const stock = {
  isActive: () => true,
  isRequired: async () => true,
  getPOIsPerList: async () => ({}),
  getPOIMerkleProofs: async () => [],
  validatePOIMerkleroots: async () => true,
  submitPOI: async () => undefined,
  submitLegacyTransactProofs: async () => undefined,
};
walletEngine.POI.init([], stock);
const raven = new sdk.RavenPOINodeInterface({ endpoint: "https://raven.example.com" });
let refused;
try {
  sdk.PerChainPOINodeInterface.install(consumerEngine.POI, [], [raven]);
} catch (cause) {
  refused = cause;
}
const held = walletEngine.POI.nodeInterface;
if (expect === "lands") {
  if (consumerEngine !== walletEngine) {
    console.error("the consumer and the wallet load different engine copies");
    process.exit(1);
  }
  if (refused !== undefined) {
    console.error(`install refused although the consumer and the wallet share one engine: ${refused}`);
    process.exit(1);
  }
  if (!(held instanceof sdk.PerChainPOINodeInterface)) {
    console.error("install returned, and the wallet engine still holds its stock interface");
    process.exit(1);
  }
  process.stdout.write("installed on the wallet engine");
} else {
  if (consumerEngine === walletEngine) {
    console.error("the consumer shares the wallet engine, so this install proves nothing about a second copy");
    process.exit(1);
  }
  if (refused === undefined) {
    console.error(`install returned on a copy the wallet never reads; the wallet engine ${held === stock ? "still holds its stock interface" : "changed"}`);
    process.exit(1);
  }
  if (!sdk.RavenError.is(refused, "InvalidQuery")) {
    console.error(`install refused with something other than InvalidQuery: ${refused}`);
    process.exit(1);
  }
  if (held !== stock) {
    console.error("install refused, yet the wallet engine no longer holds its stock interface");
    process.exit(1);
  }
  process.stdout.write("refused with InvalidQuery");
}
' "$sdk_name" "$expect" 2>"${dir}/${instrument}.err" )" \
    || { cat "${dir}/${instrument}.err" >&2; fail "${instrument} (${mode}): see the error above"; }
}

check_mode() { # mode
  local mode="$1" dir="${WORK}/$1" flags=(--no-audit --no-fund --ignore-scripts) engine_spec=() want=1 expect=lands
  case "$mode" in
    wallet-only) ;;
    default) engine_spec=("@railgun-community/engine@${engine_pin}") ;;
    legacy-peer-deps) flags+=(--legacy-peer-deps); engine_spec=("@railgun-community/engine@${engine_pin}") ;;
    split) engine_spec=("@railgun-community/engine@${engine_other}"); want=2; expect=refuses ;;
    *) echo "check-sdk-engine-singleton: unknown mode ${mode}" >&2; exit 3 ;;
  esac
  rm -rf "$dir"
  mkdir -p "$dir"
  printf '{"name":"raven-engine-singleton-probe","private":true,"version":"0.0.0","type":"commonjs"}\n' \
    > "${dir}/package.json"
  ( cd "$dir" && npm install "${flags[@]}" "$tarball" "$WALLET" "${engine_spec[@]}" ) >"${dir}/install.log" 2>&1 \
    || { tail -n 40 "${dir}/install.log" >&2; fail "install (${mode}): the tarball and ${WALLET} do not install together"; }

  local copies=()
  mapfile -t copies < <( cd "$dir" && find node_modules -type d -path '*/@railgun-community/engine' | LC_ALL=C sort )

  if [[ "$mode" == split ]]; then
    if [[ "${#copies[@]}" -ne "$want" ]]; then
      printf '  %s\n' "${copies[@]}" >&2
      echo "check-sdk-engine-singleton: split: engine@${engine_other} beside ${WALLET} left ${#copies[@]} copies, not the ${want} this mode needs" >&2
      exit 3
    fi
    install_probe "$dir" "$mode" "$expect"
    echo "  ok    ${mode}: ${#copies[@]} engine copies forced; install ${PROBE_OUTCOME}"
    return
  fi

  if [[ "${#copies[@]}" -ne "$want" ]]; then
    printf '  %s\n' "${copies[@]}" >&2
    fail "single-instance (${mode}): ${#copies[@]} engine copies in a tree holding the SDK and ${WALLET}"
  fi

  ( cd "$dir" && npm ls @railgun-community/engine --all ) >"${dir}/npm-ls-engine.txt" 2>&1 \
    || { cat "${dir}/npm-ls-engine.txt" >&2; fail "engine-edges (${mode}): npm reports an edge into engine invalid"; }

  ( cd "$dir" && node -e '
const { realpathSync } = require("node:fs");
const { join, sep } = require("node:path");
const [sdkName, copy] = process.argv.slice(1);
const vantage = {
  consumer: process.cwd(),
  sdk: realpathSync(join("node_modules", sdkName)),
  wallet: realpathSync(join("node_modules", "@railgun-community", "wallet")),
};
const resolved = Object.entries(vantage).map(([who, from]) => [who, realpathSync(require.resolve("@railgun-community/engine", { paths: [from] }))]);
const files = new Set(resolved.map(([, file]) => file));
const home = realpathSync(copy) + sep;
if (files.size !== 1 || ![...files][0].startsWith(home)) {
  console.error(resolved.map(([who, file]) => `  ${who} -> ${file}`).join("\n"));
  process.exit(1);
}
' "$sdk_name" "${copies[0]}" ) || fail "single-instance (${mode}): the consumer, the SDK and the wallet resolve engine to different files"

  write_consumers "$dir"
  ( cd "$dir" && "$TSC" -p tsconfig.json --pretty false ) >"${dir}/types.log" 2>&1 \
    || { cat "${dir}/types.log" >&2; fail "types (${mode}): the SDK is not assignable to engine's POINodeInterface"; }

  ( cd "$dir" && "$TSC" -p tsconfig.libcheck.json --pretty false ) >"${dir}/libcheck.log" 2>&1
  local upstream outside
  upstream="$(/usr/bin/grep -c "^${copies[0]}/.*error TS" "${dir}/libcheck.log")"
  outside="$(/usr/bin/grep 'error TS' "${dir}/libcheck.log" | /usr/bin/grep -v "^${copies[0]}/")"
  if [[ -n "$outside" ]]; then
    printf '%s\n' "$outside" >&2
    fail "types (${mode}): with skipLibCheck off, a diagnostic lands outside engine's own declarations"
  fi

  install_probe "$dir" "$mode" "$expect"

  echo "  ok    ${mode}: one engine (${copies[0]}), every edge valid, one resolved file; types assign, lib check clean outside engine (${upstream} upstream diagnostics inside it); install ${PROBE_OUTCOME}"
}

engine_pin="$(npm view "$WALLET" "dependencies.@railgun-community/engine" 2>/dev/null)"
[[ -n "$engine_pin" ]] || { echo "check-sdk-engine-singleton: could not read the engine version ${WALLET} depends on" >&2; exit 3; }
peer_range="$(node -p 'require(process.argv[1]).peerDependencies["@railgun-community/engine"]' "${PKG}/package.json")" || exit 3
# The newest version the peer range admits other than the wallet's pin, so npm accepts it for the
# SDK's peer and must nest the wallet's pin beside it.
engine_other="$(npm view "@railgun-community/engine@${peer_range}" version --json 2>/dev/null | node -e '
let s = ""; process.stdin.on("data", (d) => { s += d; }).on("end", () => {
  const semver = require(require.resolve("semver", { paths: [process.argv[2]] }));
  const parsed = JSON.parse(s || "[]");
  const others = (Array.isArray(parsed) ? parsed : [parsed]).filter((v) => v !== process.argv[1]);
  if (others.length > 0) process.stdout.write(others.sort(semver.rcompare)[0]);
});' "$engine_pin" "$PKG")"
[[ -n "$engine_other" ]] || { echo "check-sdk-engine-singleton: no engine version in ${peer_range} other than ${engine_pin}" >&2; exit 3; }

for mode in $MODES; do check_mode "$mode"; done

echo "check-sdk-engine-singleton: beside ${WALLET}, the packed SDK installs no engine of its own, leaves one engine that it typechecks against and installs onto, and refuses a second copy (modes: ${MODES})."
