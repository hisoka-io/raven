#!/usr/bin/env bash
# Proves the packed SDK is installable and usable by a wallet that has no checkout of
# this repo, and that the tarball carries exactly the surface it means to carry.
#
# Three things a green `pnpm test` cannot see, because the suite imports `../src` directly:
#   1. `main`/`types`/`exports` can point at TypeScript sources. A consumer then resolves
#      a `.ts` file at runtime and node refuses it - the suite never notices, because it
#      never resolves the package by name.
#   2. `npm pack` obeys `files`, not `.gitignore`. Without an allowlist the whole test
#      tier ships to every consumer.
#   3. The CommonJS and ESM halves of a dual build can each be broken on their own:
#      a missing `type` marker beside the CommonJS emit, or an extensionless relative
#      specifier in the ESM emit, fails only at a consumer's first import.
#
# Everything here is offline. The one registry dependency is packed out of the SDK's own
# installed tree, so no network call is made and no registry credential is needed.
#
# Overrides, both used by check-sdk-pack-selftest.sh:
#   SDK_PACK_PACKAGE_DIR  package to pack (default: the real SDK)
#   SDK_PACK_SCRATCH      working directory (default: a fresh mktemp dir)
set -uo pipefail

ADAPTER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG="$(cd "${SDK_PACK_PACKAGE_DIR:-${ADAPTER_ROOT}/sdk}" && pwd)"

fail() { echo "check-sdk-pack: FAIL $*" >&2; exit 1; }

node -e 'const [maj, min] = process.versions.node.split(".").map(Number);
if (maj < 20 || (maj === 20 && min < 6)) {
  console.error(`check-sdk-pack: needs node >= 20.6 for module.register/import.meta.resolve, got ${process.versions.node}`);
  process.exit(3);
}' || exit 3

[[ -d "${PKG}/node_modules" ]] || { echo "check-sdk-pack: ${PKG}/node_modules missing - run pnpm install first" >&2; exit 3; }

owns_scratch=0
if [[ -n "${SDK_PACK_SCRATCH:-}" ]]; then
  mkdir -p "$SDK_PACK_SCRATCH"
  WORK="$(cd "$SDK_PACK_SCRATCH" && pwd)"
else
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/sdk-pack.XXXXXX")"
  owns_scratch=1
fi
cleanup() { if [[ "$owns_scratch" -eq 1 ]]; then rm -rf "$WORK"; fi; }
trap cleanup EXIT

rm -rf "${WORK}/tar" "${WORK}/cjs" "${WORK}/esm"
mkdir -p "${WORK}/tar" "${WORK}/cjs" "${WORK}/esm"

# --- build and pack ---------------------------------------------------------
# The build runs as its own step rather than through the `prepack` hook: hook output
# lands on the same stdout as `npm pack --json` and a tsc error must be attributable.
( cd "$PKG" && npm run build ) >"${WORK}/build.log" 2>&1 \
  || { cat "${WORK}/build.log" >&2; fail "build: the dual-format emit did not complete"; }

packed_filename() { node -e 'let s="";process.stdin.on("data",(d)=>{s+=d}).on("end",()=>{
  const start = s.indexOf("[");
  if (start < 0) { console.error("no JSON array in npm pack output"); process.exit(1); }
  const entries = JSON.parse(s.slice(start));
  if (!Array.isArray(entries) || entries.length !== 1 || typeof entries[0].filename !== "string") {
    console.error("unexpected npm pack manifest"); process.exit(1);
  }
  process.stdout.write(entries[0].filename);
});'; }

tarball="${WORK}/tar/$( cd "$PKG" && npm pack --json --ignore-scripts --pack-destination "${WORK}/tar" 2>"${WORK}/pack.err" | packed_filename )"
[[ -f "$tarball" ]] || { cat "${WORK}/pack.err" >&2; fail "npm pack named a tarball that is not there: ${tarball}"; }

# --- pack contents ----------------------------------------------------------
# Derived from the tree rather than transcribed, so adding a module needs no manifest
# bump while a stray tests/ or lockfile still reddens.
tar -tzf "$tarball" | sed 's|^package/||' | sed '/\/$/d' | LC_ALL=C sort > "${WORK}/actual.txt"
node -e '
const { readdirSync, writeFileSync } = require("node:fs");
const pkgDir = process.argv[1];
const modules = readdirSync(`${pkgDir}/src`).filter((f) => f.endsWith(".ts")).map((f) => f.slice(0, -3));
const expected = ["package.json", "README.md", ...modules.map((m) => `src/${m}.ts`)];
for (const format of ["cjs", "esm"]) {
  expected.push(`dist/${format}/package.json`);
  for (const m of modules) expected.push(`dist/${format}/${m}.js`, `dist/${format}/${m}.d.ts`);
}
writeFileSync(process.argv[2], expected.sort().join("\n") + "\n");
' "$PKG" "${WORK}/expected.txt"
if ! diff -u "${WORK}/expected.txt" "${WORK}/actual.txt" > "${WORK}/contents.diff"; then
  cat "${WORK}/contents.diff" >&2
  fail "pack-contents: the tarball is not the intended surface (-expected +actual above)"
fi
echo "  ok    pack contents: $(wc -l < "${WORK}/actual.txt") files, exactly the derived surface"

# The two emits differ only by a nested `type` marker, and losing one is silent until a
# consumer's first require/import.
tar -xzf "$tarball" -C "${WORK}" --strip-components=1 package/dist/cjs/package.json package/dist/esm/package.json 2>/dev/null \
  || fail "module-markers: the tarball carries no dist/cjs and dist/esm module markers"
node -e '
const { readFileSync } = require("node:fs");
for (const [dir, want] of [["cjs", "commonjs"], ["esm", "module"]]) {
  const got = JSON.parse(readFileSync(`${process.argv[1]}/dist/${dir}/package.json`, "utf8")).type;
  if (got !== want) { console.error(`dist/${dir} declares type ${got}, expected ${want}`); process.exit(1); }
}
' "${WORK}" || fail "module-markers: an emit declares the wrong module system"
echo "  ok    module markers: dist/cjs is commonjs, dist/esm is module"

# The one registry dependency, packed from the SDK's own installed tree so the consumer
# installs stay offline.
poseidon_dir="${PKG}/node_modules/@railgun-community/poseidon-hash-wasm"
[[ -d "$poseidon_dir" ]] || fail "missing ${poseidon_dir}; the consumer install would need the network"
poseidon_tgz="${WORK}/tar/$( cd "$PKG" && npm pack --json --ignore-scripts --pack-destination "${WORK}/tar" "$poseidon_dir" 2>/dev/null | packed_filename )"
[[ -f "$poseidon_tgz" ]] || fail "could not pack the poseidon dependency for an offline consumer install"

install_consumer() { # dir module-type
  local dir="$1" type="$2"
  printf '{"name":"raven-%s-consumer","private":true,"version":"0.0.0","type":"%s"}\n' "$type" "$type" > "${dir}/package.json"
  ( cd "$dir" && npm install --offline --no-audit --no-fund "$tarball" "$poseidon_tgz" ) >"${dir}/install.log" 2>&1 \
    || { cat "${dir}/install.log" >&2; fail "${type}-consumer: offline install of the tarball failed"; }
}

# --- CommonJS consumer ------------------------------------------------------
install_consumer "${WORK}/cjs" commonjs
cat > "${WORK}/cjs/probe.cjs" <<'PROBEEOF'
// Module._resolveFilename, not require.cache: a require that THROWS on a .ts file never
// reaches the cache, so a cache-only scan reports clean on the exact defect this catches.
const Module = require("node:module");
const resolved = [];
const inner = Module._resolveFilename;
Module._resolveFilename = function (...args) {
  const file = inner.apply(this, args);
  resolved.push(file);
  return file;
};
let sdk;
try {
  sdk = require("@raven/railgun-poi-node-interface");
} finally {
  Module._resolveFilename = inner;
}
const iface = new sdk.RavenPOINodeInterface({ endpoint: "http://127.0.0.1:1" });
if (iface.constructor.name !== "RavenPOINodeInterface") {
  throw new Error(`constructed ${iface.constructor.name}`);
}
if (typeof iface.getPOIsPerList !== "function") throw new Error("getPOIsPerList missing");
const typescript = resolved
  .concat(Object.keys(require.cache))
  .filter((file) => file.endsWith(".ts") && !file.endsWith(".d.ts"));
if (typescript.length > 0) throw new Error(`resolved TypeScript at runtime: ${typescript.join(", ")}`);
console.log(`  ok    commonjs consumer: required, constructed, ${resolved.length} resolutions, 0 TypeScript`);
PROBEEOF
( cd "${WORK}/cjs" && node probe.cjs ) || fail "commonjs-consumer: see the error above"

# The consuming wallet compiles with module/moduleResolution NodeNext under
# "type": "commonjs". Under NodeNext the `require` branch of the exports map is what
# supplies the declarations, and a declaration reachable only through the `import` branch
# typechecks nowhere in that wallet.
cat > "${WORK}/cjs/consumer.ts" <<'CONSUMEREOF'
import { RavenPOINodeInterface, type RavenConfig } from "@raven/railgun-poi-node-interface";
const config: RavenConfig = { endpoint: "https://raven.example.com" };
export const poi: RavenPOINodeInterface = new RavenPOINodeInterface(config);
CONSUMEREOF
cat > "${WORK}/cjs/tsconfig.json" <<'CONSUMEREOF'
{
  "compilerOptions": {
    "target": "ESNext",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "noEmit": true,
    "skipLibCheck": true,
    "types": []
  },
  "include": ["consumer.ts"]
}
CONSUMEREOF
( cd "${WORK}/cjs" && "${PKG}/node_modules/.bin/tsc" -p tsconfig.json ) \
  || fail "commonjs-types: a NodeNext CommonJS consumer cannot typecheck against the package"
echo "  ok    commonjs types: NodeNext resolves the declarations and the named type exports"

# --- ESM consumer -----------------------------------------------------------
install_consumer "${WORK}/esm" module
cat > "${WORK}/esm/resolve-hook.mjs" <<'HOOKEOF'
let sink;
export function initialize(data) { sink = data.port; }
export async function resolve(specifier, context, next) {
  const result = await next(specifier, context);
  sink.postMessage(result.url);
  return result;
}
HOOKEOF
cat > "${WORK}/esm/probe.mjs" <<'PROBEEOF'
import { register } from "node:module";
import { MessageChannel } from "node:worker_threads";

const SENTINEL = "node:zlib";
const { port1, port2 } = new MessageChannel();
const resolved = [];
let arrived;
const sentinelArrived = new Promise((settle) => { arrived = settle; });
port1.on("message", (url) => { resolved.push(url); if (url === SENTINEL) arrived(); });
register("./resolve-hook.mjs", import.meta.url, { data: { port: port2 }, transferList: [port2] });

const sdk = await import("@raven/railgun-poi-node-interface");
// Port delivery is ordered: once the sentinel lands, every earlier resolution has landed.
await import(SENTINEL);
await sentinelArrived;
port1.close();

const iface = new sdk.RavenPOINodeInterface({ endpoint: "http://127.0.0.1:1" });
if (iface.constructor.name !== "RavenPOINodeInterface") {
  throw new Error(`constructed ${iface.constructor.name}`);
}
if (typeof iface.getPOIsPerList !== "function") throw new Error("getPOIsPerList missing");
const typescript = resolved.filter((url) => url.endsWith(".ts") && !url.endsWith(".d.ts"));
if (typescript.length > 0) throw new Error(`resolved TypeScript at runtime: ${typescript.join(", ")}`);
if (resolved.length < 10) throw new Error(`only ${resolved.length} resolutions seen - the hook is blind`);
console.log(`  ok    esm consumer: imported, constructed, ${resolved.length} resolutions, 0 TypeScript`);
PROBEEOF
( cd "${WORK}/esm" && node probe.mjs ) || fail "esm-consumer: see the error above"

echo "check-sdk-pack: the packed tarball installs into a fresh CommonJS and a fresh ESM project and resolves no TypeScript."
