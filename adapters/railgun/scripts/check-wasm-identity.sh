#!/usr/bin/env bash
# The wasm a consumer links must be the wasm the build emitted, compared by sha256. A rebuild has
# produced the same size with a different hash, and a `file:` install keeps the old bytes until the
# next install, so size, mtime and version string are all blind to a stale binary.
#
# WASM_IDENTITY_CLIENT_DIR (default client-wasm) and WASM_IDENTITY_SDK_DIR (default sdk) locate
# the inputs. WASM_IDENTITY_PACK_DIR also packs each target there and checks the tarball, which is
# what a registry serves, and leaves SHA256SUMS and INTEGRITY (dist.integrity's form) beside it.
#
# Exit: 0 identical, 1 a check refused, 3 an input is missing.
set -uo pipefail

ADAPTER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLIENT_DIR="${WASM_IDENTITY_CLIENT_DIR:-${ADAPTER_ROOT}/client-wasm}"
SDK_DIR="${WASM_IDENTITY_SDK_DIR:-${ADAPTER_ROOT}/sdk}"
PACK_DIR="${WASM_IDENTITY_PACK_DIR:-}"
WASM=raven_inspire_client_wasm_bg.wasm
RECORD="${WASM}.sha256"
TARGETS=(pkg-node pkg-bundler)

failed=0
refuse() { echo "check-wasm-identity: FAIL $*" >&2; failed=1; }
missing() { echo "check-wasm-identity: $*" >&2; exit 3; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

command -v node >/dev/null || missing "node is required to read the package manifests"
# npm reads a relative `a/b` as a GitHub repository, so the targets are packed by absolute path.
CLIENT_DIR="$(cd "$CLIENT_DIR" 2>/dev/null && pwd)" || missing "no client dir ${WASM_IDENTITY_CLIENT_DIR:-client-wasm}"

# The format `sha256sum -c` reads, so a consumer can check it with no tool of ours.
record_matches() {
  local dir="$1" want="$2" line
  [[ -f "${dir}/${RECORD}" ]] || { echo "no ${RECORD}"; return 1; }
  line="$(head -n 1 "${dir}/${RECORD}")"
  [[ "$line" == "${want}  ${WASM}" ]] || { echo "${RECORD} reads '${line}', the wasm is ${want}"; return 1; }
}

declare -A built name
for t in "${TARGETS[@]}"; do
  dir="${CLIENT_DIR}/${t}"
  [[ -f "${dir}/${WASM}" ]] || missing "no build output ${dir}/${WASM}"
  [[ -f "${dir}/package.json" ]] || missing "no manifest ${dir}/package.json"
  built[$t]="$(sha "${dir}/${WASM}")"
  name[$t]="$(node -p 'require(process.argv[1]).name' "${dir}/package.json")" \
    || missing "unreadable manifest ${dir}/package.json"

  if why="$(record_matches "$dir" "${built[$t]}")"; then
    # An absent `files` packs everything; a present one must name the record or it never ships.
    if node -e 'const f = require(process.argv[1]).files;
      process.exit(Array.isArray(f) && !f.includes(process.argv[2]) ? 1 : 0)' \
      "${dir}/package.json" "$RECORD"; then
      echo "  ok    record: ${t} ships ${RECORD} = ${built[$t]}"
    else
      refuse "record: ${t}/package.json \`files\` omits ${RECORD}, so the package would not carry it"
    fi
  else
    refuse "record: ${t}: ${why}; rebuild with client-wasm/scripts/wasm-build.sh"
  fi
done

if [[ "${name[pkg-node]}" == "${name[pkg-bundler]}" ]]; then
  refuse "identity: pkg-node and pkg-bundler both publish as ${name[pkg-node]}, one name for two packages"
else
  echo "  ok    identity: node is ${name[pkg-node]}, bundler is ${name[pkg-bundler]}"
fi

# wasm-bindgen emits one module for both targets, so a difference is left over from another build.
if [[ "${built[pkg-node]}" != "${built[pkg-bundler]}" ]]; then
  refuse "targets: pkg-node wasm ${built[pkg-node]} != pkg-bundler wasm ${built[pkg-bundler]}"
else
  echo "  ok    targets: both carry ${built[pkg-node]}"
fi

pack_target() {
  local t="$1" json packed file integrity got line
  json="$(npm pack --json --ignore-scripts --pack-destination "$PACK_DIR" "${CLIENT_DIR}/${t}" 2>"$pack_err")" \
    || { cat "$pack_err" >&2; missing "npm pack failed for ${CLIENT_DIR}/${t}"; }
  packed="$(node -e '
const s = process.argv[1], start = s.indexOf("[");
const entries = start < 0 ? null : JSON.parse(s.slice(start));
if (!Array.isArray(entries) || entries.length !== 1) process.exit(1);
console.log(`${entries[0].filename}\t${entries[0].integrity}`);' "$json")" \
    || missing "npm pack printed no single tarball for ${t}"
  IFS=$'\t' read -r file integrity <<< "$packed"
  [[ -f "${PACK_DIR}/${file}" ]] || missing "npm pack named ${PACK_DIR}/${file}, which is not there"
  if ! got="$(tar -xOzf "${PACK_DIR}/${file}" "package/${WASM}" 2>/dev/null | sha256sum | cut -d' ' -f1)"; then
    refuse "pack: ${t} packs ${file} with no ${WASM} in it"
  elif [[ "$got" != "${built[$t]}" ]]; then
    refuse "pack: ${t} packs ${file} with wasm ${got}, but the build emitted ${built[$t]}"
  elif ! line="$(tar -xOzf "${PACK_DIR}/${file}" "package/${RECORD}" 2>/dev/null)"; then
    refuse "pack: ${t} packs ${file} with no ${RECORD} in it"
  elif [[ "${line%%$'\n'*}" != "${built[$t]}  ${WASM}" ]]; then
    refuse "pack: ${t} packs ${file} whose ${RECORD} reads '${line%%$'\n'*}', but the build emitted ${built[$t]}"
  else
    echo "  ok    pack: ${t} packs ${file}, carrying ${built[$t]} and its record"
    printf '%s  %s\n' "$integrity" "$file" >> "${PACK_DIR}/INTEGRITY"
  fi
}

if [[ -n "$PACK_DIR" ]]; then
  command -v npm >/dev/null || missing "npm is required to pack the targets"
  mkdir -p "$PACK_DIR" || missing "cannot create ${PACK_DIR}"
  PACK_DIR="$(cd "$PACK_DIR" && pwd)"
  pack_err="$(mktemp)"
  trap 'rm -f "$pack_err"' EXIT
  : > "${PACK_DIR}/INTEGRITY"
  for t in "${TARGETS[@]}"; do
    pack_target "$t"
  done
  (cd "$PACK_DIR" && awk '{print $2}' INTEGRITY | xargs -r sha256sum -- > SHA256SUMS)
fi

[[ -f "${SDK_DIR}/package.json" ]] || missing "no manifest ${SDK_DIR}/package.json"

# Read from the manifest, not assumed, so the name the SDK imports under is the one resolved.
links="$(node -e '
const path = require("node:path");
const fs = require("node:fs");
const [sdkDir, clientDir, ...targets] = process.argv.slice(1);
const real = (p) => { try { return fs.realpathSync(p); } catch { return null; } };
const byDir = new Map(targets.map((t) => [real(path.join(clientDir, t)), t]));
const manifest = require(path.join(sdkDir, "package.json"));
for (const section of ["dependencies", "devDependencies", "optionalDependencies"]) {
  for (const [dep, spec] of Object.entries(manifest[section] ?? {})) {
    if (typeof spec !== "string" || !spec.startsWith("file:")) continue;
    const target = byDir.get(real(path.resolve(sdkDir, spec.slice(5))));
    if (target) console.log(`${dep}\t${target}`);
  }
}' "$SDK_DIR" "$CLIENT_DIR" "${TARGETS[@]}")" || missing "could not read ${SDK_DIR}/package.json"
[[ -n "$links" ]] || missing "the SDK at ${SDK_DIR} links no client-wasm target through a file: dependency, so there is nothing to compare"

while IFS=$'\t' read -r dep target; do
  # The glue loads the wasm from beside itself, so that is the binary the SDK runs.
  entry="$(node -p 'require.resolve(process.argv[1], { paths: [process.argv[2]] })' "$dep" "$SDK_DIR" 2>&1)" \
    || missing "the SDK does not resolve ${dep}; run pnpm install in ${SDK_DIR} first. ${entry}"
  linked="$(dirname "$entry")/${WASM}"
  [[ -f "$linked" ]] || missing "${dep} resolves to ${entry} with no ${WASM} beside it"
  got="$(sha "$linked")"
  if [[ "$got" != "${built[$target]}" ]]; then
    refuse "linked: ${dep} resolves ${linked} = ${got}, but the build emitted ${target} = ${built[$target]}; reinstall the SDK's dependencies (pnpm install --force)"
  elif ! why="$(record_matches "$(dirname "$linked")" "$got")"; then
    refuse "linked: ${dep} carries the built wasm, but its record does not: ${why}; reinstall the SDK's dependencies (pnpm install --force)"
  else
    echo "  ok    linked: ${dep} resolves ${target}'s wasm, ${got}"
  fi
done <<< "$links"

if (( failed )); then
  echo "check-wasm-identity: the wasm the SDK links is not provably the wasm the build emitted" >&2
  exit 1
fi
echo "check-wasm-identity: every linked wasm is byte-identical to the build output and records its hash"
