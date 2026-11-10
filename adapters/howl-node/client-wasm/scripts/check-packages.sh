#!/usr/bin/env bash
# Checks the three finished packages (scripts/wasm-build.sh) are what a registry should serve: three
# names at one version, the repository's LICENSE byte for byte, a README, a wasm its .sha256 record
# matches, repository.directory, no build-machine path, Howl's export surface and nothing more, and a
# tarball holding exactly the files listed below.
#
#   scripts/check-packages.sh   HOWL_PKG_ROOT overrides where pkg-node/, pkg-bundler/, pkg-web/ live
#
# Exit: 0 all hold, 1 a check refused, 3 an input is missing.
set -uo pipefail

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG_ROOT="${HOWL_PKG_ROOT:-${CRATE_DIR}}"
LICENSE_FILE="${HOWL_LICENSE_FILE:-${CRATE_DIR}/../../../LICENSE}"
WASM=howl_client_wasm_bg.wasm
NAMES=(pkg-node:@hisoka-io/howl-client-wasm pkg-bundler:@hisoka-io/howl-client-wasm-bundler pkg-web:@hisoka-io/howl-client-wasm-web)
# The JS surface of lib.rs and lean.rs. A name from a linked crate showing up here means that
# crate's exports reached this cdylib.
EXPORTS="HowlAnswer HowlBatch HowlCells HowlClient HowlTree blockNode decodeAnswer foldPath initPanicHook merklePath treeRoot wireConstants"
# What the web loader adds: its initialisers (the default export is __wbg_init) and their types.
WEB_EXPORTS="InitInput InitOutput SyncInitInput __wbg_init initSync"
COMMON_FILES="LICENSE README.md howl_client_wasm.d.ts howl_client_wasm.js ${WASM} ${WASM}.sha256 package.json"
BUNDLER_FILES="howl_client_wasm_bg.js"

failed=0
refuse() { echo "check-packages: FAIL $*" >&2; failed=1; }
missing() { echo "check-packages: $*" >&2; exit 3; }
command -v node >/dev/null || missing "node is required"
command -v npm >/dev/null || missing "npm is required"
[[ -f "${LICENSE_FILE}" ]] || missing "no LICENSE at ${LICENSE_FILE}"

sorted() { tr ' ' '\n' <<<"$*" | sed '/^$/d' | LC_ALL=C sort | tr '\n' ' '; }

version=
declare -A seen
for pair in "${NAMES[@]}"; do
    out="${pair%%:*}"
    want_name="${pair#*:}"
    dir="${PKG_ROOT}/${out}"
    [[ -f "${dir}/${WASM}" && -f "${dir}/package.json" ]] || missing "no finished package in ${dir}"

    name="$(node -p 'require(process.argv[1]).name' "${dir}/package.json")"
    ver="$(node -p 'require(process.argv[1]).version' "${dir}/package.json")"
    repo_dir="$(node -p 'require(process.argv[1]).repository?.directory ?? ""' "${dir}/package.json")"
    [[ "$name" == "$want_name" ]] || refuse "${out} is named ${name}, not ${want_name}"
    [[ -z "${seen[$name]:-}" ]] || refuse "${out} and ${seen[$name]} share the name ${name}"
    seen[$name]="$out"
    [[ -z "$version" || "$ver" == "$version" ]] || refuse "${out} is at ${ver}, another target at ${version}"
    version="$ver"
    [[ "$repo_dir" == "adapters/howl-node/client-wasm" ]] || refuse "${out} repository.directory is '${repo_dir}'"

    cmp -s "${LICENSE_FILE}" "${dir}/LICENSE" || refuse "${out}/LICENSE is not the repository's LICENSE"
    [[ -s "${dir}/README.md" ]] || refuse "${out} has no README.md"
    (cd "${dir}" && sha256sum -c --quiet "${WASM}.sha256" >/dev/null 2>&1) || refuse "${out}: sha256sum -c ${WASM}.sha256 does not pass"
    leaked="$(LC_ALL=C grep -rlaF "/home/" "${dir}" 2>/dev/null || true)"
    [[ -z "${leaked}" ]] || refuse "${out} carries a /home/ path in ${leaked//$'\n'/, }"

    got="$(sorted "$(sed -nE 's/^export (declare )?(function|class|const|type|interface|default function) ([A-Za-z_][A-Za-z0-9_]*).*/\3/p' "${dir}/howl_client_wasm.d.ts")")"
    want="${EXPORTS}"
    [[ "$out" == pkg-web ]] && want="${EXPORTS} ${WEB_EXPORTS}"
    [[ "$got" == "$(sorted "$want")" ]] || refuse "${out} exports [${got% }], Howl's surface is [$(sorted "$want" | sed 's/ $//')]"

    files="${COMMON_FILES}"
    [[ "$out" == pkg-bundler ]] && files="${COMMON_FILES} ${BUNDLER_FILES}"
    packed="$(cd "${dir}" && npm pack --dry-run --json --ignore-scripts 2>/dev/null \
        | node -e 'let s = ""; process.stdin.on("data", (d) => (s += d)).on("end", () =>
            console.log(JSON.parse(s)[0].files.map((f) => f.path).join(" ")))')" \
        || refuse "${out}: npm pack --dry-run failed"
    [[ "$(sorted "$packed")" == "$(sorted "$files")" ]] \
        || refuse "${out} packs [$(sorted "$packed" | sed 's/ $//')], expected [$(sorted "$files" | sed 's/ $//')]"
    echo "  ok    ${out}: ${name}@${ver}, $(cut -d' ' -f1 "${dir}/${WASM}.sha256")"
done

if [[ "$failed" -ne 0 ]]; then
    echo "check-packages.sh: FAILED" >&2
    exit 1
fi
echo "check-packages.sh: three packages, one version, each finished."
