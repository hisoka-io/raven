#!/usr/bin/env bash
# Builds the Howl client's three wasm-pack targets, finishes each as a publishable npm package, and
# runs the gzipped size gate on all three.
#
#   scripts/wasm-build.sh          release builds
#   scripts/wasm-build.sh --dev    dev builds (faster, larger)
#
# Outputs, one wasm in three loaders:
#   pkg-node/     --target nodejs   @hisoka-io/howl-client-wasm
#   pkg-bundler/  --target bundler  @hisoka-io/howl-client-wasm-bundler
#   pkg-web/      --target web      @hisoka-io/howl-client-wasm-web (initSync; MV3 service workers)
#
# wasm-pack names every target after the crate, so without the rename three packages with different
# glue would share one name and version. Each carries the repository's LICENSE, this crate's README
# and howl_client_wasm_bg.wasm.sha256 in `sha256sum -c` format.
#
# Exit: 0 built, finished and under the ceiling; 1 a build failed; 2 over the ceiling; 3 a target
# produced no wasm, or a package carries a local path.
set -euo pipefail

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${CRATE_DIR}/../../.." && pwd)"
LICENSE_FILE="${REPO_ROOT}/LICENSE"
WASM=howl_client_wasm_bg.wasm
NPM_NAME=@hisoka-io/howl-client-wasm
# A prerelease must publish under a dist-tag other than latest.
NPM_TAG=alpha

PROFILE_FLAG="--release"
[[ "${1:-}" == "--dev" ]] && PROFILE_FLAG="--dev"

# wasm-pack walks parent directories for a workspace root; this crate is its own.
cd "${CRATE_DIR}"

# Panic locations embed source paths; a published binary must not carry the build machine's.
SYSROOT="$(rustc --print sysroot)"
CARGO_HOME_DIR="${CARGO_HOME:-${HOME}/.cargo}"
# The remap changes every artifact, so it builds apart from unremapped builds.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${CRATE_DIR}/target}/remapped"
export RUSTFLAGS="${RUSTFLAGS:+${RUSTFLAGS} }--remap-path-prefix=${REPO_ROOT}=raven --remap-path-prefix=${CARGO_HOME_DIR}=cargo --remap-path-prefix=${SYSROOT}=rust"

for pair in nodejs:pkg-node bundler:pkg-bundler web:pkg-web; do
    target="${pair%%:*}"
    out="${pair#*:}"
    echo "==> wasm-pack build --target ${target} ${PROFILE_FLAG}"
    wasm-pack build "${PROFILE_FLAG}" --target "${target}" --scope hisoka-io \
        --out-dir "${out}" --out-name howl_client_wasm || {
        echo "ERROR: wasm-pack ${target} build failed" >&2
        exit 1
    }
done

finish_package() { # pkg_dir npm_name build_label
    local dir="${CRATE_DIR}/$1"
    [[ -f "${dir}/${WASM}" ]] || { echo "ERROR: ${dir} has no ${WASM}" >&2; exit 3; }
    local leaked
    leaked="$(LC_ALL=C grep -rlaF -e "${REPO_ROOT}" -e "${HOME}" -e "/home/" "${dir}" || true)"
    [[ -z "${leaked}" ]] || { echo "ERROR: ${leaked//$'\n'/, } carries a local path" >&2; exit 3; }
    (cd "${dir}" && sha256sum "${WASM}" > "${WASM}.sha256")
    cp "${LICENSE_FILE}" "${dir}/LICENSE"
    cp "${CRATE_DIR}/README.md" "${dir}/README.md"
    node -e '
const fs = require("node:fs");
const path = require("node:path");
const [manifestPath, name, tag, record, label] = process.argv.slice(1);
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
manifest.name = name;
manifest.description = `${manifest.description} (${label} build)`;
// wasm-pack lists ./snippets/* whether or not the crate emits snippets.
if (Array.isArray(manifest.sideEffects)) {
  const snippets = fs.existsSync(path.join(path.dirname(manifestPath), "snippets"));
  manifest.sideEffects = manifest.sideEffects.filter((entry) => snippets || !entry.startsWith("./snippets/"));
}
manifest.repository = { type: "git", url: "git+https://github.com/hisoka-io/raven.git", directory: "adapters/howl-node/client-wasm" };
manifest.homepage = "https://github.com/hisoka-io/raven";
manifest.publishConfig = { access: "public", tag };
if (Array.isArray(manifest.files) && !manifest.files.includes(record)) manifest.files.push(record);
fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
' "${dir}/package.json" "$2" "${NPM_TAG}" "${WASM}.sha256" "$3"
    echo "==> $1: $(node -p 'require(process.argv[1]).name' "${dir}/package.json"), $(cut -d' ' -f1 "${dir}/${WASM}.sha256")"
}

finish_package pkg-node "${NPM_NAME}" Node
finish_package pkg-bundler "${NPM_NAME}-bundler" bundler
finish_package pkg-web "${NPM_NAME}-web" web

"${CRATE_DIR}/scripts/check-wasm-size.sh" --no-build
"${CRATE_DIR}/scripts/check-packages.sh"
