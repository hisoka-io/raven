#!/usr/bin/env bash
# Build the dual wasm-pack targets (Node + bundler), finish each as a publishable npm package with
# its wasm's sha256 recorded, and run the gzipped bundle-size gate. Run from anywhere; uses absolute
# paths so the working directory is irrelevant.
#
# Usage:
#   scripts/wasm-build.sh              # release builds (default)
#   scripts/wasm-build.sh --dev        # dev builds (faster, larger)
#
# Outputs:
#   pkg-node/      (wasm-pack --target nodejs), published as @hisoka-io/raven-inspire-client-wasm
#   pkg-bundler/   (wasm-pack --target bundler), published as @hisoka-io/raven-inspire-client-wasm-bundler
#
# wasm-pack names both targets after the crate, so without the rename two packages with different
# glue would share one name and version. Each carries the repository's LICENSE, the crate README and
# raven_inspire_client_wasm_bg.wasm.sha256 in `sha256sum -c` format;
# scripts/check-wasm-identity.sh holds the copy a consumer links to it.
#
# Exit codes:
#   0 = both targets built, recorded, and under the ceiling
#   1 = build failure
#   2 = bundle size gate exceeded
#   3 = a target produced no wasm, or a package carries a local path

set -euo pipefail

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIZE_GATE="${CRATE_DIR}/../scripts/check-wasm-bundle-size.sh"
REPO_ROOT="$(cd "${CRATE_DIR}/../../.." && pwd)"
LICENSE_FILE="${REPO_ROOT}/LICENSE"
WASM=raven_inspire_client_wasm_bg.wasm
NPM_NAME=@hisoka-io/raven-inspire-client-wasm
# A prerelease must publish under a dist-tag other than latest.
NPM_TAG=alpha

PROFILE_FLAG="--release"
if [[ "${1:-}" == "--dev" ]]; then
    PROFILE_FLAG="--dev"
fi

# wasm-pack walks parent directories looking for a workspace root.
# This crate is intentionally outside the parent adapter workspace
# (so its `getrandom = ["js"]` enable doesn't feature-unify into
# native builds), so we must cd into the crate's own directory before
# invoking wasm-pack to keep it from picking up the workspace root
# Cargo.toml.
cd "${CRATE_DIR}"

# Panic locations embed source paths; a published binary must not carry the build machine's.
SYSROOT="$(rustc --print sysroot)"
CARGO_HOME_DIR="${CARGO_HOME:-${HOME}/.cargo}"
# The remap changes every artifact, so it builds in its own target dir, apart from unremapped builds.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${CRATE_DIR}/target}/remapped"
export RUSTFLAGS="${RUSTFLAGS:+${RUSTFLAGS} }--remap-path-prefix=${REPO_ROOT}=raven --remap-path-prefix=${CARGO_HOME_DIR}=cargo --remap-path-prefix=${SYSROOT}=rust"

echo "==> wasm-pack build --target nodejs ${PROFILE_FLAG}"
wasm-pack build "${PROFILE_FLAG}" \
    --target nodejs \
    --out-dir pkg-node

echo "==> wasm-pack build --target bundler ${PROFILE_FLAG}"
wasm-pack build "${PROFILE_FLAG}" \
    --target bundler \
    --out-dir pkg-bundler

finish_package() { # pkg_dir npm_name
    local dir="${CRATE_DIR}/$1"
    [[ -f "${dir}/${WASM}" ]] || { echo "ERROR: ${dir} has no ${WASM}" >&2; exit 3; }
    local leaked
    leaked="$(LC_ALL=C grep -rlaF -e "${REPO_ROOT}" -e "${HOME}" "${dir}" || true)"
    [[ -z "${leaked}" ]] || { echo "ERROR: ${leaked//$'\n'/, } carries a local path" >&2; exit 3; }
    (cd "${dir}" && sha256sum "${WASM}" > "${WASM}.sha256")
    cp "${LICENSE_FILE}" "${dir}/LICENSE"
    node -e '
const fs = require("node:fs");
const [manifestPath, name, tag, record] = process.argv.slice(1);
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
manifest.name = name;
manifest.repository = { type: "git", url: "git+https://github.com/hisoka-io/raven.git", directory: "adapters/railgun/client-wasm" };
manifest.homepage = "https://github.com/hisoka-io/raven";
manifest.publishConfig = { access: "public", tag };
if (Array.isArray(manifest.files) && !manifest.files.includes(record)) manifest.files.push(record);
fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
' "${dir}/package.json" "$2" "${NPM_TAG}" "${WASM}.sha256"
    echo "==> $1: $(node -p 'require(process.argv[1]).name' "${dir}/package.json"), $(cut -d' ' -f1 "${dir}/${WASM}.sha256")"
}

finish_package pkg-node "${NPM_NAME}"
finish_package pkg-bundler "${NPM_NAME}-bundler"

# One ceiling, owned by the size gate, which weighs the JS glue as well as the wasm.
"${SIZE_GATE}" --no-build
