#!/usr/bin/env bash
# Build the dual wasm-pack targets (Node + bundler), record each wasm's sha256 in the package that
# ships it, and run the gzipped bundle-size gate. Run from anywhere; uses absolute paths so the
# working directory is irrelevant.
#
# Usage:
#   scripts/wasm-build.sh              # release builds (default)
#   scripts/wasm-build.sh --dev        # dev builds (faster, larger)
#
# Outputs:
#   pkg-node/      (wasm-pack --target nodejs), published as <crate name>
#   pkg-bundler/   (wasm-pack --target bundler), published as <crate name>-bundler
#
# wasm-pack names both targets after the crate, so without the rename two packages with different
# glue would share one name and version. Each carries raven_inspire_client_wasm_bg.wasm.sha256 in
# `sha256sum -c` format; scripts/check-wasm-identity.sh holds the copy a consumer links to it.
#
# Exit codes:
#   0 = both targets built, recorded, and under the ceiling
#   1 = build failure
#   2 = bundle size gate exceeded
#   3 = a target produced no wasm

set -euo pipefail

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIZE_GATE="${CRATE_DIR}/../scripts/check-wasm-bundle-size.sh"
WASM=raven_inspire_client_wasm_bg.wasm

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

echo "==> wasm-pack build --target nodejs ${PROFILE_FLAG}"
wasm-pack build "${PROFILE_FLAG}" \
    --target nodejs \
    --out-dir pkg-node

echo "==> wasm-pack build --target bundler ${PROFILE_FLAG}"
wasm-pack build "${PROFILE_FLAG}" \
    --target bundler \
    --out-dir pkg-bundler

record_identity() { # pkg_dir name_suffix
    local dir="${CRATE_DIR}/$1"
    [[ -f "${dir}/${WASM}" ]] || { echo "ERROR: ${dir} has no ${WASM}" >&2; exit 3; }
    (cd "${dir}" && sha256sum "${WASM}" > "${WASM}.sha256")
    node -e '
const fs = require("node:fs");
const [manifestPath, suffix, record] = process.argv.slice(1);
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
if (suffix && !manifest.name.endsWith(suffix)) manifest.name += suffix;
if (Array.isArray(manifest.files) && !manifest.files.includes(record)) manifest.files.push(record);
fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
' "${dir}/package.json" "$2" "${WASM}.sha256"
    echo "==> $1: $(node -p 'require(process.argv[1]).name' "${dir}/package.json"), $(cut -d' ' -f1 "${dir}/${WASM}.sha256")"
}

record_identity pkg-node ""
record_identity pkg-bundler "-bundler"

# One ceiling, owned by the size gate, which weighs the JS glue as well as the wasm.
"${SIZE_GATE}" --no-build
