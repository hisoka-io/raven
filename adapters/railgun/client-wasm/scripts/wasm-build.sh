#!/usr/bin/env bash
# Build the dual wasm-pack targets (Node + bundler) and assert the
# gzipped wasm bundle stays under 500 KB. Run from anywhere; uses
# absolute paths so the working directory is irrelevant.
#
# Usage:
#   scripts/wasm-build.sh              # release builds (default)
#   scripts/wasm-build.sh --dev        # dev builds (faster, larger)
#
# Outputs:
#   pkg-node/      (wasm-pack --target nodejs)
#   pkg-bundler/   (wasm-pack --target bundler)
#
# Exit codes:
#   0 = both targets built and bundle <= 500 KB gzipped
#   1 = build failure
#   2 = bundle size gate exceeded

set -euo pipefail

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PROFILE_FLAG="--release"
if [[ "${1:-}" == "--dev" ]]; then
    PROFILE_FLAG="--dev"
fi

MAX_GZIP_BYTES=512000

# wasm-pack walks parent directories looking for a workspace root.
# This crate is intentionally outside the parent adapter workspace
# (so its `getrandom = ["js"]` enable doesn't feature-unify into
# native builds), so we must cd into the crate's own directory before
# invoking wasm-pack to keep it from picking up the rave root
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

WASM_NODE="${CRATE_DIR}/pkg-node/raven_inspire_client_wasm_bg.wasm"
WASM_BUNDLER="${CRATE_DIR}/pkg-bundler/raven_inspire_client_wasm_bg.wasm"

GZ_NODE_BYTES=$(gzip -c "${WASM_NODE}" | wc -c)
GZ_BUNDLER_BYTES=$(gzip -c "${WASM_BUNDLER}" | wc -c)

printf "\n==> Bundle sizes (gzipped)\n"
printf "  pkg-node    : %s bytes (%.1f KB)\n"  "${GZ_NODE_BYTES}"     "$(echo "${GZ_NODE_BYTES} / 1024" | bc -l)"
printf "  pkg-bundler : %s bytes (%.1f KB)\n"  "${GZ_BUNDLER_BYTES}"  "$(echo "${GZ_BUNDLER_BYTES} / 1024" | bc -l)"
printf "  ceiling     : %s bytes (%.1f KB)\n"  "${MAX_GZIP_BYTES}"    "$(echo "${MAX_GZIP_BYTES} / 1024" | bc -l)"

if (( GZ_NODE_BYTES > MAX_GZIP_BYTES )) || (( GZ_BUNDLER_BYTES > MAX_GZIP_BYTES )); then
    echo "ERROR: gzipped wasm bundle exceeds 500 KB ceiling" >&2
    exit 2
fi

echo "OK: both bundles under ceiling."
