#!/usr/bin/env bash
# CI gate: ensure both wasm-pack target outputs (Node + bundler) for
# raven-inspire-client-wasm stay below the 500 KB gzipped ceiling.
#
# Builds both targets if the pkg outputs are missing or stale, then
# fails the build with a non-zero exit code if either exceeds the
# ceiling. Invoke from anywhere; uses absolute paths so the working
# directory is irrelevant.
#
# Usage:
#   scripts/check-wasm-bundle-size.sh           # full build + size check
#   scripts/check-wasm-bundle-size.sh --no-build # size check only
#                                                # (assumes pkg-* exist)
#
# Exit codes:
#   0 = both bundles built and below the ceiling
#   1 = build invocation failed
#   2 = ceiling exceeded by at least one bundle
#   3 = pkg output missing under --no-build mode

set -euo pipefail

# Resolve the SDK + WASM crate paths relative to this script's location.
# Script lives at adapters/railgun/scripts/, so its parent is the
# adapter root (adapters/railgun/).
ADAPTER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WASM_CRATE_DIR="${ADAPTER_ROOT}/client-wasm"
PKG_NODE_DIR="${WASM_CRATE_DIR}/pkg-node"
PKG_BUNDLER_DIR="${WASM_CRATE_DIR}/pkg-bundler"

# Single source of truth for the size ceiling. 500 KB == 512000 bytes.
MAX_GZIP_BYTES=512000

DO_BUILD=1
if [[ "${1:-}" == "--no-build" ]]; then
    DO_BUILD=0
fi

if (( DO_BUILD == 1 )); then
    echo "==> wasm-pack build --target nodejs --release"
    (cd "${WASM_CRATE_DIR}" && wasm-pack build --release --target nodejs --out-dir pkg-node) || {
        echo "ERROR: wasm-pack nodejs build failed" >&2
        exit 1
    }

    echo "==> wasm-pack build --target bundler --release"
    (cd "${WASM_CRATE_DIR}" && wasm-pack build --release --target bundler --out-dir pkg-bundler) || {
        echo "ERROR: wasm-pack bundler build failed" >&2
        exit 1
    }
fi

WASM_NODE_FILE="${PKG_NODE_DIR}/raven_inspire_client_wasm_bg.wasm"
WASM_BUNDLER_FILE="${PKG_BUNDLER_DIR}/raven_inspire_client_wasm_bg.wasm"

for f in "${WASM_NODE_FILE}" "${WASM_BUNDLER_FILE}"; do
    if [[ ! -f "${f}" ]]; then
        echo "ERROR: missing wasm output ${f}" >&2
        exit 3
    fi
done

GZ_NODE_BYTES=$(gzip -c "${WASM_NODE_FILE}" | wc -c)
GZ_BUNDLER_BYTES=$(gzip -c "${WASM_BUNDLER_FILE}" | wc -c)

printf "\n==> WASM bundle sizes (gzipped)\n"
printf "  pkg-node    : %s bytes (%.1f KB)\n"  "${GZ_NODE_BYTES}"     "$(echo "${GZ_NODE_BYTES} / 1024" | bc -l)"
printf "  pkg-bundler : %s bytes (%.1f KB)\n"  "${GZ_BUNDLER_BYTES}"  "$(echo "${GZ_BUNDLER_BYTES} / 1024" | bc -l)"
printf "  ceiling     : %s bytes (%.1f KB)\n"  "${MAX_GZIP_BYTES}"    "$(echo "${MAX_GZIP_BYTES} / 1024" | bc -l)"

failed=0
if (( GZ_NODE_BYTES > MAX_GZIP_BYTES )); then
    echo "FAIL: pkg-node bundle exceeds ${MAX_GZIP_BYTES} byte ceiling" >&2
    failed=1
fi
if (( GZ_BUNDLER_BYTES > MAX_GZIP_BYTES )); then
    echo "FAIL: pkg-bundler bundle exceeds ${MAX_GZIP_BYTES} byte ceiling" >&2
    failed=1
fi

if (( failed == 1 )); then
    exit 2
fi

echo "OK: both wasm bundles under ceiling."
