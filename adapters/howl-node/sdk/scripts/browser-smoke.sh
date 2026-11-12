#!/usr/bin/env bash
# The Howl client in headless Chromium (browser-smoke/run.ts): a webpack page on the -bundler wasm
# and a Manifest V3 extension's service worker on the -web wasm, each under
# script-src 'self' 'wasm-unsafe-eval', cross-origin to a node following a local anvil chain.
#
#   scripts/browser-smoke.sh              the smoke; both must give the Node build's result
#   scripts/browser-smoke.sh --red-proof  each planted fault must fail it, for its own reason
#
# Needs HOWL_NODE_BIN (a built howl-node), anvil and pnpm on PATH, and the three wasm packages
# (client-wasm/scripts/wasm-build.sh). Exit: 0 held, 1 the smoke or a red proof failed, 3 an
# input is missing.
set -euo pipefail

SDK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SMOKE_DIR="${SDK_DIR}/browser-smoke"
WASM_DIR="${SDK_DIR}/../client-wasm"

[[ -n "${HOWL_NODE_BIN:-}" && -x "${HOWL_NODE_BIN}" ]] || { echo "browser-smoke: HOWL_NODE_BIN must name a built howl-node" >&2; exit 3; }
command -v anvil >/dev/null || { echo "browser-smoke: anvil is required" >&2; exit 3; }
for pkg in pkg-node pkg-bundler pkg-web; do
    [[ -f "${WASM_DIR}/${pkg}/howl_client_wasm_bg.wasm" ]] || { echo "browser-smoke: no ${pkg}; run client-wasm/scripts/wasm-build.sh" >&2; exit 3; }
done

(cd "${SDK_DIR}" && pnpm install --frozen-lockfile && pnpm build)
# its own lockfile, so the published package's stays as it is
(cd "${SMOKE_DIR}" && pnpm install --frozen-lockfile --ignore-workspace)
(cd "${SMOKE_DIR}" && pnpm exec playwright install chromium)

smoke() { (cd "${SMOKE_DIR}" && HOWL_SMOKE_PLANT="$1" pnpm exec tsx run.ts); }

if [[ "${1:-}" != "--red-proof" ]]; then
    smoke ""
    exit
fi

# plant, then what its failure must say
proofs=(
    "csp|SMOKE FAIL page:.*(Content Security Policy|wasm-unsafe-eval|WebAssembly)"
    "csp|SMOKE FAIL worker:.*(Content Security Policy|wasm-unsafe-eval|WebAssembly)"
    "cors|SMOKE FAIL page:.*(Network|fetch)"
    "cors|SMOKE FAIL worker:.*(Network|fetch)"
    "nodewasm|SMOKE FAIL setup: webpack"
)
failed=0
declare -A out
for proof in "${proofs[@]}"; do
    plant="${proof%%|*}"
    want="${proof#*|}"
    if [[ -z "${out[$plant]:-}" ]]; then
        if log="$(smoke "${plant}" 2>&1)"; then
            out[$plant]="PASSED"
        else
            out[$plant]="${log}"
        fi
        printf '%s\n' "${log}" | sed "s/^/  [${plant}] /"
    fi
    if [[ "${out[$plant]}" != "PASSED" ]] && grep -qE "${want}" <<<"${out[$plant]}"; then
        echo "  ok    ${plant}: ${want}"
    else
        echo "  FAIL  ${plant}: expected a failure matching '${want}'" >&2
        failed=1
    fi
done
(( failed == 0 )) || { echo "browser-smoke --red-proof: FAILED" >&2; exit 1; }
echo "browser-smoke --red-proof: every planted fault fails the smoke for its own reason."
