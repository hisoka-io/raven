#!/usr/bin/env bash
# Builds the Howl client's two wasm-pack targets (Node and bundler) and fails when either ships more
# than the ceiling, gzipped. A target ships its .wasm and every .js wasm-pack emits for it, snippets
# included; .d.ts and package.json never reach a browser and are not weighed.
#
#   scripts/check-wasm-size.sh             build both targets, then check
#   scripts/check-wasm-size.sh --no-build  check pkg-node/ and pkg-bundler/ as they are
#
# Exit: 0 under the ceiling, 1 a build failed, 2 over the ceiling, 3 an output is missing.
set -euo pipefail

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 168,279 B (node) and 168,315 B (bundler) when set; the rest is headroom for the next features.
MAX_GZIP_BYTES=256000

if [[ "${1:-}" != "--no-build" ]]; then
    for target in nodejs bundler; do
        out=pkg-node
        [[ $target == bundler ]] && out=pkg-bundler
        (cd "${CRATE_DIR}" && wasm-pack build --release --target "${target}" --scope hisoka-io \
            --out-dir "${out}" --out-name howl_client_wasm) || {
            echo "ERROR: wasm-pack ${target} build failed" >&2
            exit 1
        }
    done
fi

shipped_gzip_bytes() { # pkg_dir
    local total=0 f
    while IFS= read -r f; do
        total=$(( total + $(gzip -c "${f}" | wc -c) ))
    done < <(find "$1" -type f \( -name '*.wasm' -o -name '*.js' \) | sort)
    echo "${total}"
}

failed=0
for out in pkg-node pkg-bundler; do
    dir="${CRATE_DIR}/${out}"
    if [[ ! -f "${dir}/howl_client_wasm_bg.wasm" ]]; then
        echo "ERROR: missing wasm output ${dir}/howl_client_wasm_bg.wasm" >&2
        exit 3
    fi
    size=$(shipped_gzip_bytes "${dir}")
    printf '%-12s %8s B gzipped, ceiling %s B, %s B left\n' \
        "${out}" "${size}" "${MAX_GZIP_BYTES}" "$(( MAX_GZIP_BYTES - size ))"
    if (( size > MAX_GZIP_BYTES )); then
        echo "FAIL: ${out} ships ${size} B gzipped, over the ${MAX_GZIP_BYTES} B ceiling" >&2
        failed=1
    fi
done
(( failed == 0 )) || exit 2
echo "OK: both targets under the ceiling."
