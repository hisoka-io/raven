#!/usr/bin/env bash
# Shows check-wasm-size.sh fails on what it claims to catch, on scratch copies of the outputs.
set -uo pipefail

GATE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check-wasm-size.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/scripts" "$work/pkg-node" "$work/pkg-bundler"
cp "$GATE" "$work/scripts/gate.sh"
failed=0

check() { # expected name
    local got
    "$work/scripts/gate.sh" --no-build >/dev/null 2>&1
    got=$?
    if [[ "$got" == "$1" ]]; then
        echo "  ok    $2 (exit $got)"
    else
        echo "  FAIL  $2: expected exit $1, got $got" >&2
        failed=1
    fi
}

# Random bytes barely compress, so their gzipped size is about their size.
seed() { # dir wasm_bytes js_bytes
    head -c "$2" /dev/urandom > "$1/howl_client_wasm_bg.wasm"
    head -c "$3" /dev/urandom > "$1/howl_client_wasm.js"
}

echo "wasm size gate selftest:"
seed "$work/pkg-node" 60000 4000
seed "$work/pkg-bundler" 60000 4000
check 0 "two small targets pass"
seed "$work/pkg-node" 300000 4000
check 2 "an oversized node wasm is refused"
seed "$work/pkg-node" 60000 4000
seed "$work/pkg-bundler" 60000 300000
check 2 "oversized bundler glue is refused though its wasm is small"
seed "$work/pkg-bundler" 60000 4000
mkdir -p "$work/pkg-node/snippets/howl-client-wasm"
head -c 300000 /dev/urandom > "$work/pkg-node/snippets/howl-client-wasm/inline.js"
check 2 "oversized JS under snippets/ is weighed"
rm -rf "$work/pkg-node/snippets"
rm -f "$work/pkg-bundler/howl_client_wasm_bg.wasm"
check 3 "a missing wasm fails closed, not as zero bytes"

if [[ "$failed" -ne 0 ]]; then
    echo "check-wasm-size-selftest.sh: FAILED" >&2
    exit 1
fi
echo "check-wasm-size-selftest.sh: the gate fires on every case it claims."
