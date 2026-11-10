#!/usr/bin/env bash
# Red proof for check-packages.sh: copies of the three finished packages pass, and each planted
# fault is refused with its own exit code. Run after scripts/wasm-build.sh.
set -uo pipefail

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="${CRATE_DIR}/scripts/check-packages.sh"
WASM=howl_client_wasm_bg.wasm
for out in pkg-node pkg-bundler pkg-web; do
    [[ -f "${CRATE_DIR}/${out}/${WASM}" ]] || { echo "check-packages selftest: no ${out}; run scripts/wasm-build.sh" >&2; exit 3; }
done
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failed=0

fresh() {
    rm -rf "${work:?}/pkgs"
    mkdir -p "$work/pkgs"
    for out in pkg-node pkg-bundler pkg-web; do cp -R "${CRATE_DIR}/${out}" "$work/pkgs/${out}"; done
}
check() { # want_exit label
    local rc=0
    HOWL_PKG_ROOT="$work/pkgs" "$GATE" >"$work/log" 2>&1 || rc=$?
    if [[ "$rc" -eq "$1" ]]; then
        echo "  ok    $2 (exit $rc)"
    else
        echo "  FAIL  $2: exit $rc, wanted $1" >&2
        sed 's/^/        /' "$work/log" >&2
        failed=1
    fi
}
manifest() { # pkg js-expression over m
    node -e 'const fs = require("node:fs"); const p = process.argv[1]; const m = JSON.parse(fs.readFileSync(p, "utf8")); '"$2"'; fs.writeFileSync(p, JSON.stringify(m, null, 2));' "$work/pkgs/$1/package.json"
}

echo "check-packages selftest:"
fresh
check 0 "the three packages as built pass"
fresh
printf '\n// built in /home/ci/raven\n' >>"$work/pkgs/pkg-web/howl_client_wasm.js"
check 1 "a build-machine path in the glue is refused"
fresh
printf '\n' >>"$work/pkgs/pkg-node/LICENSE"
check 1 "a LICENSE that is not the repository's is refused"
fresh
printf '\0' >>"$work/pkgs/pkg-bundler/${WASM}"
check 1 "a wasm its sha256 record does not match is refused"
fresh
manifest pkg-bundler 'm.name = "@hisoka-io/howl-client-wasm"'
check 1 "two targets under one name are refused"
fresh
manifest pkg-web 'm.version = "0.0.0"'
check 1 "targets at two versions are refused"
fresh
manifest pkg-node 'delete m.repository.directory'
check 1 "a missing repository.directory is refused"
fresh
printf 'export function serialize_client_session(session: ClientSessionHandle): Uint8Array;\n' >>"$work/pkgs/pkg-node/howl_client_wasm.d.ts"
check 1 "a linked crate's export reaching the package is refused"
fresh
manifest pkg-node 'm.files.push("notes.txt")'
echo x >"$work/pkgs/pkg-node/notes.txt"
check 1 "a file outside the package's list is refused"
fresh
rm -rf "$work/pkgs/pkg-web"
check 3 "a missing target fails closed"

if [[ "$failed" -ne 0 ]]; then
    echo "check-packages-selftest.sh: FAILED" >&2
    exit 1
fi
echo "check-packages-selftest.sh: every planted fault refused."
