#!/usr/bin/env bash
# Red-proof for check-wasm-identity.sh: a gate ships with proof it can fail, and fails for the
# reason it names.
#
# The central case flips ONE byte of the wasm the SDK links while keeping its size, mtime and
# version string, which is the defect class a size- or version-keyed check cannot see.
#
# Builds its fixtures in a scratch dir and points the gate at them. The real pkg outputs and the
# real SDK are never read or written. Refusal needles start at `FAIL `: without it, the linked
# refusal's text also matches the passing line, so a gate that printed ok and exited 1 for another
# reason would satisfy the case.
set -uo pipefail

ADAPTER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="${ADAPTER_ROOT}/scripts/check-wasm-identity.sh"
WASM=raven_inspire_client_wasm_bg.wasm
RECORD="${WASM}.sha256"
failed=0

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
CLIENT="${work}/client-wasm"
SDK="${work}/sdk"
LINKED="${SDK}/node_modules/@hisoka-io/raven-inspire-client-wasm"
PACK=""

write_pkg() { # dir name type
  local dir="$1" name="$2" type="$3"
  mkdir -p "$dir"
  printf 'module.exports = {};\n' > "${dir}/raven_inspire_client_wasm.js"
  node -e '
const [path, name, type, record] = process.argv.slice(1);
const manifest = { name, version: "0.1.0-alpha.0", files: ["raven_inspire_client_wasm_bg.wasm", "raven_inspire_client_wasm.js", record], main: "raven_inspire_client_wasm.js" };
if (type) manifest.type = type;
require("node:fs").writeFileSync(path, JSON.stringify(manifest, null, 2) + "\n");
' "${dir}/package.json" "$name" "$type" "$RECORD"
}

record() { (cd "$1" && sha256sum "$WASM" > "$RECORD"); }

# In place, so the inode, size and version string survive; the mtime is put back by the caller.
flip_byte() {
  node -e '
const fs = require("node:fs");
const bytes = fs.readFileSync(process.argv[1]);
bytes[100] ^= 0x01;
fs.writeFileSync(process.argv[1], bytes);
' "$1"
}

# A fresh, passing fixture: both targets built from one wasm and recorded, and an SDK whose
# `file:` dependency on pkg-node was installed as a separate copy, the way pnpm materializes it.
seed() {
  rm -rf "$CLIENT" "$SDK"
  write_pkg "${CLIENT}/pkg-node" @hisoka-io/raven-inspire-client-wasm ""
  write_pkg "${CLIENT}/pkg-bundler" @hisoka-io/raven-inspire-client-wasm-bundler module
  head -c 4096 /dev/urandom > "${CLIENT}/pkg-node/${WASM}"
  cp "${CLIENT}/pkg-node/${WASM}" "${CLIENT}/pkg-bundler/${WASM}"
  record "${CLIENT}/pkg-node"
  record "${CLIENT}/pkg-bundler"
  mkdir -p "$(dirname "$LINKED")"
  printf '{"name":"sdk-fixture","private":true,"devDependencies":{"@hisoka-io/raven-inspire-client-wasm":"file:../client-wasm/pkg-node"}}\n' > "${SDK}/package.json"
  cp -r "${CLIENT}/pkg-node" "$LINKED"
}

run_gate() { # logfile
  WASM_IDENTITY_CLIENT_DIR="$CLIENT" WASM_IDENTITY_SDK_DIR="$SDK" WASM_IDENTITY_PACK_DIR="$PACK" \
    "$GATE" >"$1" 2>&1
}

drop_from_files() { # pkg-dir entry
  node -e '
const fs = require("node:fs");
const m = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
m.files = m.files.filter((f) => f !== process.argv[2]);
fs.writeFileSync(process.argv[1], JSON.stringify(m, null, 2) + "\n");
' "$1/package.json" "$2"
}

expect() { # label expected-exit needle
  local label="$1" want="$2" needle="$3" log="${work}/${1// /-}.log" got
  run_gate "$log"
  got=$?
  if [[ "$got" != "$want" ]]; then
    echo "  FAIL  ${label}: expected exit ${want}, got ${got}" >&2
    sed 's/^/        /' "$log" >&2
    failed=1
  elif ! /usr/bin/grep -Fq -- "$needle" "$log"; then
    echo "  FAIL  ${label}: exit ${got}, but not for the reason under test (wanted '${needle}')" >&2
    sed 's/^/        /' "$log" >&2
    failed=1
  else
    echo "  ok    ${label} (exit ${got})"
  fi
}

echo "wasm identity selftest:"

seed
expect "an unmodified fixture passes" 0 "ok    linked: @hisoka-io/raven-inspire-client-wasm resolves pkg-node"

# The case the gate exists for. Size, mtime and version are asserted equal before the gate
# runs, so a red here can only have come from the bytes.
seed
flip_byte "${LINKED}/${WASM}"
touch -r "${CLIENT}/pkg-node/${WASM}" "${LINKED}/${WASM}"
if [[ "$(stat -c '%s %Y' "${LINKED}/${WASM}")" != "$(stat -c '%s %Y' "${CLIENT}/pkg-node/${WASM}")" ]] \
  || ! cmp -s "${LINKED}/package.json" "${CLIENT}/pkg-node/package.json"; then
  echo "  FAIL  the one-byte fixture differs in size, mtime or manifest, so it proves nothing" >&2
  failed=1
fi
expect "one flipped byte in the linked wasm, same size, mtime and version" 1 "FAIL linked: @hisoka-io/raven-inspire-client-wasm resolves"

seed
rm -rf "${LINKED}"
ln -s "${CLIENT}/pkg-node" "$LINKED"
if [[ ! -L "$LINKED" ]]; then
  echo "  FAIL  the linked copy was not replaced by a link to the build output" >&2
  failed=1
fi
expect "a link to the build output itself passes" 0 "ok    linked:"

seed
printf '%s  %s\n' "$(printf '0%.0s' {1..64})" "$WASM" > "${LINKED}/${RECORD}"
expect "the linked copy's record disagrees with its wasm" 1 "FAIL linked: @hisoka-io/raven-inspire-client-wasm carries the built wasm, but its record does not"

seed
rm "${CLIENT}/pkg-node/${RECORD}"
expect "a target with no record" 1 "FAIL record: pkg-node: no ${RECORD}"

seed
flip_byte "${CLIENT}/pkg-bundler/${WASM}"
expect "a record that is not the hash of the wasm beside it" 1 "FAIL record: pkg-bundler: ${RECORD} reads"

seed
drop_from_files "${CLIENT}/pkg-node" "$RECORD"
expect "a record the package would not ship" 1 "FAIL record: pkg-node/package.json \`files\` omits ${RECORD}"

seed
write_pkg "${CLIENT}/pkg-bundler" @hisoka-io/raven-inspire-client-wasm module
expect "two targets under one package name" 1 "FAIL identity: pkg-node and pkg-bundler both publish as @hisoka-io/raven-inspire-client-wasm"

# A bundler target left over from another build: its record is self-consistent, so only the
# cross-target comparison can see it.
seed
flip_byte "${CLIENT}/pkg-bundler/${WASM}"
record "${CLIENT}/pkg-bundler"
expect "a bundler wasm from another build" 1 "FAIL targets: pkg-node wasm"

seed
rm -rf "${SDK}/node_modules"
expect "an SDK that was never installed fails closed" 3 "the SDK does not resolve @hisoka-io/raven-inspire-client-wasm"

# Nothing to compare must not read as identical.
seed
printf '{"name":"sdk-fixture","private":true,"devDependencies":{"@hisoka-io/raven-inspire-client-wasm":"0.1.0-alpha.0"}}\n' > "${SDK}/package.json"
expect "an SDK that links no target fails closed" 3 "links no client-wasm target"

# Pack mode reads the tarball npm actually produces, which `files` only predicts.
PACK="${work}/pack"
seed
rm -rf "$PACK"
expect "packing an unmodified fixture passes" 0 "ok    pack: pkg-bundler packs hisoka-io-raven-inspire-client-wasm-bundler-0.1.0-alpha.0.tgz"
if [[ "$(find "$PACK" -name '*.tgz' | wc -l)" -ne 2 ]] || [[ "$(wc -l < "${PACK}/INTEGRITY")" -ne 2 ]] \
  || ! (cd "$PACK" && sha256sum -c --quiet SHA256SUMS) || [[ "$(wc -l < "${PACK}/SHA256SUMS")" -ne 2 ]]; then
  echo "  FAIL  a passing pack did not leave two tarballs listed in SHA256SUMS and INTEGRITY" >&2
  failed=1
fi

# A `files` that drops the binary passes every directory check; only the tarball shows it.
seed
rm -rf "$PACK"
drop_from_files "${CLIENT}/pkg-node" "$WASM"
expect "a package that would ship without its wasm" 1 "FAIL pack: pkg-node packs hisoka-io-raven-inspire-client-wasm-0.1.0-alpha.0.tgz with no ${WASM} in it"

seed
rm -rf "$PACK"
drop_from_files "${CLIENT}/pkg-bundler" "$RECORD"
expect "a tarball without the record" 1 "FAIL pack: pkg-bundler packs hisoka-io-raven-inspire-client-wasm-bundler-0.1.0-alpha.0.tgz with no ${RECORD} in it"
PACK=""

if [[ "$failed" -ne 0 ]]; then
  echo "check-wasm-identity-selftest.sh: FAILED - the gate does not catch what it claims." >&2
  exit 1
fi
echo "check-wasm-identity-selftest.sh: the gate fires on every case it claims, each for its own reason."
