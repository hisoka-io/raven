#!/usr/bin/env bash
# Red-proof for check-wasm-bundle-size.sh: a gate ships with proof it can fail.
#
# The gate had never been observed failing. It also measured only `_bg.wasm`, and the two
# targets emit a byte-identical one, so "both bundles under ceiling" was a single measurement
# reported twice while the per-target JS glue went unmeasured entirely.
#
# Runs against copies in a scratch dir. The real pkg outputs are never modified.
set -uo pipefail

ADAPTER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="${ADAPTER_ROOT}/scripts/check-wasm-bundle-size.sh"
failed=0

check() { # expected actual name
  if [[ "$1" == "$2" ]]; then
    echo "  ok    $3 (exit $2)"
  else
    echo "  FAIL  $3: expected exit $1, got $2" >&2
    failed=1
  fi
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# A scratch adapter root the gate can be pointed at, with its own pkg dirs.
mkdir -p "$work/scripts" "$work/client-wasm/pkg-node" "$work/client-wasm/pkg-bundler"
sed 's|^ADAPTER_ROOT=.*|ADAPTER_ROOT="'"$work"'"|' "$GATE" > "$work/scripts/gate.sh"
chmod +x "$work/scripts/gate.sh"

seed_pkg() { # dir wasm_bytes js_bytes
  head -c "$2" /dev/urandom > "$1/raven_inspire_client_wasm_bg.wasm"
  head -c "$3" /dev/urandom > "$1/raven_inspire_client_wasm.js"
}

run_gate() { ( "$work/scripts/gate.sh" --no-build >/dev/null 2>&1; echo $?; ); }
gate_stderr() { ( "$work/scripts/gate.sh" --no-build 2>&1 >/dev/null; ); }

echo "wasm bundle-size selftest:"

# Random bytes barely compress, so ~60 KB of urandom is ~60 KB gzipped: comfortably under.
seed_pkg "$work/client-wasm/pkg-node" 60000 4000
seed_pkg "$work/client-wasm/pkg-bundler" 60000 4000
check 0 "$(run_gate)" "two small bundles pass"

# Over the ceiling on ONE target only, which the old single-artifact form could not express.
seed_pkg "$work/client-wasm/pkg-node" 600000 4000
check 2 "$(run_gate)" "an oversized node bundle is refused"
seed_pkg "$work/client-wasm/pkg-node" 60000 4000

seed_pkg "$work/client-wasm/pkg-bundler" 600000 4000
check 2 "$(run_gate)" "an oversized bundler bundle is refused"
seed_pkg "$work/client-wasm/pkg-bundler" 60000 4000

# The glue alone crossing the ceiling. Under the old form this was invisible: the wasm was
# the only thing weighed, so unbounded JS growth could never fail the gate.
seed_pkg "$work/client-wasm/pkg-bundler" 60000 600000
check 2 "$(run_gate)" "oversized JS glue is refused even when the wasm is small"
seed_pkg "$work/client-wasm/pkg-bundler" 60000 4000

# A missing output must fail closed rather than measure zero and pass.
rm -f "$work/client-wasm/pkg-node/raven_inspire_client_wasm_bg.wasm"
check 3 "$(run_gate)" "a missing wasm output fails closed, not as 0 bytes"
seed_pkg "$work/client-wasm/pkg-node" 60000 4000

# JS glue nested under snippets/, which wasm-pack emits for a crate using JS snippets. A flat
# glob weighs none of it, so this case fails only because the scan is recursive.
mkdir -p "$work/client-wasm/pkg-bundler/snippets/raven-inspire-client-wasm"
head -c 600000 /dev/urandom > "$work/client-wasm/pkg-bundler/snippets/raven-inspire-client-wasm/inline.js"
check 2 "$(run_gate)" "oversized JS under snippets/ is weighed, not skipped"
rm -rf "$work/client-wasm/pkg-bundler/snippets"

# And an entirely empty target dir, which is the shape a failed build leaves behind.
# Asserts WHICH guard fired, not merely that something refused: the missing-wasm precheck
# runs first and shadows `shipped_gzip_bytes`'s own empty-set refusal, so that second guard
# is unreachable and a test claiming to exercise it would be testing the wrong branch.
rm -f "$work/client-wasm/pkg-bundler"/*
check 3 "$(run_gate)" "an empty target dir fails closed"
# Captured, never piped: the gate exits 3 here BY DESIGN, and under `pipefail` that status
# becomes the pipeline's, so `gate_stderr | grep -q` reports failure on a successful match.
empty_dir_err="$(gate_stderr || true)"
if grep -q 'missing wasm output' <<<"$empty_dir_err"; then
  echo "  ok    the empty-dir refusal comes from the missing-wasm precheck"
else
  echo "  FAIL  the empty-dir refusal did not name the missing wasm output" >&2
  echo "        got: ${empty_dir_err}" >&2
  failed=1
fi

if [[ "$failed" -ne 0 ]]; then
  echo "check-wasm-bundle-size-selftest.sh: FAILED - the gate does not catch what it claims." >&2
  exit 1
fi
echo "check-wasm-bundle-size-selftest.sh: the gate fires on every case it claims."
