#!/usr/bin/env bash
# Cross-language parity gate for the five wire-relevant constants declared independently
# in Rust and TypeScript, where only a prose comment binds the two today:
#
#   1. BATCH_SIZE_LADDER   sdk/src/batch-ladder.ts        vs core/src/batch_ladder.rs
#   2. MAX_BATCH_SIZE      sdk/src/batch-ladder.ts        vs core/src/batch_ladder.rs (max_batch_size)
#   3. TREE_DEPTH          sdk/src/client-pir.ts          vs engine/src/imt.rs
#   4. NODE_HASH_BYTES     sdk/src/raven-poi-node-interface.ts vs engine/src/pir_table/mod.rs
#   5. schema envelope     sdk/src/raven-poi-node-interface.ts (stripSchemaEnvelope)
#                          vs http/src/versioned.rs (WIRE_SCHEMA_VERSION)
#
# A Rust-side change leaves the TS suite green while every batch the SDK sends is
# refused at runtime; a TREE_DEPTH drift silently changes proof length and index
# arithmetic. Every extraction asserts it produced a non-empty value BEFORE comparing —
# a grep that matches nothing must fail the gate, not pass it vacuously.
set -uo pipefail

ADAPTER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
failed=0

# extract <label> <file> <sed-expr>: prints the first match, fails closed when empty.
extract() {
  local label="$1" file="$2" expr="$3"
  if [[ ! -f "$file" ]]; then
    echo "check-sdk-constant-parity: ${label}: missing file ${file}" >&2
    exit 3
  fi
  local val
  val="$(sed -n "$expr" "$file" | head -1)"
  if [[ -z "$val" ]]; then
    echo "check-sdk-constant-parity: ${label}: extracted NOTHING from ${file} — the pattern drifted; refusing to pass vacuously" >&2
    exit 3
  fi
  printf '%s' "$val"
}

compare() { # label ts_val rust_val
  # extract's exit 3 only leaves the $() subshell, so an empty value can reach here —
  # and two empties would compare equal. Empty NEVER passes.
  if [[ -z "$2" || -z "$3" ]]; then
    echo "  FAIL  $1: empty extraction (TS='$2' Rust='$3') — pattern drift fails closed" >&2
    failed=1
    return
  fi
  if [[ "$2" == "$3" ]]; then
    echo "  ok    $1: TS=$2 Rust=$3"
  else
    echo "  FAIL  $1: TS=$2 Rust=$3" >&2
    failed=1
  fi
}

norm_list() { tr -d ' ' <<<"$1"; }

echo "sdk constant parity:"

# 1. BATCH_SIZE_LADDER
ts_ladder="$(extract "TS BATCH_SIZE_LADDER" "${ADAPTER_ROOT}/sdk/src/batch-ladder.ts" \
  's/^export const BATCH_SIZE_LADDER[^=]*= \[\(.*\)\];$/\1/p')"
rs_ladder="$(extract "Rust BATCH_SIZE_LADDER" "${ADAPTER_ROOT}/core/src/batch_ladder.rs" \
  's/^pub const BATCH_SIZE_LADDER[^=]*= \[\(.*\)\];$/\1/p')"
compare "BATCH_SIZE_LADDER" "$(norm_list "$ts_ladder")" "$(norm_list "$rs_ladder")"

# 2. MAX_BATCH_SIZE (Rust side is the max_batch_size() fn body's literal)
ts_max="$(extract "TS MAX_BATCH_SIZE" "${ADAPTER_ROOT}/sdk/src/batch-ladder.ts" \
  's/^export const MAX_BATCH_SIZE = \([0-9]*\);$/\1/p')"
rs_max="$(extract "Rust max_batch_size" "${ADAPTER_ROOT}/core/src/batch_ladder.rs" \
  '/^pub const fn max_batch_size/,/^}/{s/^ *\([0-9][0-9]*\) *$/\1/p;}')"
compare "MAX_BATCH_SIZE" "$ts_max" "$rs_max"

# 3. TREE_DEPTH
ts_depth="$(extract "TS TREE_DEPTH" "${ADAPTER_ROOT}/sdk/src/client-pir.ts" \
  's/^export const TREE_DEPTH = \([0-9]*\);$/\1/p')"
rs_depth="$(extract "Rust TREE_DEPTH" "${ADAPTER_ROOT}/engine/src/imt.rs" \
  's/^pub const TREE_DEPTH: usize = \([0-9]*\);$/\1/p')"
compare "TREE_DEPTH" "$ts_depth" "$rs_depth"

# 4. NODE_HASH_BYTES
ts_node="$(extract "TS NODE_HASH_BYTES" "${ADAPTER_ROOT}/sdk/src/raven-poi-node-interface.ts" \
  's/^const NODE_HASH_BYTES = \([0-9]*\);$/\1/p')"
rs_node="$(extract "Rust NODE_HASH_BYTES" "${ADAPTER_ROOT}/engine/src/pir_table/mod.rs" \
  's/^pub const NODE_HASH_BYTES: usize = \([0-9]*\);$/\1/p')"
compare "NODE_HASH_BYTES" "$ts_node" "$rs_node"

# 5. Schema envelope version: the TS reader's accepted version vs the Rust wire constant.
ts_env="$(extract "TS envelope version" "${ADAPTER_ROOT}/sdk/src/raven-poi-node-interface.ts" \
  's/^ *if (envelope !== \([0-9]*\)) {$/\1/p')"
rs_env="$(extract "Rust WIRE_SCHEMA_VERSION" "${ADAPTER_ROOT}/http/src/versioned.rs" \
  's/^pub const WIRE_SCHEMA_VERSION: u16 = \([0-9]*\);$/\1/p')"
compare "schema envelope version" "$ts_env" "$rs_env"

if [[ "$failed" -ne 0 ]]; then
  echo "check-sdk-constant-parity.sh: FAILED - a Rust/TS constant pair has drifted." >&2
  exit 1
fi
echo "check-sdk-constant-parity.sh: all five Rust/TS constant pairs agree."
