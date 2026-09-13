#!/usr/bin/env bash
# Cross-language parity gate for eight wire-relevant contracts declared independently
# in Rust and TypeScript:
#
#   1. BATCH_SIZE_LADDER   sdk/src/batch-ladder.ts        vs adapter policy
#   2. MAX_BATCH_SIZE      sdk/src/batch-ladder.ts        vs adapter policy + generic core ceiling
#   3. TREE_DEPTH          sdk/src/poi-pir.ts             vs engine/src/imt.rs
#   4. NODE_HASH_BYTES     sdk/src/raven-poi-node-interface.ts vs engine/src/pir_table/mod.rs
#   5. schema envelope     sdk/src/raven-poi-node-interface.ts (stripSchemaEnvelope)
#                          vs http/src/versioned.rs (WIRE_SCHEMA_VERSION)
#   6. POI status bytes    sdk/src/poi-pir.ts             vs http/src/poi_shim.rs
#   7. batch response      sdk/src/raven-poi-node-interface.ts (decodeBatchBody)
#                          vs http/src/versioned.rs (write_batch_response_versioned)
#   8. consumer status     sdk/src/events-stream.ts          vs http/src/status.rs
#
# A Rust-side change leaves the TS suite green while every batch the SDK sends is
# refused at runtime; a TREE_DEPTH drift silently changes proof length and index
# arithmetic. Every extraction asserts it produced a non-empty value BEFORE comparing —
# a grep that matches nothing must fail the gate, not pass it vacuously.
set -uo pipefail

ADAPTER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ADAPTER_BATCH="${ADAPTER_ROOT}/core/src/batch_ladder.rs"
CORE_BATCH="${ADAPTER_ROOT}/../../crates/core/src/batch_ladder.rs"
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

require_field_count() { # label table expected
  local label="$1" table="$2" expected="$3" count
  count="$(awk -F',' '{ print NF }' <<<"$table")"
  if [[ "$count" != "$expected" ]]; then
    echo "check-sdk-constant-parity: ${label}: extracted ${count} fields, expected ${expected}; refusing a partial table" >&2
    exit 3
  fi
}

echo "sdk constant parity:"

# 1. BATCH_SIZE_LADDER
ts_ladder="$(extract "TS BATCH_SIZE_LADDER" "${ADAPTER_ROOT}/sdk/src/batch-ladder.ts" \
  's/^export const BATCH_SIZE_LADDER[^=]*= \[\(.*\)\];$/\1/p')"
rs_ladder="$(extract "Rust BATCH_SIZE_LADDER" "$ADAPTER_BATCH" \
  's/^pub const BATCH_SIZE_LADDER[^=]*= \[\(.*\)\];$/\1/p')"
compare "BATCH_SIZE_LADDER" "$(norm_list "$ts_ladder")" "$(norm_list "$rs_ladder")"

# 2. MAX_BATCH_SIZE and the parameterized framework seam.
ts_max="$(extract "TS MAX_BATCH_SIZE" "${ADAPTER_ROOT}/sdk/src/batch-ladder.ts" \
  's/^export const MAX_BATCH_SIZE = \([0-9]*\);$/\1/p')"
rs_max="$(extract "Rust MAX_BATCH_SIZE" "$ADAPTER_BATCH" \
  's/^pub const MAX_BATCH_SIZE: usize = \([0-9]*\);$/\1/p')"
compare "MAX_BATCH_SIZE" "$ts_max" "$rs_max"
core_ceiling="$(extract "generic core ceiling" "$CORE_BATCH" \
  's/^pub fn padded_len(len: usize, maximum: usize).*$/len,maximum/p')"
compare "generic core ladder ceiling" "$core_ceiling" "len,maximum"
adapter_delegate="$(extract "adapter core delegation" "$ADAPTER_BATCH" \
  's/^    raven_core::batch_ladder::padded_len(len, MAX_BATCH_SIZE)\.ok()$/delegates/p')"
compare "adapter delegates ladder arithmetic" "$adapter_delegate" "delegates"
if /usr/bin/grep -q '^pub enum LadderViolation' "$ADAPTER_BATCH"; then
  echo "  FAIL  adapter ladder: local LadderViolation copy remains" >&2
  failed=1
else
  echo "  ok    adapter ladder: no local LadderViolation copy"
fi

# 3. TREE_DEPTH
ts_depth="$(extract "TS TREE_DEPTH" "${ADAPTER_ROOT}/sdk/src/poi-pir.ts" \
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

# 5. Schema envelope version across the TS reader/writer and both Rust writers.
ts_env="$(extract "TS envelope version" "${ADAPTER_ROOT}/sdk/src/raven-poi-node-interface.ts" \
  's/^const WIRE_SCHEMA_VERSION = \([0-9]*\);$/\1/p')"
rs_env="$(extract "Rust WIRE_SCHEMA_VERSION" "${ADAPTER_ROOT}/http/src/versioned.rs" \
  's/^pub const WIRE_SCHEMA_VERSION: u16 = \([0-9]*\);$/\1/p')"
compare "schema envelope version" "$ts_env" "$rs_env"
rs_client_env="$(extract "Rust client session schema version" "${ADAPTER_ROOT}/../../crates/client/src/lib.rs" \
  's/^const SESSION_WIRE_SCHEMA_VERSION: u16 = \([0-9]*\);$/\1/p')"
compare "client session schema version" "$rs_client_env" "$rs_env"
ts_reader="$(extract "TS envelope reader delegation" "${ADAPTER_ROOT}/sdk/src/raven-poi-node-interface.ts" \
  's/^ *if (envelope !== \(WIRE_SCHEMA_VERSION\)) {$/\1/p')"
compare "TS envelope reader uses shared version" "$ts_reader" "WIRE_SCHEMA_VERSION"
ts_writer_hi="$(extract "TS envelope writer high byte" "${ADAPTER_ROOT}/sdk/src/raven-poi-node-interface.ts" \
  's/^ *(\(WIRE_SCHEMA_VERSION\) >>> 8) \& 0xff,$/\1/p')"
ts_writer_lo="$(extract "TS envelope writer low byte" "${ADAPTER_ROOT}/sdk/src/raven-poi-node-interface.ts" \
  's/^ *\(WIRE_SCHEMA_VERSION\) \& 0xff,$/\1/p')"
compare "TS envelope writer high byte uses shared version" "$ts_writer_hi" "WIRE_SCHEMA_VERSION"
compare "TS envelope writer low byte uses shared version" "$ts_writer_lo" "WIRE_SCHEMA_VERSION"

# 6. POI status bytes. The Rust shim delegates to the one authoritative
# `POIStatus::wire_byte`; its local executable table supplies the four values.
rs_status_delegate="$(extract "Rust poi_status_byte delegation" "${ADAPTER_ROOT}/http/src/poi_shim.rs" \
  's/^    \(s\.wire_byte()\)$/\1/p')"
compare "poi_status_byte delegates to wire_byte" "$rs_status_delegate" "s.wire_byte()"

rs_status="$(awk '
  /assert_eq!\(poi_status_byte\(POIStatus::/ {
    line = $0
    sub(/^.*POIStatus::/, "", line)
    name = line
    sub(/\).*$/, "", name)
    code = line
    sub(/^.*\), /, "", code)
    sub(/\).*$/, "", code)
    printf "%s%s=%s", separator, name, code
    separator = ","
  }
' "${ADAPTER_ROOT}/http/src/poi_shim.rs")"
ts_status="$(awk '
  /^export function statusByteToPOIStatus/ { inside = 1; next }
  inside && /^    case [0-9]+:/ {
    code = $2
    sub(/:$/, "", code)
    next
  }
  inside && /^      return "[A-Za-z]+";/ {
    name = $2
    gsub(/[";]/, "", name)
    printf "%s%s=%s", separator, name, code
    separator = ","
    next
  }
  inside && /^}/ { exit }
' "${ADAPTER_ROOT}/sdk/src/poi-pir.ts")"
require_field_count "Rust POI status table" "$rs_status" 4
require_field_count "TS POI status table" "$ts_status" 4
compare "POI status byte table" "$ts_status" "$rs_status"

# 7. Batch response framing. The existing envelope-version pair above owns the
# version value; this pair owns prefix width, count/element integer widths and
# endian, and the length-delimited element body.
rs_batch_prefix="$(extract "Rust batch prefix width" "${ADAPTER_ROOT}/http/src/versioned.rs" \
  '/^pub fn write_batch_response_versioned/,/^}/{s/^    out.extend_from_slice(&WIRE_SCHEMA_VERSION.to_be_bytes());$/prefix2/p;}')"
rs_batch_count="$(extract "Rust batch count framing" "${ADAPTER_ROOT}/http/src/versioned.rs" \
  '/^pub fn write_batch_response_versioned/,/^}/{s/^    out.extend_from_slice(&count.to_le_bytes());$/count-u64-le/p;}')"
rs_batch_len="$(extract "Rust batch element length" "${ADAPTER_ROOT}/http/src/versioned.rs" \
  '/^pub fn write_batch_response_versioned/,/^}/{s/^        out.extend_from_slice(&elem_len.to_le_bytes());$/len-u64-le/p;}')"
rs_batch_body="$(extract "Rust batch element body" "${ADAPTER_ROOT}/http/src/versioned.rs" \
  '/^pub fn write_batch_response_versioned/,/^}/{s/^        out.extend_from_slice(&body);$/bytes/p;}')"
rs_batch="${rs_batch_prefix}|${rs_batch_count}|${rs_batch_len}|${rs_batch_body}"

ts_batch_prefix="$(extract "TS batch prefix width" "${ADAPTER_ROOT}/sdk/src/raven-poi-node-interface.ts" \
  's/^  let offset = 2;$/prefix2/p')"
ts_batch_count_lo="$(extract "TS batch count low word" "${ADAPTER_ROOT}/sdk/src/raven-poi-node-interface.ts" \
  's/^  const lenLo = view.getUint32(offset, true);$/count-u64-le/p')"
ts_batch_count_hi="$(extract "TS batch count high word" "${ADAPTER_ROOT}/sdk/src/raven-poi-node-interface.ts" \
  's/^  const lenHi = view.getUint32(offset + 4, true);$/count-u64-le/p')"
compare "batch count low/high endian" \
  "${ts_batch_count_lo}|${ts_batch_count_hi}" "${rs_batch_count}|${rs_batch_count}"
ts_batch_len_lo="$(extract "TS batch length low word" "${ADAPTER_ROOT}/sdk/src/raven-poi-node-interface.ts" \
  's/^    const elemLenLo = view.getUint32(offset, true);$/len-u64-le/p')"
ts_batch_len_hi="$(extract "TS batch length high word" "${ADAPTER_ROOT}/sdk/src/raven-poi-node-interface.ts" \
  's/^    const elemLenHi = view.getUint32(offset + 4, true);$/len-u64-le/p')"
compare "batch length low/high endian" \
  "${ts_batch_len_lo}|${ts_batch_len_hi}" "${rs_batch_len}|${rs_batch_len}"
ts_batch_body="$(extract "TS batch element body" "${ADAPTER_ROOT}/sdk/src/raven-poi-node-interface.ts" \
  's/^    out.push(new Uint8Array(buf.subarray(offset, offset + elemLenLo)));$/bytes/p')"
ts_batch="${ts_batch_prefix}|${ts_batch_count_lo}|${ts_batch_len_lo}|${ts_batch_body}"
compare "batch response framing" "$ts_batch" "$rs_batch"

# 8. SSE consumer status shape. Rust u64 values cross JSON as TypeScript numbers;
# field identity and ordering must remain exact so a new metric cannot vanish in the SDK cast.
ts_consumer_status="$(awk '
  /^export interface ConsumerStatus/ { inside = 1; next }
  inside && /^}/ { exit }
  inside && /^  [a-z_]+: number;$/ {
    field = $1
    sub(/:$/, "", field)
    printf "%s%s:number", separator, field
    separator = ","
  }
' "${ADAPTER_ROOT}/sdk/src/events-stream.ts")"
rs_consumer_status="$(awk '
  /^pub struct ConsumerStatus/ { inside = 1; next }
  inside && /^}/ { exit }
  inside && /^    pub [a-z_]+: u64,$/ {
    field = $2
    sub(/:$/, "", field)
    printf "%s%s:number", separator, field
    separator = ","
  }
' "${ADAPTER_ROOT}/http/src/status.rs")"
require_field_count "TS ConsumerStatus" "$ts_consumer_status" 9
require_field_count "Rust ConsumerStatus" "$rs_consumer_status" 9
compare "ConsumerStatus JSON shape" "$ts_consumer_status" "$rs_consumer_status"

if [[ "$failed" -ne 0 ]]; then
  echo "check-sdk-constant-parity.sh: FAILED - a Rust/TS constant pair has drifted." >&2
  exit 1
fi
echo "check-sdk-constant-parity.sh: all eight Rust/TS wire contracts agree."
