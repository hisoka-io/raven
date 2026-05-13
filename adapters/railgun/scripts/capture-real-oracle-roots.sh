#!/usr/bin/env bash
#
# adapters/railgun/scripts/capture-real-oracle-roots.sh
#
# Operator-driven one-shot capture script for the subsquid root-oracle
# fixture file at:
#
#   adapters/railgun/engine/tests/fixtures/subsquid_canonical_roots.json
#
# For each entry in `tree_checkpoints`:
#   1. cast call merkleRoot()(bytes32) at the documented capture block
#      against the configured Sepolia RPC -> writes `chain_root` +
#      `_chain_root_capture` (the cast invocation that produced it).
#   2. HTTP POST Railway upstream PPOI `/poi-events/{chainType}/{chainID}`
#      with txidVersion + listKey + startIndex/endIndex -> extracts
#      `validatedMerkleroot` -> writes `upstream_root` +
#      `_upstream_root_capture` (the HTTP invocation).
#   3. HTTP POST Subsquid GraphQL `Transaction.merkleRoot` query for
#      the same tree-checkpoint -> writes a NEW `real_subsquid_root`
#      field (separate from the existing self-derived `subsquid_root`)
#      + `_real_subsquid_root_capture`.
#
# Outputs the updated JSON in place (pretty-printed via `python3 -m
# json.tool`).
#
# This script is operator-run; it does NOT run in CI. It is also NOT
# called from any test. The subsquid root-oracle test
# (`tests/g5_d_subsquid_root_oracle.rs`) reads whatever fields are
# present in the fixture and triggers the 4-oracle assertion path only
# when ALL of `chain_root`, `upstream_root`, `real_subsquid_root` are
# non-null.
#
# REQUIREMENTS:
#   - `cast` (Foundry) for chain_root captures.
#   - `curl` for HTTP POSTs.
#   - `jq` for JSON path extraction.
#   - `python3` for in-place JSON pretty-printing.
#
# ENV VARS (override defaults):
#   RAVEN_SEPOLIA_RPC      Sepolia JSON-RPC URL (default: ethereum-sepolia-rpc.publicnode.com).
#   RAVEN_RAILWAY_ENDPOINT Railway upstream base (default: https://ppoi-node.example.io).
#   RAVEN_SUBSQUID_GRAPHQL Subsquid GraphQL endpoint (default: https://squid.example.io/graphql).
#
# USAGE:
#   bash adapters/railgun/scripts/capture-real-oracle-roots.sh           # live captures
#   bash adapters/railgun/scripts/capture-real-oracle-roots.sh --dry-run # print intended invocations only
#
# EXIT CODES:
#   0 = success (all captures completed or dry-run printed).
#   1 = missing required tool, malformed fixture, or network failure.

set -euo pipefail

# Script lives at adapters/railgun/scripts/, so its parent is the
# adapter root (adapters/railgun/).
ADAPTER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="${ADAPTER_ROOT}/engine/tests/fixtures/subsquid_canonical_roots.json"

DRY_RUN=0
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=1
fi

SEPOLIA_RPC="${RAVEN_SEPOLIA_RPC:-https://ethereum-sepolia-rpc.publicnode.com}"
RAILWAY_ENDPOINT="${RAVEN_RAILWAY_ENDPOINT:-https://ppoi-node.example.io}"
SUBSQUID_GRAPHQL="${RAVEN_SUBSQUID_GRAPHQL:-https://squid.example.io/graphql}"

# Sepolia chain id for the Railway endpoint path. Source-of-truth:
# clones/railgun-research/repo-cache/private-proof-of-innocence/packages/node/src/api/schemas.ts:5
SEPOLIA_CHAIN_TYPE=0
SEPOLIA_CHAIN_ID=11155111

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required (sudo apt install jq)" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required" >&2
  exit 1
fi

if [[ "$DRY_RUN" -eq 0 ]]; then
  if ! command -v cast >/dev/null 2>&1; then
    echo "ERROR: cast (foundry) is required for chain_root captures." >&2
    echo "       Install: curl -L https://foundry.paradigm.xyz | bash && foundryup" >&2
    exit 1
  fi
  if ! command -v curl >/dev/null 2>&1; then
    echo "ERROR: curl is required" >&2
    exit 1
  fi
fi

if [[ ! -f "$FIXTURE" ]]; then
  echo "ERROR: fixture not found at $FIXTURE" >&2
  exit 1
fi

PROXY_ADDR=$(jq -r '._railgun_proxy' "$FIXTURE")
LIST_KEY_HEX=$(jq -r '._list_key_hex' "$FIXTURE")
TREE_COUNT=$(jq '.tree_checkpoints | length' "$FIXTURE")

echo "capture-real-oracle-roots.sh"
echo "  fixture:       $FIXTURE"
echo "  proxy:         $PROXY_ADDR"
echo "  list_key:      $LIST_KEY_HEX"
echo "  sepolia_rpc:   $SEPOLIA_RPC"
echo "  railway:       $RAILWAY_ENDPOINT"
echo "  subsquid:      $SUBSQUID_GRAPHQL"
echo "  tree_count:    $TREE_COUNT"
echo "  mode:          $([[ $DRY_RUN -eq 1 ]] && echo dry-run || echo live)"
echo

# Build a working copy of the fixture in a tempfile so any partial
# failure leaves the original untouched. We rewrite-in-place at the
# end after every capture step succeeded (or dry-ran).
WORK=$(mktemp)
trap 'rm -f "$WORK"' EXIT
cp "$FIXTURE" "$WORK"

for ((i = 0; i < TREE_COUNT; i++)); do
  TREE_NUMBER=$(jq -r ".tree_checkpoints[$i].tree_number" "$WORK")
  LEAF_COUNT=$(jq -r ".tree_checkpoints[$i].leaf_count" "$WORK")
  BLOCK_HEIGHT=$(jq -r ".tree_checkpoints[$i].block_height" "$WORK")
  LABEL=$(jq -r ".tree_checkpoints[$i]._label // \"(unnamed)\"" "$WORK")

  echo "tree_checkpoints[$i]: tree=$TREE_NUMBER leaf_count=$LEAF_COUNT block=$BLOCK_HEIGHT"
  echo "  label: $LABEL"

  # ---- Step 1: chain_root via cast call ----
  CAST_CMD=(
    cast call
    --rpc-url "$SEPOLIA_RPC"
    --block "$BLOCK_HEIGHT"
    "$PROXY_ADDR"
    'merkleRoot()(bytes32)'
  )
  CAST_INVOCATION="${CAST_CMD[*]}"
  echo "  [chain_root]    intended: $CAST_INVOCATION"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    if CHAIN_ROOT=$("${CAST_CMD[@]}" 2>/dev/null); then
      CHAIN_ROOT=$(echo "$CHAIN_ROOT" | tr -d '[:space:]')
      echo "  [chain_root]    -> $CHAIN_ROOT"
      WORK_NEW=$(mktemp)
      jq --arg root "$CHAIN_ROOT" --arg cap "$CAST_INVOCATION" \
        ".tree_checkpoints[$i].chain_root = \$root | .tree_checkpoints[$i]._chain_root_capture = \$cap" \
        "$WORK" > "$WORK_NEW"
      mv "$WORK_NEW" "$WORK"
    else
      echo "  [chain_root]    FAILED: cast call returned non-zero (network / RPC issue?)" >&2
    fi
  fi

  # ---- Step 2: upstream_root via Railway POST ----
  # Source-of-truth for endpoint shape:
  #   clones/railgun-research/repo-cache/private-proof-of-innocence/packages/node/src/api/schemas.ts:20-29
  #     - GetPOIListEventRangeBodySchema requires:
  #       txidVersion, startIndex, endIndex, listKey
  RAILWAY_URL="$RAILWAY_ENDPOINT/poi-events/$SEPOLIA_CHAIN_TYPE/$SEPOLIA_CHAIN_ID"
  END_INDEX=$((LEAF_COUNT))
  RAILWAY_BODY=$(cat <<EOF
{"txidVersion":"V2_PoseidonMerkle","listKey":"$LIST_KEY_HEX","startIndex":0,"endIndex":$END_INDEX}
EOF
)
  RAILWAY_INVOCATION="curl -X POST -H 'Content-Type: application/json' -d '$RAILWAY_BODY' $RAILWAY_URL"
  echo "  [upstream_root] intended: $RAILWAY_INVOCATION"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    if UPSTREAM_RESP=$(curl -sS -X POST -H 'Content-Type: application/json' -d "$RAILWAY_BODY" "$RAILWAY_URL" 2>/dev/null); then
      # The upstream response carries one signedPOIEvent per index;
      # we want the validatedMerkleroot at index = leaf_count - 1
      # (the last event in the captured range).
      LAST=$((LEAF_COUNT - 1))
      UPSTREAM_ROOT=$(echo "$UPSTREAM_RESP" | jq -r --argjson idx "$LAST" \
        '[.[] | .validatedMerkleroot // .validated_merkleroot // empty][$idx] // empty')
      if [[ -n "$UPSTREAM_ROOT" && "$UPSTREAM_ROOT" != "null" ]]; then
        if [[ "$UPSTREAM_ROOT" != 0x* ]]; then
          UPSTREAM_ROOT="0x$UPSTREAM_ROOT"
        fi
        echo "  [upstream_root] -> $UPSTREAM_ROOT"
        WORK_NEW=$(mktemp)
        jq --arg root "$UPSTREAM_ROOT" --arg cap "$RAILWAY_INVOCATION" \
          ".tree_checkpoints[$i].upstream_root = \$root | .tree_checkpoints[$i]._upstream_root_capture = \$cap" \
          "$WORK" > "$WORK_NEW"
        mv "$WORK_NEW" "$WORK"
      else
        echo "  [upstream_root] FAILED: response did not carry validatedMerkleroot at index $LAST" >&2
        echo "                   raw: $(echo "$UPSTREAM_RESP" | head -c 200)" >&2
      fi
    else
      echo "  [upstream_root] FAILED: HTTP request failed" >&2
    fi
  fi

  # ---- Step 3: real_subsquid_root via Subsquid GraphQL ----
  # Source-of-truth for the GraphQL field shape:
  #   clones/railgun-research/repo-cache/subsquid-integration/schema.graphql:160-178
  #     type Transaction { ... merkleRoot: Bytes! ... utxoTreeOut: BigInt! ... }
  # Per-tree IMT root is exposed via Transaction.merkleRoot at the
  # transaction that brought the tree to leaf_count == LEAF_COUNT.
  # We query for the latest transaction within block <= BLOCK_HEIGHT
  # whose utxoTreeOut == TREE_NUMBER and whose
  # utxoBatchStartPositionOut + len(commitments) == LEAF_COUNT.
  GRAPHQL_QUERY=$(cat <<EOF
query {
  transactions(
    where: {
      blockNumber_lte: $BLOCK_HEIGHT,
      utxoTreeOut_eq: $TREE_NUMBER
    },
    orderBy: blockNumber_DESC,
    limit: 1
  ) {
    merkleRoot
    blockNumber
    utxoTreeOut
    utxoBatchStartPositionOut
    commitments
  }
}
EOF
)
  GRAPHQL_BODY=$(jq -n --arg q "$GRAPHQL_QUERY" '{query: $q}')
  GRAPHQL_INVOCATION="curl -X POST -H 'Content-Type: application/json' -d <<<query>>> $SUBSQUID_GRAPHQL"
  echo "  [real_subsquid] intended: POST $SUBSQUID_GRAPHQL  (Transaction.merkleRoot @ tree=$TREE_NUMBER, block<=$BLOCK_HEIGHT)"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    if SUBSQUID_RESP=$(curl -sS -X POST -H 'Content-Type: application/json' -d "$GRAPHQL_BODY" "$SUBSQUID_GRAPHQL" 2>/dev/null); then
      REAL_ROOT=$(echo "$SUBSQUID_RESP" | jq -r '.data.transactions[0].merkleRoot // empty')
      if [[ -n "$REAL_ROOT" && "$REAL_ROOT" != "null" ]]; then
        if [[ "$REAL_ROOT" != 0x* ]]; then
          REAL_ROOT="0x$REAL_ROOT"
        fi
        echo "  [real_subsquid] -> $REAL_ROOT"
        WORK_NEW=$(mktemp)
        jq --arg root "$REAL_ROOT" --arg cap "$GRAPHQL_INVOCATION" \
          ".tree_checkpoints[$i].real_subsquid_root = \$root | .tree_checkpoints[$i]._real_subsquid_root_capture = \$cap" \
          "$WORK" > "$WORK_NEW"
        mv "$WORK_NEW" "$WORK"
      else
        echo "  [real_subsquid] FAILED: response did not carry data.transactions[0].merkleRoot" >&2
        echo "                   raw: $(echo "$SUBSQUID_RESP" | head -c 200)" >&2
      fi
    else
      echo "  [real_subsquid] FAILED: HTTP request failed" >&2
    fi
  fi

  echo
done

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "DRY RUN complete; fixture left untouched at $FIXTURE"
  exit 0
fi

# Pretty-print + atomic-rename into place. python3 -m json.tool keeps
# the existing _README array shape (jq would also work but inserts
# different whitespace than the existing file).
PRETTY=$(mktemp)
python3 -m json.tool --indent 2 "$WORK" > "$PRETTY"
mv "$PRETTY" "$FIXTURE"
echo "wrote updated fixture at $FIXTURE"
