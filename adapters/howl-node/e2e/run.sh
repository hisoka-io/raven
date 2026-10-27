#!/usr/bin/env bash
# Howl's own contracts on a local anvil chain, a Raven Howl node following that chain, and wallets on the
# Raven SDK. Every note a wallet holds and every Merkle path it spends with comes through Raven, and each
# wallet is graded after every transaction against an independent scan of the chain's logs.
#
#   run.sh <darkpool checkout> <out dir> <suite>...
#
# Suites, run in order, each on a fresh chain:
#   stage        copy the harness under darkpool/ into the checkout, which must be at the pinned commit
#   sim:<set>    five agents with real proofs, a mid-run node restart, a reorganisation, then a pool
#                grown past two full Merkle blocks with every wallet acting once more
#   smoke:<set>  Kage (a solver with its own tree, an older-root intent, wrong hints refused) and a
#                2-of-3 FROST multisig (scan, spend, a signer refusing a mismatched root)
#   plant:<set>  red-proof: a short run whose wallets are served a feed with one row blanked; it must
#                fail, and every mismatch must trace to that row
#   full:<set>   the long run: outsider load, 26 rounds and a pool grown past the 65,536-row feed segment
#   nightly      stage sim:1 sim:2 smoke:1 smoke:2 plant:1
#
# The node, wasm and SDK default to this checkout's build outputs; HOWL_NODE_BIN, RAVEN_SDK and
# RAVEN_WASM override them. Needs node 22, anvil, nargo and native bb on PATH (see the workflow).
set -euo pipefail

E2E="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOWL="$(cd "$E2E/.." && pwd)"
DARKPOOL="$(cd "${1:?darkpool checkout}" && pwd)"
mkdir -p "${2:?out dir}"
OUT="$(cd "$2" && pwd)"
shift 2
[[ $# -gt 0 ]] || { echo "run.sh: name at least one suite" >&2; exit 2; }

PIN="$(tr -d '[:space:]' < "$E2E/darkpool.rev")"
CONTRACTS="$DARKPOOL/packages/evm-contracts"
export HOWL_NODE_BIN="${HOWL_NODE_BIN:-$HOWL/target/release/howl-node}"
export RAVEN_SDK="${RAVEN_SDK:-$HOWL/sdk/dist/index.js}"
export RAVEN_WASM="${RAVEN_WASM:-$HOWL/client-wasm/pkg-node/howl_client_wasm.js}"
ANVIL_PORT="${ANVIL_PORT:-18955}"
export SIM_NODE_PORT="${SIM_NODE_PORT:-18956}"
export SIM_RPC_URL="http://127.0.0.1:$ANVIL_PORT"
# the harness imports workspace packages that ship TypeScript sources
export NODE_OPTIONS="--experimental-strip-types --no-warnings" DOTENV_CONFIG_QUIET=true

stage() {
  local head
  head="$(git -C "$DARKPOOL" rev-parse HEAD)"
  [[ "$head" == "$PIN" ]] || { echo "darkpool checkout is at $head, the harness is pinned to $PIN" >&2; return 1; }
  cp -R "$E2E/darkpool/." "$DARKPOOL/"
  echo "staged the harness into $DARKPOOL at $PIN"
}

need_built() {
  local f
  for f in "$HOWL_NODE_BIN" "$RAVEN_SDK" "$RAVEN_WASM" "$CONTRACTS/test/raven-sim/RavenSim.test.ts"; do
    [[ -e "$f" ]] || { echo "missing $f: build the node, wasm and SDK, and stage first" >&2; return 1; }
  done
}

ANVIL=
stop_anvil() { [[ -z "$ANVIL" ]] || { kill "$ANVIL" 2>/dev/null || true; wait "$ANVIL" 2>/dev/null || true; ANVIL=; }; }
trap stop_anvil EXIT

# runs one hardhat test file on a fresh chain; the log lands in <out>/<name>.log, the harness's own files
# in <out>/<name>/
hardhat_run() { # name test-file
  local name=$1 file=$2 rc=0
  rm -rf "${OUT:?}/$name"
  mkdir -p "$OUT/$name"
  anvil --port "$ANVIL_PORT" --gas-limit 1000000000 --silent > "$OUT/$name.anvil.log" 2>&1 &
  ANVIL=$!
  local up=0
  for _ in $(seq 200); do
    if curl -sf -X POST -H 'content-type: application/json' \
      --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' "$SIM_RPC_URL" > /dev/null; then
      up=1
      break
    fi
    sleep 0.1
  done
  [[ $up == 1 ]] || { echo "anvil did not start on $ANVIL_PORT" >&2; stop_anvil; return 1; }
  local t0=$SECONDS
  (cd "$CONTRACTS" && SIM_OUT_DIR="$OUT/$name" npx hardhat --config hardhat.raven-sim.config.ts \
    test "test/raven-sim/$file" --network simAnvil) > "$OUT/$name.log" 2>&1 || rc=$?
  stop_anvil
  echo "$name: rc=$rc in $((SECONDS - t0)) s"
  return "$rc"
}

sim_env() { # set: the agent runs share everything but the knobs below
  export SIM_PARAM_SET=$1 SIM_SEED="${SIM_SEED:-20261016}"
  unset SIM_PLANT_DROP_FEED_LEAF
}

suite() {
  local s=$1 set=${1#*:}
  case "$s" in
    stage) stage ;;
    sim:[12])
      sim_env "$set"
      SIM_SMOKE=0 SIM_ROUNDS=8 SIM_MIN_TX=40 SIM_PRESEED_START=0 SIM_PRESEED_HALF=0 SIM_BULK_TO=2100 \
        hardhat_run "sim-set$set" RavenSim.test.ts
      ;;
    full:[12])
      sim_env "$set"
      SIM_SMOKE=0 SIM_ROUNDS=26 SIM_MIN_TX=100 SIM_PRESEED_START=1100 SIM_PRESEED_HALF=1000 SIM_BULK_TO=70000 \
        hardhat_run "full-set$set" RavenSim.test.ts
      ;;
    smoke:[12])
      sim_env "$set"
      hardhat_run "smoke-set$set" RavenKageMultisig.test.ts
      ;;
    plant:[12])
      sim_env "$set"
      local row=1 rc=0
      SIM_SMOKE=1 SIM_ROUNDS=3 SIM_MIN_TX=15 SIM_PRESEED_START=0 SIM_PRESEED_HALF=0 SIM_BULK_TO=0 \
        SIM_PLANT_DROP_FEED_LEAF=$row hardhat_run "plant-set$set" RavenSim.test.ts || rc=$?
      [[ $rc != 0 ]] || { echo "plant-set$set: the planted feed fault did not turn the run red" >&2; return 1; }
      python3 "$E2E/check-plant.py" "$OUT/plant-set$set/mismatches.jsonl" "$row"
      ;;
    nightly)
      local n
      for n in stage sim:1 sim:2 smoke:1 smoke:2 plant:1; do suite "$n"; done
      ;;
    *) echo "unknown suite: $s" >&2; return 2 ;;
  esac
}

for s in "$@"; do
  [[ "$s" == stage || "$s" == nightly ]] || need_built
  suite "$s"
done
