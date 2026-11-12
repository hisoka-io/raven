# Howl end-to-end suite

Howl's own contracts on a local anvil chain, the Raven Howl node from this checkout following that
chain, and wallets on this checkout's SDK and wasm client. Every note a wallet holds and every Merkle
path it spends with comes through Raven. After every transaction each wallet is graded against an
independent scan of the chain's logs and against the pool's token balances; a run with any mismatch
fails.

The scheduled workflow `.github/workflows/howl-e2e.yml` runs it every night and on demand. It does not
run on push.

## Layout

| Path | What |
|---|---|
| `darkpool.rev` | the commit of [hisoka-io/darkpool](https://github.com/hisoka-io/darkpool) the harness runs against |
| `darkpool/` | the harness, copied over that checkout at the same paths: a hardhat config that adds the local network, and the test files under `test/raven-sim/` |
| `run.sh` | stages the harness and runs the suites, each on a fresh chain |
| `check-plant.py` | passes a planted run only when it went red for the planted fault alone |

## Suites

| Suite | What it runs | When |
|---|---|---|
| `sim:<set>` | five agents with real proofs over 8 rounds (deposits, transfers, splits, joins, swaps, withdrawals, public claims, refused cheats), a node restart halfway, a reorganisation under every wallet, then the pool grown to 2,100 leaves and every wallet acting once more | nightly, sets 1 and 2 |
| `smoke:<set>` | Kage: a solver with its own tree settles an intent proved at an older root, and wrong count hints are refused. Multisig: a 2-of-3 FROST group finds its notes through the client package's multisig scan and spends them (withdraw, split, join, transfer), and a signer handed a mismatched root refuses | nightly, sets 1 and 2 |
| `plant:<set>` | the wallets are served a feed with one row blanked; the run must fail, and every mismatch must trace to that row | nightly, set 1 |
| `full:<set>` | 26 rounds with 2,100 outsider deposits and a pool grown to 70,000 leaves, past the 65,536-row feed segment (1 h 45 min on a 16-core machine) | on demand |

Proofs are real. Wallet circuits are proved with bb.js, and the Kage settlement proof, which is
recursive, with native bb 5.0.0.

## Running it locally

```sh
git clone https://github.com/hisoka-io/darkpool && git -C darkpool checkout "$(cat adapters/howl-node/e2e/darkpool.rev)"
adapters/howl-node/e2e/run.sh darkpool e2e-out stage
# build the node (cargo build --release -p howl-node), the nodejs wasm (wasm-pack, pkg-node) and the SDK,
# then Howl's packages: pnpm install && pnpm turbo run build --filter=evm-contracts...
adapters/howl-node/e2e/run.sh darkpool e2e-out sim:1 smoke:1 plant:1
```

It needs node 22, anvil, nargo 1.0.0-beta.22 and native bb 5.0.0 on `PATH`. Each suite writes
`<out>/<suite>.log` and the harness's own records under `<out>/<suite>/` (`summary.json`,
`mismatches.jsonl`, the node's log).
