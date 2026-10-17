# Howl node

Serves Howl wallets from one pool deployment. The node follows the pool's tree events on chain, keeps
the discovery table (one 256-byte `howl-note-v1` cell per tree leaf), and answers four kinds of read:

- the **tag-prefix feed**: six bytes per leaf, in leaf order, read in resumable segments;
- the **tree**: the leaves of any 1,024-leaf block, and the level-10 node of every full block, from
  which a wallet folds the full depth-32 path of a note at any leaf count it chooses;
- **private cell reads**: a batch of cells by leaf position, answered by PIR, either under a
  session key uploaded once (`POST /howl/v1/session`) or with the key carried in the request;
- a **sync** read that returns the feed delta, the new upper nodes and the newest block in one answer.

Every answer starts with the same 56-byte header: wire version, parameter-set id, route, and the tree
state it was read from (leaf count, the chain block it reflects, the pool's root). One answer is read
from one state, and a row the feed shows is a row a private read returns. The layouts are in
`wire/src/lib.rs` and pinned by `wire/tests/layout.rs`; the tree arithmetic is `wire/src/tree.rs`.

| Crate | What it holds |
|---|---|
| `wire` (`howl-wire`) | the answer header and bodies, the batch ladder, the tree arithmetic |
| `store` (`howl-store`) | the durable positional table, its chain marks, and rewind for reorganisations |
| `node` (`howl-node`) | chain follower, the served view and its encoded shards, the HTTP routes, the binary |
| `client-wasm` (`howl-client-wasm`) | the wallet's side in WebAssembly: answer decoding, private reads under a fresh key, the verified tree |
| `sdk` (`@hisoka-io/raven-howl-client`) | the TypeScript package a Howl wallet calls: feed scan, private reads, paths |

## Running

```sh
cargo build --release --manifest-path adapters/howl-node/Cargo.toml -p howl-node
HOWL_NODE_RPC_URL=<json-rpc endpoint> \
  adapters/howl-node/target/release/howl-node --data-dir ./howl-data --chain-id <chain id> \
  --pool <pool address, 0x-prefixed> --deployment-block <block the pool was deployed in> \
  --listen 127.0.0.1:8645
```

The endpoint is read from the environment so that a key in its URL stays out of the process list.
Optional flags: `--poll-ms` (2,000), `--max-range` (blocks per log read, 2,000), `--max-sessions`
(2,048), `--session-ttl-secs` (3,600; a session's lifetime restarts with each use), `--concurrent`
(batches answered at once).

The node serves each block as soon as it is read, and every answer names that block. When the chain
reorganises below the node's newest block, the node returns to the newest block it recorded that the
chain still has and reads on from there. Within 64 blocks of the head it reads the header of every
block it takes in, and applies the read only when the headers link to each other and to the node's
newest block and every log names one of them; a read that spans a reorganisation is dropped and read
again. A leaf whose logged root the node's rows cannot reproduce takes the node back one recorded
block further. A newest block the endpoint does not know is waited for a few polls while the
endpoint's head block is one the node read; a head block the node did not read is a shorter chain,
followed at once.

A wallet that holds the newest block up to its leaf count sends that count as `held`, so a sync with
nothing new carries the header and three empty runs: 96 bytes.

## Routes

| Route | Answer body |
|---|---|
| `GET /howl/v1/params` | cell bytes, rows per shard, ladder cap, session lifetime, the public key material |
| `GET /howl/v1/prefixes?since=N` | `base`, `next`, the rows from `N` to the next 65,536-row boundary or the end |
| `GET /howl/v1/block/{b}` | the leaves of block `b` present at the answer's leaf count |
| `GET /howl/v1/upper?since=K` | level-10 nodes of full blocks from `K` |
| `GET /howl/v1/sync?since=N&upper=K&held=H` | the three reads above for the newest block, at one leaf count; the newest block's leaves start at leaf `H` when it falls inside that block (`held` is optional, 0 by default) |
| `POST /howl/v1/session` | a session handle for an uploaded packing key |
| `POST /howl/v1/notes` | one response per query of a batch |
| `GET /howl/v1/health` | plain text: leaves, block, shards, sessions |

A read that names a position past the node's state is answered `409` with a header-only answer that
states where the node stands.
