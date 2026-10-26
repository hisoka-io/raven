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
Optional flags: `--poll-ms` (2,000), `--max-range` (most blocks one log read asks for, 50,000),
`--max-sessions`
(2,048), `--session-ttl-secs` (3,600; a session's lifetime restarts with each use), `--concurrent`
(batches answered at once), `--respond-threads` (threads computing set-2 responses, shared by every
batch; the cores), `--walk-blocks` (64, at least 1, below), `--param-set` (1 or 2, below; 1 by
default). The bounds of a public node are under [Serving in public](#serving-in-public).

A log read starts at one block and doubles while it holds less than half of one table batch. When the
endpoint refuses a read (a block-range or result cap, a timeout) or its answer passes 192 MiB, the
read is halved and asked again at once, so `--max-range` needs no tuning to the endpoint's limits; a
lower value only saves the refused reads on an endpoint with a small range cap.

The node serves each block as soon as it is read, and every answer names that block. When the chain
reorganises below the node's newest block, the node returns to the newest block it recorded that the
chain still has and reads on from there. Within the walk depth (`--walk-blocks`, 64) of the head it
reads the pool's leaf count there, which needs the endpoint to keep that block's state for the walk
depth plus the blocks made during one step; deeper blocks need no old state, so a pruned endpoint
serves a catch-up. A walk deeper than the endpoint's recent state fails each step near the head. Within the walk it also reads the header of every
block it takes in, and applies the read only when the headers link to each other and to the node's
newest block and every log names one of them; a read that spans a reorganisation is dropped and read
again. A leaf whose logged root the node's rows cannot reproduce takes the node back one recorded
block further. A newest block the endpoint does not know is waited for a few polls while the
endpoint's head block is one the node read; a head block the node did not read is a shorter chain,
followed at once.

A wallet that holds the newest block up to its leaf count sends that count as `held`, so a sync with
nothing new carries the header and three empty runs: 96 bytes.

## Parameter sets

A node serves one parameter set, chosen at start and named in every answer's header and every
request's prefix. A client builds its key and queries for the set the params answer names. The
plain routes are the same bytes under either set apart from that id.

| | Set 1 | Set 2 |
|---|---|---|
| Scheme | ring 2,048, a 60-bit modulus, plaintext modulus 65,537, responses switched to 36 bits | ring 2,048, a 29-bit prime, plaintext modulus 16, a one-row packing key at about 2^60 |
| Key material in the params answer | the node's, versioned | the key-mask version, 2 B; each key carries its own mask seed |
| Session payload | the serialized key, 46,252 B | the key, 15,394 B: its key-mask version, its 32-byte mask seed, then the key |
| Batch payload | the serialized batch | `howl_wire::P16Batch`: the key's source, then 7,456 B per query |
| Response per query | 9,870 B | 9,208 B, the first 246 bytes of the cell; the rest of a cell is zero |
| Seat per session | 48 KiB | 32 KiB: the key and its mask |


| Route | Answer body |
|---|---|
| `GET /howl/v1/params` | cell bytes, rows per shard, ladder cap, session lifetime, the public key material |
| `GET /howl/v1/prefixes?since=N` | `base`, `next`, the rows from `N` to the next 65,536-row boundary or the end |
| `GET /howl/v1/block/{b}` | the leaves of block `b` present at the answer's leaf count |
| `GET /howl/v1/upper?since=K` | level-10 nodes of full blocks from `K` |
| `GET /howl/v1/sync?since=N&upper=K&held=H` | the three reads above for the newest block, at one leaf count; the newest block's leaves start at leaf `H` when it falls inside that block (`held` is optional, 0 by default) |
| `POST /howl/v1/session` | a session handle for an uploaded packing key |
| `POST /howl/v1/notes` | one response per query of a batch |
| `GET /howl/v1/health` | plain text: leaves, block, shards |
| `GET /howl/v1/status` | plain text for the operator, under a bearer token: seats, queue, refusals |

A read that names a position past the node's state is answered `409` with a header-only answer that
states where the node stands.

## Serving in public

Every read route answers any caller: the feed is public, and a private read needs no account. The
one credential is the operator's: `GET /howl/v1/status` reports seats in use, the respond queue and
the refusals of each bound, and opens only to `Authorization: Bearer <token>` with the token set in
`HOWL_NODE_OPERATOR_TOKEN` (16 bytes at least, compared in constant time). Generate it at random,
e.g. `openssl rand -hex 32`: its length is all the node checks. Unset, the route answers `401` to
everyone. The public health answer carries only what every answer's header carries.

Wallets reach a node through shared exits, so the bounds are on the node's work, never on a
caller's address:

| Flag | Default | Bounds |
|---|---|---|
| `--rate`, `--rate-burst` | 5,000 / s, 10,000 | requests on each route but health, status and session, all callers together, each route with a bucket of its own; past it `429` on that route only |
| `--session-rate`, `--session-burst` | 4 / s, 64 | sessions opened, so seats cannot be filled faster; past it `429` |
| `--queued` | 8 per `--concurrent` | batches and registrations waiting for a permit; past it `503` at once |
| `--permit-wait-ms` | 20,000 | how long one waits for a permit before `503` |
| `--bodies` | twice the permits and queue places | session and batch bodies being read or answered; a body takes its place before its first byte is read; past it `503` at once |
| `--body-timeout-ms` | 30,000 | how long one body may take to arrive before `408` |
| `--max-sessions` | 2,048 | seats; a full table answers a new session `503`, and the TypeScript client then reads with the key inline, which needs no seat |

`429` and `503` carry `Retry-After`, which browsers may read, and close the connection. A session or
batch body past its route's size is refused with `413` and never decoded. Measured on two cores
over a local socket, each read route answered about 64,000 requests a second and a two-query
private read about 87 a second; the request rate sits well below the first, and the permits bound
the second. These bounds hold the node's memory and CPU whatever reaches it; telling a flood from
wallets belongs to the proxy or filter in front of a public node.

## Container

`deploy/Dockerfile` builds the node from the repository root, with the `adapters/howl` submodule
checked out:

```sh
docker build -f adapters/howl-node/deploy/Dockerfile -t howl-node .
docker run -v howl-data:/data -p 8645:8645 \
  -e HOWL_NODE_RPC_URL=<json-rpc endpoint> -e HOWL_CHAIN_ID=<chain id> \
  -e HOWL_POOL=<pool address> -e HOWL_DEPLOYMENT_BLOCK=<block> howl-node
```

The node runs as an unprivileged user under `tini`, keeps its table and key material in the `/data`
volume (or `HOWL_DATA_DIR`, or a platform's `RAILWAY_VOLUME_MOUNT_PATH`), binds `0.0.0.0:$PORT`
(8645), and stops cleanly on `SIGTERM`. The image's health check reads `/howl/v1/health`.
`HOWL_PARAM_SET` picks the set, `HOWL_NODE_OPERATOR_TOKEN` opens the status route, and arguments
after the image name are passed to the node, so `--max-sessions 512` or any flag above can be added
there; the address, data directory and pool come only from the variables, so the health check
always probes the port the node binds. `deploy/entrypoint.sh` lists every variable.

The endpoint must accept a block hash as the block of `eth_call` (EIP-1898). It may be pruned: it
needs the full log history from the deployment block, and the state of the blocks within the walk
depth of the head.
