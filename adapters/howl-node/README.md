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
batch; the cores), `--walk-blocks` (64, at least 1, below), `--param-set` (2 or 1, below; 2 by
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
request's prefix. It serves set 2 unless started with `--param-set 1` (`HOWL_PARAM_SET=1` in the
container); set 1 stays selectable. A client builds its key and queries for the set the params answer names. The
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
| `GET /howl/v1/health` | liveness: `ok leaves=.. block=.. shards=..`, `200` while the process serves |
| `GET /howl/v1/ready` | readiness: `ready block=.. head=..` with `200` while the follower reached the head within `--stale-after-secs`, else `stale ...` with `503` |
| `GET /howl/v1/status` | plain text for the operator, under a bearer token: freshness, seats, queue, refusals |

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

Any origin may call. A preflight is cached for two hours (`Access-Control-Max-Age: 7200`), so a
browser wallet's binary POSTs are preflighted once per session rather than once per call. `429` and
`503` carry `Retry-After`, which browsers may read, and close the connection. A session or
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
(8645), and stops cleanly on `SIGTERM`. The image's health check reads `/howl/v1/health`, the
liveness route; a load balancer that should send wallets only to a current node reads
`/howl/v1/ready`.
`HOWL_PARAM_SET` picks the set, `HOWL_NODE_OPERATOR_TOKEN` opens the status route, and arguments
after the image name are passed to the node, so `--max-sessions 512` or any flag above can be added
there; the address, data directory and pool come only from the variables, so the health check
always probes the port the node binds. `deploy/entrypoint.sh` lists every variable.

The endpoint must accept a block hash as the block of `eth_call` (EIP-1898). It may be pruned: it
needs the full log history from the deployment block, and the state of the blocks within the walk
depth of the head.

## Health, readiness and the endpoint check

The node tells three things apart:

- **Liveness**, `GET /howl/v1/health`: `200` while the process serves, whatever the endpoint does.
  The image's `HEALTHCHECK` reads it, so a node catching up or riding out an endpoint outage keeps
  running.
- **Readiness**, `GET /howl/v1/ready`: `200` while the follower's last step that ended at the chain
  head is younger than `--stale-after-secs` (120). A chain that makes no new block keeps the node
  ready, since each poll ends at the head. A follower that falls behind, or whose reads fail, turns
  it `503` within the bound. A cold start is ready once the catch-up reaches the head.
- **Status**, `GET /howl/v1/status` under the operator token: one line of `key=value` fields. The
  freshness fields are `head` (the newest head the follower read), `block` (the block served),
  `behind` (their gap in blocks), `ready` (1 or 0), `current_age_ms` (since the follower last
  reached the head), `step_age_ms` (since its last good step) and `step_errors` (failed steps since
  start). Failed steps are logged at `warn` and retried every poll.

The follower runs beside the routes. Should it end, the node logs why and exits non-zero, so the
container's restart policy brings it back.

Before pointing a node at an endpoint, check it with the same reads the follower makes:

```sh
HOWL_NODE_RPC_URL=<json-rpc endpoint> howl-node check --chain-id 421614 \
  --pool 0x6DABb5682A62b3827eE7e0E02F1DACE896AD457a --deployment-block 312414608
# in the image:
docker run --rm -e HOWL_NODE_RPC_URL=<endpoint> --entrypoint howl-node howl-node check ...
```

It prints one line per check and exits `0` when the endpoint serves a node: `chain_id` (the endpoint's
chain is the one given), `head`, `call_by_hash` (the pool's count by block hash at the head,
EIP-1898), `state_at_walk_depth` (the same `--walk-blocks` below the head, so a pruned endpoint
keeps enough state), `logs_from_deployment` (the four-event log read from the deployment block,
halved while the endpoint refuses its range) and `event_filter` (the answer holds only the pool's
four events, and which of them appear). The check reads only; the endpoint URL is never printed.

## Hosting on Arbitrum Sepolia

One node serves one pool. For the Howl test deployment on Arbitrum Sepolia (chain `421614`):

| Variable | Value |
|---|---|
| `HOWL_NODE_RPC_URL` | an Arbitrum Sepolia JSON-RPC endpoint that passes `howl-node check` |
| `HOWL_CHAIN_ID` | `421614` |
| `HOWL_POOL` | the pool proxy of the deployment, e.g. `0x6DABb5682A62b3827eE7e0E02F1DACE896AD457a` |
| `HOWL_DEPLOYMENT_BLOCK` | the block the pool was deployed in, e.g. `312414608` |
| `HOWL_PARAM_SET` | `2` (default) |
| `HOWL_DATA_DIR` | the volume, `/data` by default |
| `PORT` | `8645` by default |
| `HOWL_NODE_OPERATOR_TOKEN` | `openssl rand -hex 32`, kept in the platform's secret store |

Flags such as `--poll-ms`, `--stale-after-secs` or `--max-sessions` go after the image name.

**Image.** Build from the repository root with both submodules checked out (`git submodule update
--init crates/inspire adapters/howl`): `docker build -f adapters/howl-node/deploy/Dockerfile -t
howl-node .`

**Volume.** Mount a persistent volume at `/data` (or `HOWL_DATA_DIR`). It holds the table and the
node's key material; a restart resumes from it, and a new volume replays the chain from the
deployment block.

**Endpoint.** EIP-1898 (`eth_call` by block hash), the pool's full log history from the deployment
block, and the state of the newest `--walk-blocks` (64) blocks plus the blocks made during one step.
A pruned endpoint serves; `howl-node check` confirms all three.

**Endpoint calls**, measured on Arbitrum Sepolia at the default flags against a public endpoint: the
cold catch-up from block 312414608 (15.5 million blocks) took 667 s and about 2,350 calls, and the
node then followed the head for 39 minutes at 4.0 calls a second, 94% of them block headers: the
follower reads the header of every new block to link it to the last. That is about 14,300 calls an
hour, or 10.3 million a month; a plan sized for that serves one node. Each step there took about
12.6 s and read the 47 or so blocks made since the one before, so the served block trails the head
by up to that step time.

**Sizing**, measured with 10^6 leaves on set 2 on a dense synthetic chain: a cold catch-up of 129.9 to
135.6 s at a peak of 2.65 to 2.68 GiB resident; a restart serves again in 12.8 to 14.2 s; the
follower trails a new block by 115 to 131 ms at the median. The data directory held 446 MB at 10^6
leaves on set 1. Two cores and 4 GiB of memory with a 10 GB volume leave room to grow.

**Routes to monitor.** `/howl/v1/health` for the platform's liveness probe, `/howl/v1/ready` for
traffic and alerts, `/howl/v1/status` with the operator token for the freshness and load fields.
