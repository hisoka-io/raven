# @hisoka-io/raven-howl-client

Howl discovery over a Raven Howl node, for wallets.

- The wallet scans the public **tag-prefix feed** (six bytes per leaf) on the device, and
  downloads only the rows past the ones it already holds.
- It reads the 256-byte `howl-note-v1` cells of the positions that match in **private batches**
  (PIR), under a packing key it uploads once per session, or carries in each request.
- It keeps the pool's **tree** as verified level by level and builds a note's depth-32 path at
  any leaf count it chooses, ready for the pool's `isKnownRoot`.

Every answer names the leaf count and the chain block it was read at. Each sync is checked
against the tree the client verified before, so a chain reorganisation under the wallet's cursor
is found, rewound and read again.

## Use

```ts
import * as wasm from "@hisoka-io/howl-client-wasm";
import { RavenHowlSource, fetchTransport } from "@hisoka-io/raven-howl-client";
import { Fr } from "@aztec/foundation/fields";

const source = new RavenHowlSource({
  transport: fetchTransport("https://howl.example"),
  wasm,
  field: { fromBytes: (b) => Fr.fromBuffer(Buffer.from(b)), toBytes: (f) => f.toBuffer() },
  keyMode: "session", // or "inline"
});

const { leafCount, block } = await source.sync(); // feed delta, upper nodes, newest block
const matches = source.matches(candidateTags); // local scan, no request
const records = await source.fetchNotes(matches.map((m) => m.position));
const witness = await source.merkleWitness(records[0].leafIndex); // or (index, leafCount)
```

`RavenHowlSource` also answers Howl's current `DiscoverySource` shape from the feed:
`probeFirst(tags)` and `fetchOccurrences(requests)` give the same records, and
`fetchLeafBlock(blockIndex)` returns a block's leaves from the verified tree.

| Method | What it does |
|---|---|
| `sync()` | pulls the feed from the cursor, the new upper nodes and the newest block past the leaves held (96 bytes when nothing is new); checks the root; reports `rewoundTo` after a reorganisation |
| `matches(tags, from?)` | positions whose feed row equals a tag's low six bytes |
| `fetchNotes(positions)` | private read, one record per position in request order, batches of up to the node's ladder cap |
| `fetchTagPrefixes(since)` | one feed segment as served |
| `fetchLeafBlock(b)` | the leaves of block `b` |
| `merkleWitness(index, leafCount?)` | siblings from level 0 up, the root at that count, folded and checked |
| `snapshot()` | what a wallet stores to resume: feed rows, upper nodes, newest block, state |

A key is built under a secret drawn inside the wasm when a client is created, and never under
one the caller supplies. In `session` mode the source uploads one key per session and opens a
new session, under a new secret, when the node reports the old one expired. In `inline` mode
every request carries a key built for it alone.

## Sizes on the wire

| Item | Bytes |
|---|---:|
| Feed | 6 per leaf |
| Session key upload (once per session) | 46,256 |
| Private read, per slot of a batch, session mode | 15,477 up, 9,874 down |
| Batch framing | 24 up, 58 down |
| Key carried inline | 46,244 more per request |

## Develop

```sh
# the wasm, next to this package
(cd ../client-wasm && wasm-pack build --release --target nodejs --scope hisoka-io \
  --out-dir pkg-node --out-name howl_client_wasm)
pnpm install
pnpm typecheck
pnpm test                                  # offline known-answer tests
HOWL_NODE_BIN=../target/release/howl-node pnpm test   # plus a node following a local anvil chain
```

`HOWL_REPO=<Howl checkout>` adds cross-checks against Howl's own key derivation, codec and
self-mint preflight, and regenerates the vectors in `tests/fixtures/howl-vectors.json` that the
offline tests check (`HOWL_WRITE_VECTORS=1` rewrites them). CI runs the offline tests and the
node suite; `node scripts/check-test-count.mjs` holds the run to the counts in
`tests/EXPECTED_COUNTS.json`.
