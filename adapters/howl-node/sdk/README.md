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
// after opening a record and recomputing its commitment, with no request:
const check = await source.confirmNote(records[0], commitment); // "confirmed" | "unconfirmed"
// at spend time (reads the note's block in plaintext):
const witness = await source.merkleWitness(records[0].leafIndex); // or (index, leafCount)
// witness.leaf must equal the commitment; confirmNote now answers "confirmed" or refuses
```

`confirmNote` refuses a cell that opens but is not the verified tree's leaf at its position. It
never reads a block from the node: when the client does not hold the note's 1,024-leaf block it
answers `"unconfirmed"`, and the check is made at spend time against the witness, whose build
reads that block anyway.

A feed row is six bytes, so a row of another note can match a tag. Read and try to open every
matched position, never only the first: a tag is in use when any of its rows opens.

`RavenHowlSource` also answers Howl's current `DiscoverySource` shape from the feed:
`probeFirst(tags)` reads every matching position in one private read and returns, per tag, the
first record (`record`) and all of them (`positions`, `records`); `fetchOccurrences(requests)`
then answers from those cells, and `fetchLeafBlock(blockIndex)` returns a block's leaves from the
verified tree. Checks that decide whether a tag or index is in use (a self-mint preflight, a
counter reconcile) use `matches(tags)` or the `feed` view of the synced rows, and every record in
`records`.

| Method | What it does |
|---|---|
| `sync()` | pulls the feed from the cursor, the new upper nodes and the newest block past the leaves held (96 bytes when nothing is new); checks the root; reports `rewoundTo` after a reorganisation |
| `matches(tags, from?)` | positions whose feed row equals a tag's low six bytes |
| `feed` | read-only view of the synced feed rows: `length`, `bytes()`, `matches(prefixTags, from?)` |
| `fetchNotes(positions)` | private read, one record per position in request order, batches of up to the node's ladder cap; position 0 (the genesis filler) is refused |
| `confirmNote(record, commitment)` | checks a recomputed commitment against the record's prefix and, when the client holds the note's block, the verified tree's leaf at its position; sends no request; `"unconfirmed"` otherwise |
| `fetchTagPrefixes(since)` | one feed segment as served |
| `fetchLeafBlock(b)` | the leaves of block `b`; a full block the client does not hold is read from the node in plaintext, so call it at spend time, not at discovery |
| `merkleWitness(index, leafCount?)` | siblings from level 0 up, the root at that count, folded and checked; its `block` is the newest verified block, not the block at that count |
| `snapshot()` | what a wallet stores to resume: feed rows, upper nodes, newest block, state |

A key is built under a secret drawn inside the wasm when a client is created, and never under
one the caller supplies. The client reads under the parameter set the node's params answer
names, and refuses answers to its own requests from a node of another set. In `session` mode
the source uploads one key per session and opens a new session, under a new secret, when the
node reports the old one expired. When the node has no seat free, the read carries its key inline
instead, and the source asks for a seat again a minute later. In `inline` mode every request
carries a key built for it alone.

When a private read is refused, or its answer does not open, the source reads the node's params
again once. If the node now serves other material (it restarted under the other parameter set,
or was re-seeded with new key material), the source drops its key and session, builds the same
read again under the node's params, and sends it once; otherwise, or if that read fails too, it
raises the error. The feed, the tree and the cells already read are chain data and stay: after a
re-seed on the same chain the next sync goes on from the cursor.

A private read whose connection closes before any response arrives (a keep-alive socket the node
dropped when it restarted) is sent once more over a new connection with the same bytes. A read
that got any status, or that ran out its timeout, is not sent again by the source. A node over
its rate or with its queue full answers `Busy` (`retryable` is true); `retryAfter` carries the
seconds its `Retry-After` asked for, at most `MAX_RETRY_AFTER_SECONDS`, and the caller chooses
when to call again. A custom transport passes `headers` in its `Exchange` to carry it.

## Multisig

Howl's `MultisigScanner` reads chain events, with all seven ciphertext words and the full
commitment, and keeps its tag maps to itself. `MultisigRavenScan` feeds it from Raven cells:

```ts
import { MultisigRavenScan } from "@hisoka-io/raven-howl-client";

const scanner = await MultisigScanner.create({ v, gpk, compliancePk, memberIds, selfWindow, incomingWindow });
const scan = new MultisigRavenScan({
  source, field, scanner, memberIds, selfWindow, incomingWindow, // the scanner's own windows
  keys: {
    selfTag: async (memberId, j) => { /* deriveSelfEph; null when its y is odd */ },
    incomingAt: async (from) => { /* multisigIncomingKeyAt: { index, tag, secret } */ },
    open: async (record, source, secret) => { /* per content key: reconstructCiphertext with
      owner = multisigOwner(gpk), demDecrypt, leaf -> [{ words, commitment }] */ },
  },
});
const { found, refused, unopened } = await scan.scan(); // found[i].view is the scanner's own view
```

It registers the tags the scanner registers, under the same lookahead rules, probes them, opens
every matched position of the right record kind, accepts a note whose commitment starts with the
cell's 16-byte prefix, checks it with `confirmNote`, and passes the scanner the event it would have
read from the chain. Windows grow on both sides from the same notes, so a note past the first
window is reached in a later round of the same scan.

A FROST spend signs a message that binds the tree root. The coordinator takes every path of a
session at one leaf count, and each signer checks the session against its own client before it
commits:

```ts
const { session, witnesses } = await openSigningSession(source, [leafIndex], leafCount); // { leafCount, root, notes }
// each signer, with the notes its own scan found (leaf index -> commitment):
await checkSigningSession(mySource, field, session, myNotes); // throws SigningSessionRefused
```

A signer refuses a note its scan did not find (`unknown-note`), a tree leaf that is not that note
(`leaf`), a path that folds to another root at the session count (`root`), or a count its node
does not reach (`count`). The root must still be known on chain before proving.

## Sizes on the wire

| Item | Parameter set 1 | Parameter set 2 |
|---|---:|---:|
| Feed | 6 per leaf | 6 per leaf |
| Session key upload (once per session) | 46,256 | 15,364 |
| Private read, per slot of a batch, session mode | 15,477 up, 9,874 down | 7,460 up, 9,212 down |
| Batch framing | 24 up, 58 down | 15 up, 58 down |
| Key carried inline | 46,244 more per request | 15,352 more per request |

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
self-mint preflight, a FROST group's multisig scan and signing session on both parameter sets, and regenerates the vectors in `tests/fixtures/howl-vectors.json` that the
offline tests check (`HOWL_WRITE_VECTORS=1` rewrites them). CI runs the offline tests and the
node suite; `node scripts/check-test-count.mjs` holds the run to the counts in
`tests/EXPECTED_COUNTS.json`.
