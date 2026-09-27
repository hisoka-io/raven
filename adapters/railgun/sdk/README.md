# @hisoka-io/railgun-poi-node-interface

A `POINodeInterface` for the Railgun engine. It resolves PPOI status, PPOI auth-paths and
commit-tree auth-paths from a Raven Railgun adapter server, by client-side PIR unless configured
otherwise.

## Install

```sh
npm install @hisoka-io/railgun-poi-node-interface
```

```ts
// ESM, and any bundler
import { RavenPOINodeInterface } from "@hisoka-io/railgun-poi-node-interface";
```

```js
// CommonJS, which is what a `tsc`-built wallet emits
const { RavenPOINodeInterface } = require("@hisoka-io/railgun-poi-node-interface");
```

Node 20 or newer. The package ships a CommonJS build and an ESM build with a `.d.ts` beside each,
selected through conditional `exports`; no TypeScript source is on any resolution path a loader
takes. From a checkout, `pnpm install && pnpm run build` produces both, `pnpm pack` produces the
tarball a consumer installs, and `adapters/railgun/scripts/check-sdk-pack.sh` installs that tarball
into a throwaway CommonJS project and a throwaway ESM project and refuses a tarball that is not the
intended surface.

### The PIR client WASM is supplied by the caller

Client-side PIR needs `raven-inspire-client-wasm`, the wasm-pack output of
`adapters/railgun/client-wasm`. No module under `src/` imports it: the caller loads it and passes it
in through `clientPirContexts`, typed as `RavenInspireWasm`, so the shape this package depends on is
the interface, not the artifact.

It is a development dependency only, for this package's own tests, so installing the SDK installs
no WASM: the caller adds `raven-inspire-client-wasm` to its own dependencies. How that package is
published is still open.

### Engine is a peer, never a dependency

`RavenPOINodeInterface` is assignable to `POINodeInterface` from `@railgun-community/engine`, and its
declarations import engine's types. Engine is therefore an optional peer dependency
(`^9.6.0 || 9.7.0-rc.0`), which shares the copy your wallet already has and can never install a
second one. That matters because engine's injection seam, `POI.init`, is a static on a class: an
interface installed through a second copy is never read by the wallet's, and nothing reports it.

The range is written out because a prerelease satisfies only a range that names its own version:
`^9.6.0` does not admit `9.7.0-rc.0`, which `@railgun-community/wallet@10.10.0-rc.1` pins exactly.
`adapters/railgun/scripts/check-sdk-engine-singleton.sh` installs the packed SDK beside that wallet,
with npm's default resolution and with `--legacy-peer-deps`, and requires one engine copy on disk,
one resolved file, and a consumer that typechecks against it.

Engine's status values are a string enum, which no string literal satisfies, so the engine-shaped
`getPOIsPerList(txidVersion, chain, listKeys, commitments)` is typed with engine's own
`POIsPerList`. The two-argument `getPOIsPerList(listKeys, commitments)` returns
`PoisPerListResponse`, which adds the SDK-local verdicts `Unreachable` and `MissingStale`.

The two shapes fail differently, because engine runs its receive refresh, legacy submission, spent
refresh and spend-POI generation in one chain that a rejection cuts short:

- The engine-shaped `getPOIsPerList` never rejects over a failed list or commitment. Engine
  replaces a commitment's whole stored map with the one it is handed, so a commitment whose verdict
  on any asked list could not be established (a failed or stale request, a missing context, an
  absence that cannot be shown current, or an SDK-local verdict) is left out of the result, and
  engine keeps what it held. In plaintext mode it asks in batches of 20, as the stock interface does.
- The engine-shaped `submitLegacyTransactProofs` submits in batches of 20 and never rejects: a
  failed batch, or no `upstreamFallbackEndpoint` to send to, leaves those proofs for engine's next
  refresh.
- The engine-shaped calls still refuse a `txidVersion` or chain other than the configured one.
- The two-argument overloads raise the typed `RavenError`s described below.

## How it plugs in

`RavenPOINodeInterface` implements Railgun's abstract `POINodeInterface`, the same class the stock `WalletPOINodeInterface` implements:

```ts
import { RavenPOINodeInterface } from "@hisoka-io/railgun-poi-node-interface";

const poi = new RavenPOINodeInterface({
  endpoint: "https://raven.example.com",
  // Optional; see "The credential is optional" below before leaving it out.
  bearerToken: process.env.RAVEN_BEARER_TOKEN,
  // Used by validation/submission; private stale reads still refuse by default.
  upstreamFallbackEndpoint: "https://ppoi.fdi.network",
});
```

Every request the interface sends carries a deadline, `requestTimeoutMs`, from sending it to its
last body byte: 60,000 ms by default, which is what the stock interface allows a POI node request.
A request past it fails as `Network`. The deadline covers the whole body, so a caller of
`fetchBcToIdxMap` on a slow link raises it: that body is tens of megabytes on a large list (see
below).

### The credential is optional

`bearerToken` is sent as `Authorization: Bearer <token>` on every request to `endpoint`, and never
to `upstreamFallbackEndpoint`. Leave it out, or pass `undefined`, and the SDK sends no
`Authorization` header at all -- the same shape as Railgun's own POI node client, which addresses a
node by URL alone.

**Leaving it out works only against a node that does not require a credential.** A node that does
answers `401` on every route the SDK uses, which surfaces as a typed `ServerError` `RavenError`
carrying `status: 401`. A stock Raven adapter is no longer such a node -- its read routes carry no
credential, and the PPOI list they serve is public data either way. Pass a token only when the
operator says their node wants one. Two routes still refuse without one, and the SDK calls neither:
`/v1/admin/*`, and `/metrics` while `metrics_public` is false, which is its default.

A token that is empty, has leading or trailing whitespace, or holds anything but printable ASCII
is refused at construction with `InvalidQuery`, and the message never quotes it. The SDK never
interpolates what it was given: `process.env.RAVEN_BEARER_TOKEN!` with the variable unset is
`undefined` at runtime whatever its type says, and that is treated as no credential rather than
sent as `Authorization: Bearer undefined`, a request that looks authenticated and is not.

Wiring it into a wallet needs no Railgun change and no fork: engine's public `POI.init(lists,
nodeInterface)` is the injection point. `startRailgunEngine` still takes `poiNodeURLs`, since the
wallet refuses to load a POI network without them and uses them for its txid merkleroot validation,
which this package does not replace. It then installs the stock `WalletPOINodeInterface` through
`POI.init`; calling `POI.init` again afterwards, from the same engine copy (see above), installs this
one in its place:

```ts
import { POI } from "@railgun-community/engine";
import { POI_REQUIRED_LISTS } from "@railgun-community/shared-models";

await startRailgunEngine(/* ..., */ poiNodeURLs /* , ... */);
POI.init([...POI_REQUIRED_LISTS, ...customPOILists], poi);
```

`POI.init` installs one interface for every chain the engine runs. This one answers only its
configured chain: on any other it reports POI as not required and is inactive, so install it only in
a wallet that runs that one chain.

## What it routes

| Method                       | Client-PIR (default)             | Plaintext (`useClientPir: false`)         |
|------------------------------|----------------------------------|-------------------------------------------|
| `getPOIsPerList`             | `POST /v1/instance/:id/batch`    | `POST /v1/poi/pois-per-list`              |
| `getPOIMerkleProofs`         | `POST /v1/instance/:id/batch`    | `POST /v1/poi/merkle-proofs`              |
| `getMerkleProof`             | `POST /v1/instance/:id/batch`    | `POST /v1/commit-tree/:tree/merkle-proof` |
| `validatePOIMerkleroots`     | upstream JSON-RPC                | upstream JSON-RPC                         |
| `submitPOI`                  | upstream JSON-RPC                | upstream JSON-RPC                         |
| `submitLegacyTransactProofs` | upstream JSON-RPC                | upstream JSON-RPC                         |

Only the client-PIR column is private: the plaintext routes carry the blinded commitments or the
leaf index in the request body. The upstream calls go to `upstreamFallbackEndpoint` in plaintext, as
the stock interface's go to its POI node, and refuse when it is not configured, except the
engine-shaped `submitLegacyTransactProofs` above.

`getMerkleProof` returns a `CommitTreeProof` of `kind: "authPath"` on both paths: `elements` and
`indices`, and **no root**. PIR fetches the 16 auth-path siblings; it never fetches the leaf, so there
is nothing to fold a root from. A caller that needs a root fetches the leaf row itself and folds with
the exported `foldMerkleRoot`.

Public-info channels (cacheable, no per-BC leak):

| Call                                         | Route                              |
|----------------------------------------------|------------------------------------|
| `fetchBcToIdxMap` (method)                   | `GET /v1/poi/:list/bc-to-idx-map`  |
| `syncPoiListIndex` (method)                  | `GET /v1/poi/:list/bc-prefixes`    |
| `fetchBcPrefixIndex` (exported function)     | `GET /v1/poi/:list/bc-prefixes`    |
| `fetchStatusHeader` (method)                 | `GET /v1/poi/:list/status-header`  |

`fetchBcToIdxMap` returns the channel's rows as `{ epoch, listKey, rows, entries }`, parsed rather
than cast. The node publishes a gap-free prefix of the list in index order, so entry `i` must be row
`i`: a body that is not JSON, answers for another list, or has a row repeated or out of place is
refused with a typed `DecodeError`. The body carries no count of its own, so the call first walks
the prefix channel and then compares the body with it row by row. The list only grows, so these are
refused with a `DecodeError` too: a body shorter than that walk (cut, or served from an older copy),
a body longer than the list the channel serves when read again, and any row whose prefix differs,
including a row hidden by relabelling every row after it. A body that an append overtook between
the two reads is accepted after one read of the new tail. Both reads are sent with
`cache: "no-cache"`. The check costs one walk of the prefix channel, 6 B a row: 2,150,064 B at
N = 358,344 (2026-09-20T08:14:13Z, derived), beside the 31,064,918 B body it checks at that N.
A wallet that needs only its own notes' indices should hold an index from `syncPoiListIndex` (next
section) and skip the JSON channel entirely.

Build a `bcToIdxMaps` preload from the rows with **`bcToIdxMapFrom(entries)`**, not
`new Map(entries)`: the channel emits one row per LEAF and a commitment may recur within a list, so
`new Map` is last-wins and keeps the highest occurrence while the adapter resolves to the lowest -- a
different leaf, in a possibly different PPOI block, verified against a different root, and carrying
the same commitment so the row-binding guard cannot tell the two apart. The helper also strips and
lower-cases the key, which the internal lookup matches exactly. A map carries no row count, so read
the next section before relying on one.

`bc-prefixes` publishes the same index as **6 bytes per row instead of ~86**, segmented one block per
response with a `?since=N` cursor and an immutable `Cache-Control` on any sealed block. Measured
against a two-block fixture (N = 65,539): **393,234 B over two responses** versus **5,625,348 B in
one** -- a 14.3x saving, and the only one of the two a client can resume rather than re-download
whole.

`fetchBcPrefixIndex` walks every segment and returns `{ epoch, prefixes, total }`. A sealed segment
carries only its own cursor (`x-raven-index-base`, `x-raven-index-next`); the list-wide
`x-raven-index-total` and `x-raven-index-epoch` ride on the frontier segment alone, and the walk
reads them only there. A cache may replay a sealed segment for a year, so a total read off one
would contradict the frontier's, and a stale total equal to the segment's own cursor would end the
walk early with no error. A cross-origin browser can read all four once the wallet's origin is in
the server's `cors_allowed_origins`, which exposes them.

**The epoch says nothing for a PPOI list.** Mirrored rows carry no chain height, so it is always 0,
and a lookup with no candidates means *"absent from the first `total` rows"*, not *"absent from the
list"*. `total` is the quantity that moves when the list grows, so it is what the SDK binds an index
to; see the next section.

**A six-byte prefix is not a commitment**, so `indexCandidatesFor` returns every matching row rather
than the first. A blinded commitment is a BN254 field element, so its first six bytes take about
2^45.6 values, not 2^48; over ~360k rows the chance that some two rows share a prefix is about 0.12%.
Unlikely, not impossible, and a client that assumed uniqueness would eventually fetch the wrong row.
Resolving a candidate costs nothing extra: the served row carries the full commitment in its first
32 bytes and the fold path already refuses a row whose commitment is not the one asked for.

A wallet proving its own notes wants this rather than the whole map -- it holds K commitments and
needs K indices, not the entire list.

## An absence is answered only at the row count the node serves

A commitment with no index has no row to query, so its `Missing` is decided by the index alone and no
row's commitment check ever runs. An index one append behind the list therefore reads a real member
as `Missing`, and that is the verdict a wallet acts on. The SDK closes this by binding every index to
the list's row count and bringing it up to the node's count on each call:

```ts
const poi = new RavenPOINodeInterface({ endpoint, clientPirContexts });
await poi.syncPoiListIndex(listKey); // first run: walks the prefix channel once, ~6 B per row
// every later getPOIsPerList / getPOIMerkleProofs re-reads only the index's tail first
```

- **Each client-PIR call on an index first syncs it.** The sync re-reads from a multiple of
  `BC_INDEX_RESUME_ALIGN_ROWS` (2,048) below the rows held, so the cursor it sends names a window of
  about three days of list growth rather than the exact row a client last reached, which would link
  its calls and its restarts. The re-read rows are compared with what is held: the list is
  append-only, so a difference is the node contradicting itself and is refused (`DecodeError`), as
  is a node serving fewer rows than the index holds (`StaleAdapter`). The sync request is sent
  whatever the commitments are, so it says nothing about membership, and it carries the bearer
  credential but never the PIR client id. It is sent with `cache: "no-cache"`: the frontier is
  served `max-age=15`, and a browser or CDN answering from its copy would let an absence read as
  current against a list up to 15 s old. Syncs of one index run one at a time, so a slower one
  never lands an older list over a newer one.
- **An index this node did not produce is re-read in full.** One passed in `poiListIndexes` is
  compared row by row against the prefix channel on its first sync, because an absence is answered
  from the index alone and a row changed anywhere in it would silently turn a member into a
  non-member. After that it is held as the node's own, and later syncs re-read only the tail.
- **Only then is an absence `Missing`**, and it is counted as `absent` in `indexCounters()`.
- **An absence that cannot be shown current is refused by default.** That is an index whose sync
  failed, or a `bcToIdxMaps` entry, which has no row count at all. `indexStalenessPolicy:
  "answer-at-index-rows"` is the explicit decision to answer it anyway, and it answers the SDK-local
  verdict `MissingStale`, never `Missing`, so each verdict says which kind of absence it is, per
  commitment and per list. Those answers are counted apart, as `absentFromStaleIndex` or
  `absentFromBareMap`. Under the default, a sync that fails on the network reads `Unreachable` for
  the absences in the two-argument `getPOIsPerList`, as a failed query does. The engine-shaped call
  answers neither `MissingStale` nor `Unreachable`: it leaves the commitment out.
- **A failed sync costs only the absences.** A commitment the held index has a row for is still
  asked, and its row confirms it: a row the list holds never moves. So `getPOIsPerList` still answers
  members and `getPOIMerkleProofs` still proves them; only a commitment with no row is refused, with
  the sync's own error kind.
- **A proof has no answer for an absence**, so `getPOIMerkleProofs` refuses every kind, and its
  refusal says whether the absence is from the node's list or could not be shown current. It is
  counted in the `indexCounters()` field the same absence takes in `getPOIsPerList`.
- **A prefix is not a commitment**, so a candidate is confirmed by the row it returns: a row carrying
  the same six-byte prefix but another commitment moves the SDK to the next candidate in a second
  round, and a row that does not even carry the prefix is refused rather than read as absent. The
  lowest confirmed candidate wins, which is the occurrence the adapter resolves to.

What no channel on the node can show is a node that serves the same shorter list everywhere: that
reads exactly like a node that has not ingested the tail yet, and for a PPOI list nothing the node
publishes tracks that lag. The freshness header's `applied_height` is 0 for a mirrored list and its
`lag_blocks` follows the chain, not the list. Only a total read from upstream could tell the two
apart.

### The index survives a restart

`syncPoiListIndex` and every sync that moves the index write it to `poiListIndexStore`: IndexedDB by
default where the runtime has it (`indexedDbPoiListIndexStore`). Node has none, so a Node wallet
passes its own `{ load, save }` over whatever it persists to; the record is opaque bytes. A restarted
client reads the index from the store, so `poiListIndexCandidates(listKey, commitment)` resolves an
index with no request at all, and its next call resumes from the stored cursor. Calls that arrive
while the store is being read all wait for that one read, so a wallet's first calls after a start,
which arrive together, all resolve from it. Records are keyed by
chain, node and list, carry their list key and a SHA-256 digest, and anything that does not verify is
ignored and costs a re-walk, never an answer. A failed save is swallowed for the same reason.

A record is written only after a sync against that same node, so every row in it was served or
confirmed by that node, and a restart re-reads only the tail rather than the whole list again. The
rows below the cursor are not re-read on each start: re-reading them is the full walk the store
exists to avoid, and a re-read of the same node could catch only a row it once served wrongly and
later corrected, never one it serves wrongly throughout.

## One-query cover fanout

`queryClientPirFanout(instanceId, context, targetIndex, realShardIds, shardCount)` sends one
encrypted local-index query to `POST /v1/instance/:id/fanout`. It pads the shard list to the same
dyadic ladder used by batches, adds distinct complement shards with browser CSPRNG draws, shuffles
all slots, and restores decrypted real rows to caller shard order.

The serialized query also contains a clear shard selector even though the fanout server overrides
it per slot. The SDK retargets that field through the typed Rust/WASM decoder to an independently
sampled member of the shuffled list, so it cannot remain an original-target marker. Low-level cover
plans are runtime-issued, immutable, capped at 32 slots and rejected if forged.

The adapter operator must enable the fanout route and configure `max_fanout_shards` for the ladder
step the client will use. Private freshness remains fail-closed; fanout has no plaintext upstream
fallback.

## PPOI status verdicts are bound to the blinded commitment

A T1 status row is `[status_byte, blinded_commitment[0..min(recordSize - 1, 32)]]`. Rows for list
indices that hold no record are zero-filled, and status byte `0` means `Valid`, so a decode that
reads only byte 0 turns an absent record into the verdict that authorises a spend. `getPOIsPerList`
therefore compares the row's BC tail against the blinded commitment it asked about and raises a
typed `DecodeError` `RavenError` on any mismatch -- including the all-zero row -- rather than
returning a status.

On the two-argument call a `Network` failure returns the SDK-local `Unreachable` verdict. It never
degrades to the adapter's non-blocking `Missing` verdict, so callers can distinguish an absent PPOI
record from a request that never reached the adapter. The engine-shaped call leaves such a
commitment out, as it does a row that fails the binding check.

Two limits are worth stating plainly. At the narrowest record width the encoder builds (32 bytes) the
row has room for `bc[0..31]`, so the binding covers 31 of the 32 BC bytes; a wider record binds all
32. And the row's status byte is only as trustworthy as the adapter that wrote it: this check proves
the row describes *your* BC, not that the verdict inside it is correct.

## Private freshness policy

Every PIR response carries
`X-Raven-Freshness: lag_blocks=N applied_height=M epoch=E confidence=0.X`. In client-PIR mode,
confidence below `freshnessConfidenceFloor` (default 0.5) raises a typed `StaleData` error even when
`upstreamFallbackEndpoint` is configured; the engine-shaped `getPOIsPerList` leaves that request's
commitments out instead. The error carries the public freshness values but no blinded commitment,
list key, token, or URL.

`freshnessConfidenceFloor` must be finite and within `[0,1]`; invalid values are rejected with
`InvalidQuery` during construction. A missing private freshness header raises `StaleAdapter`, and a
malformed one raises `DecodeError`, because neither can supply the fields required by `StaleData`.

Falling back upstream sends the exact commitment and list in plaintext. Callers who deliberately
choose freshness over query privacy must opt in:

```ts
const poi = new RavenPOINodeInterface({
  endpoint: "https://raven.example.com",
  bearerToken: process.env.RAVEN_BEARER_TOKEN,
  upstreamFallbackEndpoint: "https://ppoi.fdi.network",
  privateStalePolicy: "allow-upstream-disclosure",
});
```

Fresh private responses remain private under either policy. Plaintext mode retains its existing
fallback because contacting upstream discloses nothing beyond the plaintext request already sent.

## Verifying a served auth path

A PIR-served PPOI auth path arrives as sibling hashes. Folding them yields a root, but a root the
same node supplied would verify nothing, so the SDK compares the fold against a root obtained
independently:

1. A root you pinned yourself in `ppoiPinnedRoots` always wins.
2. Otherwise the SDK asks the upstream PPOI aggregator directly, over the wallet's own `fetch`,
   never through the Raven node.
3. Otherwise it refuses. The client-PIR path never returns an unverified proof.

`pinUpstream` defaults to `upstreamFallbackEndpoint`, so the configuration above needs no new
field: the wallet already opens TLS to that host for validation and submission, and no new party
is introduced. Set `pinUpstream: false` to disable the resolver and require a hand-loaded pin.
**There is no default hostname** -- with no upstream configured the resolver is inert and step 3
applies.

Both pin requests are a function of public state only: the list key, a block number, and
upstream's own tip. No blinded commitment is sent, and the aggregator's own API takes none.

Be precise about what that does and does not hide. The **block** is derived from the note's leaf
index, so a pin request tells the aggregator which 65,536-leaf block your note sits in -- today that
is roughly one-in-six for the OFAC list, and it narrows further as blocks are added. It does not
reveal which note. Requests for the same block are identical between wallets apart from the
JSON-RPC `id`, and a burst of proofs against one Raven snapshot costs one block-naming request
rather than one per proof.

Not once per cache window, which this paragraph claimed until it was measured. A fold whose root
has moved off the cached window makes the SDK forget the tail and re-resolve, and a re-resolve
starts with the block-naming query. Every insert into a filling block moves every auth path in it,
so a list that takes a leaf between two of your proofs is back to one block-naming request per
proof -- as is a node lagging 64 or more leaves behind you (the window is the 64 indices
`tip-63 .. tip`, so a node exactly 64 behind is already outside it), which pays it on every proof while
refusing every proof. If you want the block hidden too, preload `ppoiPinnedRoots` for every block
from a source you already trust; the resolver is then never consulted.

A pin source that names the same **origin** as the endpoint being verified is refused: setting
`pinUpstream` to it throws at construction, and inheriting such a value leaves the resolver inert
rather than verifying in a circle. Scheme case, a default port, a trailing slash and an extra path
segment all resolve to the same origin and are all caught. A `pinUpstream` that is neither an
http(s) URL nor a same-origin path is refused as malformed and says so -- it used to be reported as
a circularity, sending operators to look for one that was not there.

This is a misconfiguration guard, not a security boundary, and the difference is worth stating. It
cannot prove two host*names* are different parties: `localhost` and `127.0.0.1` are distinct origins
that reach the same process, and two DNS names can resolve to one host. If you point the pin source
at the node you are verifying by a name the guard cannot recognise, verification is vacuous and
nothing will tell you. **Choose a pin source you know is operated by someone else.**

On a chain other than Ethereum mainnet, set `pinUpstreamNetworkName` to the name upstream reports
under `forNetwork`. An unrecognised chain refuses rather than guessing, because guessing would
read another chain's tip and refuse honest proofs.

## IMT cache layers

The client-side IMT (Incremental Merkle Tree) node cache (entry point: `ImtCache` in [`src/imt-cache.ts`](src/imt-cache.ts)) is layered:

- **L1 -- `InMemoryLru`** (always present). Bounded `Map`-backed LRU; default capacity 1024 entries x 32 byte values = ~32 KB. Synchronous `getSync`/`set` fast-path.
- **L2 -- IndexedDB** (when `globalThis.indexedDB` is exposed, which browsers do and Node does not). Lazily opened on first use; reads promote IDB hits back into L1.

There is **no `localStorage` L2.** Every supported browser ships IndexedDB, so a synchronous-blocking 5 MB key-value store would only add eviction-policy complexity without unlocking a real environment. In the rare no-IDB case (Safari private browsing on older versions, custom embedders that strip IDB), the L1 in-memory layer alone is the fallback -- the cache is best-effort, not authoritative.

Cached nodes are tagged with the snapshot epoch of the instance they came from, read off the `X-Raven-Epoch` header of every batch response. Four rules keep a served auth path current:

- **A batch reply without `X-Raven-Epoch` is refused.** The nodes cannot be pinned to a snapshot, so the SDK raises a typed `StaleAdapter` `RavenError` instead of caching them. An empty header value counts as absent.
- **Every level of one path resolves at one epoch.** If a batch response reports an epoch newer than the cached levels already gathered, those levels are discarded and the path is reassembled, so a proof is never folded from siblings of two different trees.
- **A fully-cached path still sends its batch.** It re-queries every level, so the request carries the same slot count as a cold path and the wire never publishes that the wallet already holds the path. There is no `GET /v1/status` shortcut: the reply's own `X-Raven-Epoch` is the revalidation.
- **An unreachable revalidation fails closed.** A failed batch raises a typed `RavenError` rather than returning cached nodes the SDK can no longer certify.

`X-Raven-Schema-Version` invalidates independently. A value that is not a decimal non-negative
integer is refused with a typed `StaleAdapter` `RavenError`: handing `NaN` to the cache would make its
"same epoch and schema, keep the nodes" comparison unreachable (`NaN !== NaN`) and purge the scope on
every reply. An absent or empty value is treated as absent, matching the epoch rule. Invalidation is
scoped to one instance: `noteFreshness(scopeKey, epochTag, schemaVersion)` drops only that instance's nodes from both layers, because snapshots advance per instance and a list instance's epoch says nothing about a tree instance's cached nodes. A scope the cache holds no recorded tuple for (a fresh page over a surviving IndexedDB layer) is dropped rather than trusted. Build `scopeKey` with the exported `imtCacheScopeKey({ chainId, scope })`.

## Session persistence is opt-in

`loadClientPirContext` builds the per-instance PIR session. Passing `persistSession: true` caches
that session in IndexedDB keyed `(instanceId, sha256(crsBincode))`, so a later page load skips
`build_client_session` and a CRS rotation self-invalidates.

**The cached blob contains the client's RLWE secret key.** Enabling it places a secret at rest in the
browser's storage, where anything with same-origin script access can read it. It defaults to `false`
and a wasm build merely exposing `serialize_client_session` does not enable it; pass it only with the
user's informed consent, and prefer leaving it off on shared or untrusted devices. With it off, no
session blob is read or written and every load takes the cold `build_client_session` path.
