# @hisoka-io/railgun-poi-node-interface

A `POINodeInterface` for the Railgun engine. It answers PPOI status on the device, from the list
index it syncs from a Raven Railgun adapter server, and fetches PPOI auth paths from that server by
client-side PIR.

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

### Engine is an optional peer: the package needs its types only

This package is useful only inside a Railgun wallet, and it needs `@railgun-community/engine` for
its types alone: `RavenPOINodeInterface` is assignable to engine's `POINodeInterface`, and the
published declarations import engine's types. Every Railgun wallet already has engine, directly or
through `@railgun-community/wallet`, so engine is an optional peer (`^9.6.0 || 9.7.0-rc.0`): installing
this package installs no engine, and its types resolve against the copy your wallet has. Nothing
in it loads engine at runtime; a test refuses any `src/` import of engine that is not
`import type`, and the pack gate's consumers hold a stand-in engine that throws if loaded.

One copy matters because engine's injection seam, `POI.init`, is a static on a class: an interface
installed through a second copy is never read by the wallet's, and nothing reports it.
`PerChainPOINodeInterface.install(POI, ...)` refuses with `InvalidQuery` when the `POI` it is given
holds no interface, which is how a copy the wallet never started looks; a direct `POI.init`
through such a copy succeeds and is never read. The wallet package does not export `POI`, so the
code that calls `install` imports it from `@railgun-community/engine`, and should list it. List it at
the version your `@railgun-community/wallet` depends on: a different version is what installs a
second copy.

The range is written out because a prerelease satisfies only a range that names its own version:
`^9.6.0` does not admit `9.7.0-rc.0`, which `@railgun-community/wallet@10.10.0-rc.1` pins exactly.
`adapters/railgun/scripts/check-sdk-engine-singleton.sh` installs the packed SDK beside that wallet
with npm, first with nothing else and then with engine listed at the wallet's version (under npm's
default resolution and under `--legacy-peer-deps`), and requires one engine copy on disk, one
resolved file, a consumer that typechecks against it, and `install` landing on the copy the wallet
reads. A fourth install lists engine at another version, forcing a second copy, and requires
`install` to refuse.

Engine's status values are a string enum, which no string literal satisfies, so the engine-shaped
`getPOIsPerList(txidVersion, chain, listKeys, commitments)` is typed with engine's own
`POIsPerList`. The two-argument `getPOIsPerList(listKeys, commitments)` returns
`PoisPerListResponse`, with the same four verdicts spelled as strings.

The two shapes fail differently, because engine runs its receive refresh, legacy submission, spent
refresh and spend-POI generation in one chain that a rejection cuts short:

- The engine-shaped `getPOIsPerList` never rejects. Engine replaces a commitment's whole stored map
  with the one it is handed, so a commitment whose verdict on a served list could not be
  established (the list's index could not be synced, or the submitted-proof store could not be
  read for an absent commitment) is left out of the result, and engine keeps what it held.
- The engine-shaped `submitLegacyTransactProofs` submits in batches of 20 and never rejects: a
  failed batch, or no `upstreamFallbackEndpoint` to send to, leaves those proofs for engine's next
  refresh.
- Engine refreshes each active `txidVersion` from a promise it does not await, where a rejection
  goes unhandled. So for a `txidVersion` or chain other than the configured one, the engine-shaped
  `getPOIsPerList` answers an empty map and `submitLegacyTransactProofs` sends nothing; neither
  sends a request. An interface configured for one `txidVersion` therefore never makes a note of
  another spendable. The engine-shaped `getPOIMerkleProofs` and `validatePOIMerkleroots` refuse
  such a call with `InvalidQuery`, as the stock interface lets their failures through.
- The two-argument overloads raise the typed `RavenError`s described below.

## How it plugs in

`RavenPOINodeInterface` implements Railgun's abstract `POINodeInterface`, the same class the stock
`WalletPOINodeInterface` implements:

```ts
import { RavenPOINodeInterface } from "@hisoka-io/railgun-poi-node-interface";

const raven = new RavenPOINodeInterface({
  endpoint: "https://raven.example.com",
  // Optional; see "The credential is optional" below before leaving it out.
  bearerToken: process.env.RAVEN_BEARER_TOKEN,
  // Used for submission, root validation and block-root pins.
  upstreamFallbackEndpoint: "https://ppoi.fdi.network",
  // One context per list; see loadClientPirContext.
  clientPirContexts: new Map([[`t2Path:1:${listKey}`, pathContext]]),
  // One path instance per 65,536-leaf PPOI block of the list.
  clientPirInstanceLabels: new Map([
    [`t2Path:1:${listKey}:0`, "ppoi-paths-ofac-0"],
    [`t2Path:1:${listKey}:1`, "ppoi-paths-ofac-1"],
    // ...one per block the list has
  ]),
});
```

A list is served on the interface's chain exactly when `clientPirContexts` holds a
`t2Path:<chainId>:<listKey>` context for it. Every key names the chain: a key without it matches
nothing.

Every request the interface sends carries a deadline, `requestTimeoutMs`, from sending it to its
last body byte: 60,000 ms by default, which is what the stock interface allows a POI node request.
A request past it fails as `Network`.

### One interface for every chain

Engine's public `POI.init(lists, nodeInterface)` installs one interface for every chain the engine
runs, while a `RavenPOINodeInterface` answers for one chain. `PerChainPOINodeInterface` sends each
call to the Raven interface serving the call's chain and every other chain to the stock interface,
unchanged. `startRailgunEngine` installs the stock `WalletPOINodeInterface`, which
`@railgun-community/wallet` does not export, so `PerChainPOINodeInterface.install` takes the
interface engine holds at that point and installs the router in front of it:

```ts
import { POI } from "@railgun-community/engine";
import { POI_REQUIRED_LISTS } from "@railgun-community/shared-models";
import { PerChainPOINodeInterface } from "@hisoka-io/railgun-poi-node-interface";

await startRailgunEngine(/* ..., */ poiNodeURLs, customPOILists /* , ... */);
PerChainPOINodeInterface.install(POI, [...POI_REQUIRED_LISTS, ...customPOILists], [raven]);
```

Engine keeps that interface in a private static, which `install` reads; it refuses, with
`InvalidQuery`, when engine holds none (the engine was started without `poiNodeURLs`) or already
holds a router. A wallet that builds its own stock interface passes it directly:
`POI.init(lists, new PerChainPOINodeInterface(stock, [raven]))`.

On a chain no Raven interface serves, `isRequired`, `isActive` and every POI call are the stock
interface's, errors included. On a chain one serves, the Raven interface answers everything and
`isRequired` is `true`. Two Raven interfaces for one chain are refused at construction. Wiring it
needs no Railgun change and no fork, and it must use the same engine copy the wallet uses (see
above). `startRailgunEngine` still takes `poiNodeURLs`: the wallet refuses to load a POI network
without them and uses them for its txid merkleroot validation, which this package does not replace.

A bare `RavenPOINodeInterface` installed with `POI.init` reports every chain but its own inactive,
and its `isRequired` refuses such a chain with `InvalidQuery` rather than answer `false`, which
engine would read as every balance on that chain spendable. Install it without the router only in a
wallet that runs that one chain.

### The credential is optional

`bearerToken` is sent as `Authorization: Bearer <token>` on every request to `endpoint`, and never
to `upstreamFallbackEndpoint`. Leave it out, or pass `undefined`, and the SDK sends no
`Authorization` header at all -- the same shape as Railgun's own POI node client, which addresses a
node by URL alone.

**Leaving it out works only against a node that does not require a credential.** A node that does
answers `401` on every route the SDK uses, which surfaces as a typed `ServerError` `RavenError`
carrying `status: 401`. A stock Raven adapter is no longer such a node -- its read routes carry no
credential, and the PPOI list they serve is public data either way. Pass a token only when the
operator says their node wants one.

A token that is empty, has leading or trailing whitespace, or holds anything but printable ASCII
is refused at construction with `InvalidQuery`, and the message never quotes it. The SDK never
interpolates what it was given: `process.env.RAVEN_BEARER_TOKEN!` with the variable unset is
`undefined` at runtime whatever its type says, and that is treated as no credential rather than
sent as `Authorization: Bearer undefined`, a request that looks authenticated and is not.

## What it routes

| Method                       | Where it goes                                          |
|------------------------------|--------------------------------------------------------|
| `getPOIsPerList`             | `GET /v1/poi/:list/bc-prefixes` (the index sync), then answered on the device |
| `getPOIMerkleProofs`         | the index sync, then `POST /v1/instance/:id/batch` to the block's path instance |
| `validatePOIMerkleroots`     | upstream JSON-RPC                                      |
| `submitPOI`                  | upstream JSON-RPC                                      |
| `submitLegacyTransactProofs` | upstream JSON-RPC                                      |

The upstream calls go to `upstreamFallbackEndpoint` in plaintext, as the stock interface's go to its
POI node, and refuse when it is not configured, except the engine-shaped
`submitLegacyTransactProofs` above. No call sends upstream a status or proof question about a
commitment. The block-root pins below also read from upstream.

## Status is answered on the device

`getPOIsPerList` syncs each served list's index from the node and answers from it, per commitment
and list:

- **`Valid`** when the commitment's six-byte prefix is among the rows synced in this call;
- **`ProofSubmitted`** when this device submitted a proof covering the commitment for that list,
  through `submitPOI` (its output commitments, and the unshield's when there is one) or
  `submitLegacyTransactProofs`, and upstream accepted it, and the commitment is not yet in the
  index;
- **`Missing`** otherwise.

The only requests are the index syncs. Their cursors are multiples of 2,048 rows that depend only
on how many rows the index already holds and how long the list is, so no request names a
commitment, a list index or a shard, and two calls about different commitments from the same index
state send the same requests.

`ShieldBlocked` is never answered: nothing on the device says a shield is blocked, so a blocked
shield reads `Missing`, which engine files as pending rather than spendable.

A six-byte prefix is not a commitment. Status fetches no row, so a note whose prefix a listed note
shares reads `Valid`; the proof it needs to spend binds all 32 bytes and is refused. A blinded
commitment's first six bytes take about 2^45.6 values, so over ~360k rows the chance of such a
match for a given note is about 7 in 10^9.

A list the interface does not serve is left out of every commitment's map, as the stock node
leaves out a list it does not hold, and engine treats that list as unproven for the note. A wallet
whose `Active` lists Raven does not all serve therefore sees those notes as not spendable; serve
every active list. The two-argument call refuses such a list with `InvalidQuery` before any
request.

### Submissions persist through a store

The submitted set persists through `submittedProofStore`, any `{ load, save }` of opaque bytes. The
default keeps it in memory. Engine stores `ProofSubmitted` in its own database, but after each
restart the in-memory set is empty, status answers `Missing` over it, and engine generates and
submits the proof again: one resubmission per restart for each commitment still off the list.
`indexedDbPoiListIndexStore({ namespace: "submitted-proofs" })` has the shape for a browser; a Node
wallet passes its own. An entry is dropped only when its commitment appears in the list's index, so
with a persistent store a device submits at most once per list and commitment. A record that does
not verify reads as empty, and one the store cannot read leaves that list's absent commitments out
of the engine-shaped answer rather than risk a resubmission.

An entry has no expiry and no call removes it. If upstream accepts a proof and the commitment never
reaches the list, the device answers `ProofSubmitted` for it indefinitely, engine never submits it
again, and the note stays unspendable while the store keeps the entry. Clearing the store's record
for that chain and list is the only way back to a resubmission.

## The list index

`syncPoiListIndex` (method) and `fetchBcPrefixIndex` (exported function) read
`GET /v1/poi/:list/bc-prefixes`: **6 bytes a row**, segmented one PPOI block per response with a
`?since=N` cursor and an immutable `Cache-Control` on any sealed block.

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
For a proof, resolving a candidate costs nothing extra: the served row carries the full commitment
in its first 32 bytes and the fold path refuses a row whose commitment is not the one asked for.

## An absence is answered only at the row count the node serves

A commitment with no index row is answered by the index alone. An index one append behind the list
therefore reads a real member as `Missing`, and that is the verdict a wallet acts on. The SDK closes
this by binding every index to the list's row count and bringing it up to the node's count on each
call:

```ts
await raven.syncPoiListIndex(listKey); // optional warm-up: the first call walks the channel once
// every getPOIsPerList / getPOIMerkleProofs re-reads only the index's tail first
```

- **Each call first syncs the index**, walking the whole channel when none is held. A later sync
  re-reads from a multiple of `BC_INDEX_RESUME_ALIGN_ROWS` (2,048) below the rows held, so the cursor
  it sends names a window of about three days of list growth rather than the exact row a client
  last reached, which would link its calls and its restarts. The re-read rows are compared with what
  is held: the list is append-only, so a difference is the node contradicting itself and is refused
  (`DecodeError`), as is a node serving fewer rows than the index holds (`StaleAdapter`). The sync
  carries the bearer credential but never the PIR client id. It is sent with `cache: "no-cache"`:
  the frontier is served `max-age=15`, and a browser or CDN answering from its copy would let an
  absence read as current against a list up to 15 s old. Syncs of one index run one at a time, so a
  slower one never lands an older list over a newer one.
- **An index this node did not produce is re-read in full.** One passed in `poiListIndexes`
  (keyed `<chainId>:<listKey>`) is compared row by row against the prefix channel on its first
  sync, because an absence is answered from the index alone and a row changed anywhere in it would
  silently turn a member into a non-member. After that it is held as the node's own, and later
  syncs re-read only the tail.
- **A status call whose sync fails answers nothing for that list**: the two-argument call raises
  the sync's own error kind, and the engine-shaped call leaves every commitment out. Only an index
  synced in the call answers `Missing`, counted as `absent` in `indexCounters()`.
- **A proof survives a failed sync for a commitment the held index has a row for**: the row
  confirms it, and a row the list holds never moves. An absent commitment is refused before any
  query, with the sync's own error kind when the sync failed, and counted as `absent` when the index
  was synced in the call.
- **A prefix is not a commitment**, so a proof's candidate is confirmed by the row it returns: a row
  carrying the same six-byte prefix but another commitment moves the SDK to the next candidate in a
  second round, and a row that does not even carry the prefix is refused rather than read as absent.
  The lowest confirmed candidate wins, which is the occurrence the adapter resolves to.

What no channel on the node can show is a node that serves the same shorter list everywhere: that
reads exactly like a node that has not ingested the tail yet, and for a PPOI list nothing the node
publishes tracks that lag. Only a total read from upstream could tell the two apart.

### The index survives a restart

`syncPoiListIndex` and every sync that moves the index write it to `poiListIndexStore`: IndexedDB by
default where the runtime has it (`indexedDbPoiListIndexStore`). Node has none, so a Node wallet
passes its own `{ load, save }` over whatever it persists to; the record is opaque bytes. A restarted
client reads the index from the store, so `poiListIndexCandidates(listKey, commitment)` resolves an
index with no request at all, and its next call resumes from the stored cursor. Calls that arrive
while the store is being read all wait for that one read, so a wallet's first calls after a start,
which arrive together, all resolve from it. Records are keyed by chain, node and list, carry their
list key and a SHA-256 digest, and anything that does not verify is ignored and costs a re-walk,
never an answer. A failed save is swallowed for the same reason.

A record is written only after a sync against that same node, so every row in it was served or
confirmed by that node, and a restart re-reads only the tail rather than the whole list again. The
rows below the cursor are not re-read on each start: re-reading them is the full walk the store
exists to avoid, and a re-read of the same node could catch only a row it once served wrongly and
later corrected, never one it serves wrongly throughout.

## Auth paths come from the block's instance

A list is served as a forest: one path instance per 65,536-leaf PPOI block, named in
`clientPirInstanceLabels` under `t2Path:<chainId>:<listKey>:<block>`. `getPOIMerkleProofs` asks each
commitment's block instance at the leaf's row in that block, one padded batch per block. A block
with no label is refused with `InvalidQuery` naming the key it needs, and an index past the rows the
instance's shard config declares is refused by name; neither sends a query.

A request carries only encrypted queries. The exact leaf index is not sent, but its block and shard
are, which narrows it to the rows of one shard: the node sees the block, from the instance asked;
each query's shard, which the query carries in the clear;
the batch size, which the ladder pads to a power of two up to 32; and the per-instance client id
and session handle, which link one wallet's queries to that instance. Cover queries go to shards no
real query uses while free ones remain.

## Private freshness policy

Every PIR response carries
`X-Raven-Freshness: lag_blocks=N applied_height=M epoch=E confidence=0.X`. Confidence below
`freshnessConfidenceFloor` (default 0.5) raises a typed `StaleData` error, and nothing is asked of
anyone else: there is no private way to re-ask, and asking upstream in the clear would name the
note. The error carries the public freshness values but no blinded commitment, list key, token, or
URL.

`freshnessConfidenceFloor` must be finite and within `[0,1]`; invalid values are rejected with
`InvalidQuery` during construction. A missing private freshness header raises `StaleAdapter`, and a
malformed one raises `DecodeError`, because neither can supply the fields required by `StaleData`.

## Verifying a served auth path

A PIR-served PPOI auth path arrives as sibling hashes. Folding them yields a root, but a root the
same node supplied would verify nothing, so the SDK compares the fold against a root obtained
independently:

1. A root you pinned yourself in `ppoiPinnedRoots`, keyed `<chainId>:<listKey>:<block>`, always wins.
2. Otherwise the SDK asks the upstream PPOI aggregator directly, over the wallet's own `fetch`,
   never through the Raven node.
3. Otherwise it refuses. The proof path never returns an unverified proof.

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

## Session persistence is opt-in

`loadClientPirContext` builds the per-instance PIR session. Passing `persistSession: true` caches
that session in IndexedDB keyed `(instanceId, sha256(crsBincode))`, so a later page load skips
`build_client_session` and a CRS rotation self-invalidates.

**The cached blob contains the client's RLWE secret key.** Enabling it places a secret at rest in the
browser's storage, where anything with same-origin script access can read it. It defaults to `false`
and a wasm build merely exposing `serialize_client_session` does not enable it; pass it only with the
user's informed consent, and prefer leaving it off on shared or untrusted devices. With it off, no
session blob is read or written and every load takes the cold `build_client_session` path.
