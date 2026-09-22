# @raven/railgun-poi-node-interface

Drop-in `POINodeInterface` for the Railgun wallet stack. Privately resolves PPOI status, PPOI auth-paths, and commit-tree auth-paths against a Raven Railgun PIR adapter server.

## Install

```sh
npm install @raven/railgun-poi-node-interface
```

```ts
// ESM, and any bundler
import { RavenPOINodeInterface } from "@raven/railgun-poi-node-interface";
```

```js
// CommonJS, which is what a `tsc`-built wallet emits
const { RavenPOINodeInterface } = require("@raven/railgun-poi-node-interface");
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

The manifest still lists that package as a runtime dependency under a repo-relative `file:` path
that resolves to nothing outside this repository. Installing the tarball succeeds and the SDK works,
but the consumer is left with a dangling `node_modules/raven-inspire-client-wasm` link and
`npm ls` reports the tree invalid. How the WASM is published, and therefore how this entry should
read, is still open.

## How it plugs in

`RavenPOINodeInterface` implements Railgun's abstract `POINodeInterface`, the same class the stock `WalletPOINodeInterface` implements:

```ts
import { RavenPOINodeInterface } from "@raven/railgun-poi-node-interface";

const poi = new RavenPOINodeInterface({
  endpoint: "https://raven.example.com",
  // Optional; see "The credential is optional" below before leaving it out.
  bearerToken: process.env.RAVEN_BEARER_TOKEN,
  // Used by validation/submission; private stale reads still refuse by default.
  upstreamFallbackEndpoint: "https://ppoi.fdi.network",
});
```

### The credential is optional

`bearerToken` is sent as `Authorization: Bearer <token>` on every request to `endpoint`, and never
to `upstreamFallbackEndpoint`. Leave it out, or pass `undefined`, and the SDK sends no
`Authorization` header at all -- the same shape as Railgun's own POI node client, which addresses a
node by URL alone.

**Leaving it out works only against a node that does not require a credential.** A node that does
answers `401` on every route the SDK uses, which surfaces as a typed `ServerError` `RavenError`
carrying `status: 401`. A stock Raven adapter configures a mandatory `read_token`, so it is such a
node: pass its token.

A token that is empty, has leading or trailing whitespace, or holds anything but printable ASCII
is refused at construction with `InvalidQuery`, and the message never quotes it. The SDK never
interpolates what it was given: `process.env.RAVEN_BEARER_TOKEN!` with the variable unset is
`undefined` at runtime whatever its type says, and that is treated as no credential rather than
sent as `Authorization: Bearer undefined`, a request that looks authenticated and is not.

Wiring it into a wallet: today `startRailgunEngine` takes a list of POI node URLs and builds the stock `WalletPOINodeInterface` internally, and neither `WalletPOI` nor a POI-interface setter is part of the wallet's public API. Making `RavenPOINodeInterface` the active POI interface therefore needs a small, additive injection point in Railgun (one hook that accepts any `POINodeInterface`), or it is wired in through a fork. That injection point is the integration to land with the Railgun team.

## What it routes

| Method                    | Route                                                    | Privacy |
|---------------------------|----------------------------------------------------------|---------|
| `getPOIsPerList`          | `POST /v1/poi/pois-per-list`                             | PIR     |
| `getPOIMerkleProofs`      | `POST /v1/poi/merkle-proofs`                             | PIR     |
| `getMerkleProof`          | `POST /v1/commit-tree/:tree/merkle-proof`                | PIR     |
| `validatePOIMerkleroots`  | upstream passthrough                                     | trust   |
| `submitPOI`               | upstream passthrough                                     | trust   |
| `submitLegacyTransactProofs` | upstream passthrough                                  | trust   |

`getMerkleProof` returns a `CommitTreeProof`, discriminated on `kind`:

- `kind: "authPath"` -- the client-PIR path. Carries `elements` and `indices` and **no root**. PIR fetches the 16 auth-path siblings; it never fetches the leaf, so there is nothing to fold a root from. A caller that needs a root fetches the leaf row itself and folds with the exported `foldMerkleRoot`.
- `kind: "rooted"` -- the plaintext path (`useClientPir: false`). Carries the adapter's own `MerkleProof` under `proof`, root included.

Public-info channels (cacheable, no per-BC leak):

| Method               | Route                              |
|----------------------|------------------------------------|
| `fetchBcToIdxMap`    | `GET /v1/poi/:list/bc-to-idx-map`  |
| `fetchStatusHeader`  | `GET /v1/poi/:list/status-header`  |

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

A `Network` failure returns the SDK-local `Unreachable` verdict. It never degrades to the adapter's
non-blocking `Missing` verdict, so callers can distinguish an absent PPOI record from a request that
never reached the adapter.

Two limits are worth stating plainly. At the narrowest record width the encoder builds (32 bytes) the
row has room for `bc[0..31]`, so the binding covers 31 of the 32 BC bytes; a wider record binds all
32. And the row's status byte is only as trustworthy as the adapter that wrote it: this check proves
the row describes *your* BC, not that the verdict inside it is correct.

## Private freshness policy

Every PIR response carries
`X-Raven-Freshness: lag_blocks=N applied_height=M epoch=E confidence=0.X`. In client-PIR mode,
confidence below `freshnessConfidenceFloor` (default 0.5) raises a typed `StaleData` error even when
`upstreamFallbackEndpoint` is configured. The error carries the public freshness values but no
blinded commitment, list key, token, or URL.

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
upstream's own tip. They are byte-identical for every wallet asking about the same block and
carry nothing that identifies which commitment you hold.

A pin source equal to the endpoint being verified is refused: explicitly setting `pinUpstream` to
it throws at construction, and inheriting it leaves the resolver inert rather than verifying in a
circle.

On a chain other than Ethereum mainnet, set `pinUpstreamNetworkName` to the name upstream reports
under `forNetwork`. An unrecognised chain refuses rather than guessing, because guessing would
read another chain's tip and refuse honest proofs.

## IMT cache layers

The client-side IMT (Incremental Merkle Tree) node cache (entry point: `ImtCache` in [`src/imt-cache.ts`](src/imt-cache.ts)) is layered:

- **L1 -- `InMemoryLru`** (always present). Bounded `Map`-backed LRU; default capacity 1024 entries x 32 byte values = ~32 KB. Synchronous `getSync`/`set` fast-path.
- **L2 -- IndexedDB** (when `globalThis.indexedDB` is exposed). Used by modern browsers (Safari 10+, Chrome 24+, Firefox 16+) and by Node tests via an IDB shim. Lazily opened on first use; reads promote IDB hits back into L1.

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
