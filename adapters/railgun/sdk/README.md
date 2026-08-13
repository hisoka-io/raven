# @raven/railgun-poi-node-interface

Drop-in `POINodeInterface` for the Railgun wallet stack. Privately resolves PPOI status, PPOI auth-paths, and commit-tree auth-paths against a Raven Railgun PIR adapter server.

## How it plugs in

`RavenPOINodeInterface` implements Railgun's abstract `POINodeInterface`, the same class the stock `WalletPOINodeInterface` implements:

```ts
import { RavenPOINodeInterface } from "@raven/railgun-poi-node-interface";

const poi = new RavenPOINodeInterface({
  endpoint: "https://raven.example.com",
  bearerToken: process.env.RAVEN_BEARER_TOKEN!,
  upstreamFallbackEndpoint: "https://poi.us.proxy.railwayapi.xyz",
});
```

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

## PPOI status verdicts are bound to the blinded commitment

A T1 status row is `[status_byte, blinded_commitment[0..min(recordSize - 1, 32)]]`. Rows for list
indices that hold no record are zero-filled, and status byte `0` means `Valid`, so a decode that
reads only byte 0 turns an absent record into the verdict that authorises a spend. `getPOIsPerList`
therefore compares the row's BC tail against the blinded commitment it asked about and raises a
typed `DecodeError` `RavenError` on any mismatch -- including the all-zero row -- rather than
returning a status. Only a `Network` failure degrades to `Missing`; every other failure propagates so
the wallet retries or falls back instead of spending.

Two limits are worth stating plainly. At the narrowest record width the encoder builds (32 bytes) the
row has room for `bc[0..31]`, so the binding covers 31 of the 32 BC bytes; a wider record binds all
32. And the row's status byte is only as trustworthy as the adapter that wrote it: this check proves
the row describes *your* BC, not that the verdict inside it is correct.

## Freshness fallback

Every PIR response carries `X-Raven-Freshness: lag_blocks=N applied_height=M epoch=E confidence=0.X`. If `confidence` falls below `freshnessConfidenceFloor` (default 0.5) and an `upstreamFallbackEndpoint` is configured, the wallet falls back to the upstream PPOI service for that call.

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
