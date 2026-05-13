# @raven/railgun-poi-node-interface

Drop-in `POINodeInterface` for the Railgun wallet stack. Privately resolves PPOI status, PPOI auth-paths, and commit-tree auth-paths against a Raven Railgun PIR adapter server.

## One-line wallet swap

```ts
import { RailgunWallet } from "@railgun-community/wallet";
import { RavenPOINodeInterface } from "@raven/railgun-poi-node-interface";

RailgunWallet.setPOINodeInterface(
  new RavenPOINodeInterface({
    endpoint: "https://raven.example.com",
    bearerToken: process.env.RAVEN_BEARER_TOKEN!,
    upstreamFallbackEndpoint: "https://poi.us.proxy.railwayapi.xyz",
  }),
);
```

## What it routes

| Method                    | Route                                                    | Privacy |
|---------------------------|----------------------------------------------------------|---------|
| `getPOIsPerList`          | `POST /v1/poi/pois-per-list`                             | PIR     |
| `getPOIMerkleProofs`      | `POST /v1/poi/merkle-proofs`                             | PIR     |
| `getMerkleProof`          | `POST /v1/commit-tree/:tree/merkle-proof`                | PIR     |
| `validatePOIMerkleroots`  | upstream passthrough                                     | trust   |
| `submitPOI`               | upstream passthrough                                     | trust   |
| `submitLegacyTransactProofs` | upstream passthrough                                  | trust   |

Public-info channels (cacheable, no per-BC leak):

| Method               | Route                              |
|----------------------|------------------------------------|
| `fetchBcToIdxMap`    | `GET /v1/poi/:list/bc-to-idx-map`  |
| `fetchStatusHeader`  | `GET /v1/poi/:list/status-header`  |

## Freshness fallback

Every PIR response carries `X-Raven-Freshness: lag_blocks=N applied_height=M epoch=E confidence=0.X`. If `confidence` falls below `freshnessConfidenceFloor` (default 0.5) and an `upstreamFallbackEndpoint` is configured, the wallet falls back to the upstream PPOI service for that call.

## IMT cache layers

The client-side IMT (Incremental Merkle Tree) node cache (entry point: `ImtCache` in [`src/imt-cache.ts:208`](src/imt-cache.ts)) is layered:

- **L1 -- `InMemoryLru`** (always present). Bounded `Map`-backed LRU; default capacity 1024 entries x 32 byte values = ~32 KB. Synchronous `getSync`/`set` fast-path.
- **L2 -- IndexedDB** (when `globalThis.indexedDB` is exposed). Used by modern browsers (Safari 10+, Chrome 24+, Firefox 16+) and by Node tests via an IDB shim. Lazily opened on first use; reads promote IDB hits back into L1.

There is **no `localStorage` L2.** Every supported browser ships IndexedDB, so a synchronous-blocking 5 MB key-value store would only add eviction-policy complexity without unlocking a real environment. In the rare no-IDB case (Safari private browsing on older versions, custom embedders that strip IDB), the L1 in-memory layer alone is the fallback -- the cache is best-effort, not authoritative.

Invalidation is driven by the `X-Raven-Epoch` and `X-Raven-Schema-Version` headers: `noteFreshness(epochTag, schemaVersion)` drops both layers whenever either advances, so stale nodes cannot survive a server-side reorg or schema bump.
