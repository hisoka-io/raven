# @hisoka-io/railgun-poi-node-interface

A `POINodeInterface` for the Railgun engine. It answers PPOI status on the device, from the list
index it syncs from a Raven Railgun adapter server, and fetches PPOI auth paths from that server by
client-side PIR.

## Install

```sh
npm install @hisoka-io/railgun-poi-node-interface@alpha @hisoka-io/raven-inspire-client-wasm@alpha
```

Node 20 or newer; the package ships CommonJS and ESM builds. A browser bundle installs
`@hisoka-io/raven-inspire-client-wasm-bundler@alpha` in place of the Node wasm. The caller loads the
wasm and passes it in, so both wasm packages are optional peers. `@railgun-community/engine` is an
optional peer too: the package uses its types only and reads the copy your wallet already has.
Import `POI` from that same copy, since an interface installed through a second copy is never read.

## Example

```ts
import { POI } from "@railgun-community/engine";
import {
  PerChainPOINodeInterface,
  RavenPOINodeInterface,
  fetchInstanceParams,
  loadClientPirContext,
} from "@hisoka-io/railgun-poi-node-interface";
import * as wasm from "@hisoka-io/raven-inspire-client-wasm";

// listKey: the PPOI list to serve; lists: the POI lists the engine was started with.
const endpoint = "https://raven.example.com";
const params = await fetchInstanceParams({ endpoint, instanceId: "ppoi-paths-ofac-0" });
const { context } = await loadClientPirContext({ wasm, instanceId: "ppoi-paths-ofac-0", ...params });

const raven = new RavenPOINodeInterface({
  endpoint,
  upstreamFallbackEndpoint: "https://ppoi.fdi.network",
  clientPirContexts: new Map([[`t2Path:1:${listKey}`, context]]),
  // One path instance per 65,536-leaf PPOI block of the list.
  clientPirInstanceLabels: new Map([[`t2Path:1:${listKey}:0`, "ppoi-paths-ofac-0"]]),
});

// After startRailgunEngine: Raven answers chain 1, the stock interface every other chain.
PerChainPOINodeInterface.install(POI, lists, [raven]);
```

`install` refuses with `InvalidQuery` when the engine holds no interface (started without
`poiNodeURLs`) or already holds a router. A wallet that builds its own stock interface passes it
directly: `POI.init(lists, new PerChainPOINodeInterface(stock, [raven]))`.

## What it routes

| Method                       | Where it goes                                                               |
|------------------------------|-----------------------------------------------------------------------------|
| `getPOIsPerList`             | `GET /v1/poi/:list/bc-prefixes` (the index sync), then answered on the device |
| `getPOIMerkleProofs`         | the index sync, then `POST /v1/instance/:id/batch` to the block's instance  |
| `validatePOIMerkleroots`     | upstream JSON-RPC                                                           |
| `submitPOI`                  | upstream JSON-RPC                                                           |
| `submitLegacyTransactProofs` | upstream JSON-RPC                                                           |

No request to the Raven node carries a commitment.

- **Status.** A commitment is `Valid` when its 6-byte prefix is in the synced index,
  `ProofSubmitted` when this device's accepted proof covers it and it is not yet listed, and
  `Missing` otherwise. A note that shares a listed note's prefix reads `Valid`, and its proof,
  which binds all 32 bytes, is refused.
- **Proofs.** A proof query is an encrypted PIR query, and the server does not learn which row
  was retrieved. Each served path is folded and checked against a root from `ppoiPinnedRoots` or,
  failing that, from `pinUpstream` (default `upstreamFallbackEndpoint`). The SDK never returns an
  unverified path.
- **Freshness.** Every PIR response carries `X-Raven-Freshness`; confidence below
  `freshnessConfidenceFloor` (default 0.5) raises `StaleData`.

## Persistence

- `poiListIndexStore`: the synced list index, so a restart re-reads only the tail. IndexedDB by
  default where the runtime has it; a Node wallet passes its own `{ load, save }` of opaque bytes.
- `submittedProofStore`: commitments this device submitted proofs for, in memory by default.
  Persist it to avoid one resubmission per restart. It holds the device's own blinded
  commitments, so a Node store should create its files owner-only (mode 600, directories 700).
- `persistSession: true` on `loadClientPirContext` caches the PIR session in IndexedDB. The cached
  blob holds the client's RLWE secret key; it is off by default. `clearPersistedSessions()` erases
  every cached session and rejects with a `Storage` error if the erase did not commit.

## Errors

Every refusal is a `RavenError` with a `kind` and a `retryable` flag, true for `Network` and for
`ServerError` with status 408, 429 or 5xx. `bearerToken` is optional and is sent only to
`endpoint`. `captureWireRequests: true` keeps the last 64 outbound requests for
`lastWireRequests()`.

Source: https://github.com/hisoka-io/raven
