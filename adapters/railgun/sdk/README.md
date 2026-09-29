# @hisoka-io/railgun-poi-node-interface

A `POINodeInterface` for the Railgun engine. It answers PPOI status on the device, from the list
index it syncs from a Raven Railgun adapter server, and fetches PPOI auth paths from that server by
client-side PIR.

## Install

```sh
npm install @hisoka-io/railgun-poi-node-interface@alpha @hisoka-io/raven-inspire-client-wasm@alpha
```

Node 20 or newer. A browser bundle installs `@hisoka-io/raven-inspire-client-wasm-bundler@alpha` in
place of the Node wasm. `@railgun-community/engine` is an optional peer: the package uses its types only
and reads the copy your wallet already has.

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
  clientPirInstanceLabels: new Map([[`t2Path:1:${listKey}:0`, "ppoi-paths-ofac-0"]]),
});

// After startRailgunEngine: Raven answers chain 1, the stock interface every other chain.
PerChainPOINodeInterface.install(POI, lists, [raven]);
```

Submitted proofs persist through `submittedProofStore`, any `{ load, save }` of opaque bytes. A Node
wallet's own store should create its files owner-only (mode 600, directories 700), since the
submitted-proof record holds the device's own blinded commitments.

## Documentation

The full guide, covering routing, the list index, auth-path verification, persistence and errors,
is in the repository: https://github.com/hisoka-io/raven/blob/main/adapters/railgun/sdk/GUIDE.md

Source: https://github.com/hisoka-io/raven
