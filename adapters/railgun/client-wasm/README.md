# @hisoka-io/raven-inspire-client-wasm

The WebAssembly PIR client that `@hisoka-io/railgun-poi-node-interface` runs on the device: it
builds encrypted InsPIRe queries and decrypts the answers, so a Raven node serves a PPOI auth path
without learning which row was asked for.

Two builds of one wasm, published as two packages:

- `@hisoka-io/raven-inspire-client-wasm` for Node
- `@hisoka-io/raven-inspire-client-wasm-bundler` for browser bundlers (webpack, Vite, Rollup)

## Install

```sh
npm install @hisoka-io/railgun-poi-node-interface@alpha @hisoka-io/raven-inspire-client-wasm@alpha
```

A browser bundle installs `@hisoka-io/raven-inspire-client-wasm-bundler@alpha` in its place.

## Example

```ts
import { fetchInstanceParams, loadClientPirContext } from "@hisoka-io/railgun-poi-node-interface";
import * as wasm from "@hisoka-io/raven-inspire-client-wasm";

const params = await fetchInstanceParams({ endpoint, instanceId: "ppoi-paths-ofac-0" });
const { context } = await loadClientPirContext({ wasm, instanceId: "ppoi-paths-ofac-0", ...params });
```

Before it derives a key, the client refuses a served parameter set outside the shipped bounds:
ring dimension 2048 to 4096, modulus at most 2^60 - 2^14 + 1, error width exactly 6.4, and
gadgets of at most 3 digits, no more than their base needs to cover the modulus.
Each package carries `raven_inspire_client_wasm_bg.wasm.sha256`, which `sha256sum -c` checks
against the wasm beside it.

Source, build and documentation: https://github.com/hisoka-io/raven
