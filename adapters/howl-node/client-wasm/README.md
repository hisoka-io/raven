# @hisoka-io/howl-client-wasm

The WebAssembly client that `@hisoka-io/raven-howl-client` runs on the device: it decodes a Howl
node's answers, builds private cell reads under a session key drawn inside the wasm, and folds
Merkle paths at a chosen leaf count.

Three builds of one wasm, published as three packages:

| Package | Loads in |
|---|---|
| `@hisoka-io/howl-client-wasm` | Node |
| `@hisoka-io/howl-client-wasm-bundler` | a page built by a bundler (webpack, Vite, Rollup) |
| `@hisoka-io/howl-client-wasm-web` | a Manifest V3 service worker, or any page that loads ES modules itself |

## Install

```sh
npm install @hisoka-io/raven-howl-client@alpha @hisoka-io/howl-client-wasm@alpha
```

A bundled page installs `@hisoka-io/howl-client-wasm-bundler@alpha` in its place, and an extension
`@hisoka-io/howl-client-wasm-web@alpha`.

## Example

```ts
import * as wasm from "@hisoka-io/howl-client-wasm";
import { RavenHowlSource, fetchTransport } from "@hisoka-io/raven-howl-client";

const source = new RavenHowlSource({ transport: fetchTransport("https://howl.example"), wasm, field, keyMode: "session" });
```

The `-web` build is initialised once before use. A service worker registers its listeners
synchronously, so it starts reading the wasm bytes the extension ships at load and has each
handler wait for them:

```ts
import * as wasm from "@hisoka-io/howl-client-wasm-web";

const ready = fetch(chrome.runtime.getURL("howl_client_wasm_bg.wasm"))
  .then((response) => response.arrayBuffer())
  .then((bytes) => wasm.initSync({ module: bytes }));
// in each handler: await ready;
```

Each package carries `howl_client_wasm_bg.wasm.sha256`, which `sha256sum -c` checks against the
wasm beside it.

Source, build and documentation: https://github.com/hisoka-io/raven
