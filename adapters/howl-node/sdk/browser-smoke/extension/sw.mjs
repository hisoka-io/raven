import * as wasm from "@hisoka-io/howl-client-wasm-web";
import { smoke } from "../scenario.mjs";

// Started at load, so every event handler can wait on it; the worker registers handlers synchronously.
const ready = fetch(chrome.runtime.getURL("howl_client_wasm_bg.wasm"))
  .then((response) => response.arrayBuffer())
  .then((bytes) => wasm.initSync({ module: bytes }));

globalThis.howlSmoke = async (input) => {
  await ready;
  return smoke(wasm, input);
};
