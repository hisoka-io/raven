import * as wasm from "@hisoka-io/howl-client-wasm-bundler";
import { smoke } from "../scenario.mjs";

globalThis.howlSmoke = (input) => smoke(wasm, input);
