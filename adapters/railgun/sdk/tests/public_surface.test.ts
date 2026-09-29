import { describe, expect, it } from "vitest";

import * as wasmPkg from "@hisoka-io/raven-inspire-client-wasm";

import * as sdk from "../src/index";
import type { RavenInspireWasm } from "../src/index";

// The wasm functions the SDK binds. `satisfies` keeps the list inside the SDK's contract.
const SDK_BOUND = [
  "build_client_session",
  "build_seeded_query",
  "extract_response",
  "register_client_session",
  "client_packing_keys_versioned",
  "install_server_session_handle",
  "init_panic_hook",
  "build_instance_params_blob",
  "serialize_client_session",
  "deserialize_client_session",
] as const satisfies readonly (keyof RavenInspireWasm)[];

describe("public surface", () => {
  it("exports no session-cache internals from the SDK", () => {
    for (const name of ["idbGet", "idbPut", "idbClear", "sha256Hex"]) {
      expect(Object.keys(sdk), name).not.toContain(name);
    }
  });

  it("links a wasm whose every exported function the SDK binds", () => {
    const functions = Object.entries(wasmPkg)
      .filter(([, value]) => typeof value === "function")
      .map(([name]) => name)
      .filter((name) => name !== "ClientSessionHandle");
    const bound: readonly string[] = SDK_BOUND;
    expect(functions.filter((name) => !bound.includes(name))).toEqual([]);
  });
});
