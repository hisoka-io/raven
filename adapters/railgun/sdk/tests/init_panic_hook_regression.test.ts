/**
 * Regression-guard: `installPanicHook` is wired. Without it, raven-inspire
 * panics surface as opaque `RuntimeError: unreachable executed` traps with
 * no Rust file:line.
 */

import { describe, expect, it } from "vitest";

import * as wasmPkg from "raven-inspire-client-wasm";

import { installPanicHook } from "../src/index";
import type { RavenInspireWasm } from "../src/index";

describe("init_panic_hook regression-guard", () => {
  it("installPanicHook returns true on the real wasm package", () => {
    const wasm = wasmPkg as unknown as RavenInspireWasm;
    const installed = installPanicHook(wasm);
    expect(installed).toBe(true);
  });

  it("installPanicHook returns false when the wasm shim lacks the symbol", () => {
    // older bundles omit the export; contract is no-op + return false
    const stub: RavenInspireWasm = {
      build_client_session: () => ({ free: () => undefined }),
      build_seeded_query: () => new Uint8Array(0),
      extract_response: () => new Uint8Array(0),
      build_instance_params_blob: () => new Uint8Array(0),
      path_indices_for_leaf: () => new Uint32Array(16),
      path_indices_for_per_list_leaf: () => new Uint32Array(16),
      // init_panic_hook intentionally omitted
    };
    expect(installPanicHook(stub)).toBe(false);
  });

  it("installPanicHook is idempotent: second call also returns true", () => {
    const wasm = wasmPkg as unknown as RavenInspireWasm;
    expect(installPanicHook(wasm)).toBe(true);
    // wasm-side set_once no-ops on re-install, so this must not throw
    expect(installPanicHook(wasm)).toBe(true);
  });
});
