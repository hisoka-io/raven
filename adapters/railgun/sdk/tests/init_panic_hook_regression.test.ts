/**
 * Regression-guard: the WASM panic hook MUST be installable from the
 * SDK before any PIR call.
 *
 * Without `init_panic_hook`, raven-inspire panics surface as opaque
 * `RuntimeError: unreachable executed` traps — see the original
 * `Moduli must match` regression that this test stack triages. With
 * the hook installed, every panic carries an originating
 * `<file.rs>:<line>:<col>` and the upstream assertion message.
 *
 * This test does NOT exercise live PIR; it just confirms the SDK's
 * `installPanicHook` surface is wired so wallets can call it once at
 * boot.
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
    // Defensive guard for older bundles that omitted the export. The
    // SDK's contract is "no-op + return false" so wallets can detect
    // the case and warn the operator without aborting.
    const stub: RavenInspireWasm = {
      build_client_session: () => ({ free: () => undefined }),
      build_seeded_query: () => new Uint8Array(0),
      extract_response: () => new Uint8Array(0),
      build_instance_params_blob: () => new Uint8Array(0),
      path_indices_for_leaf: () => new Uint32Array(16),
      path_indices_for_per_list_leaf: () => new Uint32Array(16),
      // init_panic_hook intentionally omitted.
    };
    expect(installPanicHook(stub)).toBe(false);
  });

  it("installPanicHook is idempotent: second call also returns true", () => {
    const wasm = wasmPkg as unknown as RavenInspireWasm;
    expect(installPanicHook(wasm)).toBe(true);
    // The wasm-side `console_error_panic_hook::set_once` no-ops on the
    // second install, so installPanicHook must not throw on the
    // re-call.
    expect(installPanicHook(wasm)).toBe(true);
  });
});
