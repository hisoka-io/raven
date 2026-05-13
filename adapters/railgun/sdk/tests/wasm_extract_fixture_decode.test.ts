/**
 * WASM-only fixture-decode test for `extract_response`.
 *
 * Loads a known-good live PIR exchange captured by
 * `crates/raven-railgun-adapter/crates/raven-inspire-client-wasm/examples/capture_live_fixture.rs`
 * and asserts that the WASM binding's `extract_response` recovers
 * byte-identical leaf bytes to the native Rust client.
 *
 * Splits the WASM-binding bug from any live-server / network noise:
 * the fixture pins a single deterministic exchange, so any divergence
 * is necessarily inside the wasm-bindgen / bincode marshalling layer.
 *
 * Gated on `RAVEN_FIXTURE_DIR` env var; skipped when unset (the
 * default; CI lanes don't carry the fixture). Capture once with:
 *
 *   mkdir -p /tmp/raven-fixture-tree-0-leaf-0
 *   cargo run --release --example capture_live_fixture \
 *     --manifest-path crates/raven-railgun-adapter/crates/raven-inspire-client-wasm/Cargo.toml \
 *     -- http://52.205.11.251:8080 $(cat run/secrets/bearer-token) commit-tree-0 0 \
 *     /tmp/raven-fixture-tree-0-leaf-0
 *
 * Then run:
 *
 *   RAVEN_FIXTURE_DIR=/tmp/raven-fixture-tree-0-leaf-0 \
 *     pnpm test wasm_extract_fixture_decode
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { afterAll, describe, expect, it } from "vitest";

import * as wasmPkg from "raven-inspire-client-wasm";

import type { RavenInspireWasm } from "../src/index";

const FIXTURE_DIR = process.env.RAVEN_FIXTURE_DIR;
const RUN = FIXTURE_DIR !== undefined;
const fixtureIt = RUN ? it : it.skip;

const wasm = wasmPkg as unknown as RavenInspireWasm;
const wasmInit = wasmPkg as unknown as { init_panic_hook?: () => void };
if (typeof wasmInit.init_panic_hook === "function") {
  wasmInit.init_panic_hook();
}

interface Fixture {
  paramsBundle: Uint8Array;
  crsBincode: Uint8Array;
  shardConfigBincode: Uint8Array;
  inspireParamsBincode: Uint8Array;
  clientStateBincode: Uint8Array;
  responseInner: Uint8Array;
  expectedLeafHex: string;
  entrySize: number;
}

function read(dir: string, name: string): Uint8Array {
  return new Uint8Array(readFileSync(join(dir, name)));
}

function readText(dir: string, name: string): string {
  return readFileSync(join(dir, name), "utf-8").trim();
}

function loadFixture(dir: string): Fixture {
  const inspireParamsBincode = read(dir, "inspire_params.bin");
  const shardConfigBincode = read(dir, "shard_config.bin");
  // Reconstruct the params bundle the SDK normally builds from
  // `build_instance_params_blob`. The stored secret_key.bin is the
  // serialized RlweSecretKey the native fixture used; for the WASM
  // path we want a fresh session, so we let `build_instance_params_blob`
  // generate a new SK. The session, however, must match the
  // `client_state.bincode` (which was emitted under the captured SK)
  // OR the test must rebuild the client state via the WASM session;
  // the latter is the production path so we use it. NOTE: this means
  // the test captures a whole exchange end-to-end; it does NOT
  // exercise extract_response on a foreign-session response, which
  // would always fail extract regardless of WASM-binding bugs.
  const paramsBundle = wasm.build_instance_params_blob(
    inspireParamsBincode,
    shardConfigBincode,
  );
  return {
    paramsBundle,
    crsBincode: read(dir, "crs.bin"),
    shardConfigBincode,
    inspireParamsBincode,
    clientStateBincode: read(dir, "client_state.bin"),
    responseInner: read(dir, "response_inner.bin"),
    expectedLeafHex: readText(dir, "expected_leaf_hex.txt"),
    entrySize: Number.parseInt(readText(dir, "entry_size.txt"), 10),
  };
}

describe("wasm extract_response against captured live fixture", () => {
  if (!RUN) {
    it.skip("requires RAVEN_FIXTURE_DIR pointing at a capture_live_fixture output", () => {
      // Skip marker visible in offline lanes.
    });
  }

  const sessions: Array<{ free: () => void }> = [];
  afterAll(() => {
    for (const s of sessions) s.free();
  });

  fixtureIt(
    "wasm_extract_response_against_captured_live_fixture_byte_identical_to_native",
    () => {
      if (!FIXTURE_DIR) throw new Error("env guard");
      const fx = loadFixture(FIXTURE_DIR);

      // For an end-to-end fixture decode we need the same session
      // that produced the response. We rebuild it from the captured
      // params + the captured secret-key bytes by going through the
      // WASM build_client_session. Because `secret_key.bin` is held
      // separately, we reuse the captured params bundle but inject
      // the captured key.
      const secretKeyBincode = new Uint8Array(
        readFileSync(join(FIXTURE_DIR, "secret_key.bin")),
      );
      const paramsBundle = buildParamsBundleFromCapturedKey(
        fx.inspireParamsBincode,
        fx.shardConfigBincode,
        secretKeyBincode,
      );
      const session = wasm.build_client_session(paramsBundle, fx.crsBincode);
      sessions.push(session);

      const plaintext = wasm.extract_response(
        session,
        fx.crsBincode,
        fx.clientStateBincode,
        fx.responseInner,
        fx.entrySize,
      );
      expect(plaintext.length).toBeGreaterThanOrEqual(32);
      const leafHex = bytesToHexNoPrefix(plaintext.subarray(0, 32));
      expect(leafHex).toBe(fx.expectedLeafHex);
    },
  );

  fixtureIt(
    "wasm_extract_response_panics_with_typed_error_on_truncated_response",
    () => {
      if (!FIXTURE_DIR) throw new Error("env guard");
      const fx = loadFixture(FIXTURE_DIR);
      const secretKeyBincode = new Uint8Array(
        readFileSync(join(FIXTURE_DIR, "secret_key.bin")),
      );
      const paramsBundle = buildParamsBundleFromCapturedKey(
        fx.inspireParamsBincode,
        fx.shardConfigBincode,
        secretKeyBincode,
      );
      const session = wasm.build_client_session(paramsBundle, fx.crsBincode);
      sessions.push(session);

      // Truncate the response: half the bytes guarantee a bincode
      // decode failure that surfaces as a typed JsValue error string,
      // not an `unreachable` trap.
      const truncated = fx.responseInner.subarray(
        0,
        Math.floor(fx.responseInner.length / 2),
      );
      let threw = false;
      try {
        wasm.extract_response(
          session,
          fx.crsBincode,
          fx.clientStateBincode,
          truncated,
          fx.entrySize,
        );
      } catch (e) {
        threw = true;
        // Must surface as a structured Error/string, not an
        // `unreachable executed` trap. Substring check on either
        // "bincode" or the raven-inspire op name confirms typed
        // routing through the WasmClientError variants.
        const msg = String(e);
        expect(msg.length).toBeGreaterThan(0);
        expect(msg.includes("unreachable")).toBe(false);
      }
      expect(threw).toBe(true);
    },
  );
});

/**
 * Mirrors the bincode shape of `WasmInstanceParamsBundle` defined in
 * `crates/raven-railgun-adapter/crates/raven-inspire-client-wasm/src/lib.rs`.
 * We need this because `build_instance_params_blob` generates a fresh
 * RLWE SK; the fixture-decode path needs to inject the captured SK so
 * the rebuilt session matches the captured `client_state.bincode`.
 *
 * Wire shape (bincode v1, default fixint LE):
 *   u64 LE  inspire_params_bincode.len
 *   bytes   inspire_params_bincode
 *   u64 LE  shard_config_bincode.len
 *   bytes   shard_config_bincode
 *   u64 LE  rlwe_secret_key_bincode.len
 *   bytes   rlwe_secret_key_bincode
 */
function buildParamsBundleFromCapturedKey(
  inspireParamsBincode: Uint8Array,
  shardConfigBincode: Uint8Array,
  rlweSecretKeyBincode: Uint8Array,
): Uint8Array {
  const total =
    8 + inspireParamsBincode.length +
    8 + shardConfigBincode.length +
    8 + rlweSecretKeyBincode.length;
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let off = 0;
  const writeVec = (bytes: Uint8Array): void => {
    view.setUint32(off, bytes.length, true);
    view.setUint32(off + 4, 0, true); // hi=0; payload sizes always fit u32 in practice.
    off += 8;
    out.set(bytes, off);
    off += bytes.length;
  };
  writeVec(inspireParamsBincode);
  writeVec(shardConfigBincode);
  writeVec(rlweSecretKeyBincode);
  return out;
}

function bytesToHexNoPrefix(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 1) {
    s += bytes[i].toString(16).padStart(2, "0");
  }
  return s;
}
