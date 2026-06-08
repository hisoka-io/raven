// Asserts the WASM `extract_response` recovers byte-identical leaf bytes to native Rust,
// against a deterministic captured fixture so any divergence is in the wasm-bindgen /
// bincode layer, not network noise. Gated on RAVEN_FIXTURE_DIR; skipped when unset.

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
    it.skip("requires RAVEN_FIXTURE_DIR pointing at a capture_live_fixture output", () => {});
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

      // Rebuild the exact session that produced the response by injecting the captured SK.
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

      // Half the bytes force a bincode decode failure that must surface as a typed error, not an unreachable trap.
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
        const msg = String(e);
        expect(msg.length).toBeGreaterThan(0);
        expect(msg.includes("unreachable")).toBe(false);
      }
      expect(threw).toBe(true);
    },
  );
});

/**
 * Mirrors the bincode `WasmInstanceParamsBundle` shape so the captured SK can be
 * injected (build_instance_params_blob otherwise generates a fresh one).
 * Wire shape (bincode v1, fixint LE): three (u64 LE len, bytes) vecs in order
 * inspire_params, shard_config, rlwe_secret_key.
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
