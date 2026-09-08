// WASM `extract_response` against the Rust-emitted fixture under `tests/fixtures/`, so any
// divergence is in the wasm-bindgen / bincode layer rather than in network noise.
//
// This ran against nothing for as long as it existed: it was gated on `RAVEN_FIXTURE_DIR`
// pointing at a `capture_live_fixture` output, and no such generator is in the tree - the
// directory it wanted (`client_state.bin`, `response_inner.bin`, `expected_leaf_hex.txt`,
// `entry_size.txt`, `secret_key.bin`) is emitted by no example, script or CI job. The
// checked-in fixture carries the same secret key inside `params_bundle.bin`, so a session
// rebuilt from it decrypts the recorded responses byte-exactly and the gate is unnecessary.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, describe, expect, it } from "vitest";

import * as wasmPkg from "raven-inspire-client-wasm";

import { decodeClientPirQueryBundle } from "../src/index";
import type { RavenInspireClientSession, RavenInspireWasm } from "../src/index";

const FIXTURES_DIR = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

const wasm = wasmPkg as unknown as RavenInspireWasm;
const wasmInit = wasmPkg as unknown as { init_panic_hook?: () => void };
if (typeof wasmInit.init_panic_hook === "function") {
  wasmInit.init_panic_hook();
}

/**
 * Rows `adapters/railgun/client-wasm/examples/emit_test_fixture.rs` encoded:
 * `[status = idx % 4, bc[0..31]]` over a 32-byte cell — the production
 * `PerListStatusEncoder` shape (engine/src/pir_table/list.rs). Pinned rather than
 * recomputed so a regenerated fixture that changes the row shape reddens instead of
 * agreeing with itself; that pin is exactly what caught the first-cut emitter
 * writing `bc[1..32]` and shipping rows production would never serve.
 */
const EXPECTED_ROW_HEX: Record<number, string> = {
  0: "00bc000000000000000000000000000000000000000000000000000000000000",
  1: "01bc000000000000000000000000000000000000000000000000000000010000",
  2: "02bc000000000000000000000000000000000000000000000000000000020000",
  3: "03bc000000000000000000000000000000000000000000000000000000030000",
  4: "00bc000000000000000000000000000000000000000000000000000000040000",
};

interface FixtureMeta {
  entry_size: number;
  list_key_hex: string;
  target_indices: number[];
  bcs_hex: string[];
}

function read(name: string): Uint8Array {
  return new Uint8Array(readFileSync(join(FIXTURES_DIR, name)));
}

const meta = JSON.parse(
  readFileSync(join(FIXTURES_DIR, "fixture.json"), "utf-8"),
) as FixtureMeta;
const paramsBundle = read("params_bundle.bin");
const crsBincode = read("crs.bin");
const shardConfigBincode = read("shard_config.bin");

const sessions: RavenInspireClientSession[] = [];

/** A session over the fixture's own secret key, which `params_bundle.bin` carries. */
function newSession(): RavenInspireClientSession {
  const session = wasm.build_client_session(paramsBundle, crsBincode);
  sessions.push(session);
  return session;
}

/** Per-query state for `targetIdx`; the query bytes go to a server, this half never does. */
function clientStateFor(session: RavenInspireClientSession, targetIdx: number): Uint8Array {
  return decodeClientPirQueryBundle(
    wasm.build_seeded_query(session, shardConfigBincode, BigInt(targetIdx)),
  ).clientStateBincode;
}

function hex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

describe("wasm extract_response against the checked-in Rust-emitted fixture", () => {
  afterAll(() => {
    for (const s of sessions) s.free();
    sessions.length = 0;
  });

  it("recovers the row native Rust encoded, byte for byte, at every fixture index", () => {
    expect(meta.target_indices).toEqual([0, 1, 2, 3, 4]);
    const session = newSession();
    for (const idx of meta.target_indices) {
      const plaintext = wasm.extract_response(
        session,
        crsBincode,
        clientStateFor(session, idx),
        read(`response_for_idx_${idx}.bin`),
        meta.entry_size,
      );
      expect(plaintext.length, `idx ${idx} plaintext length`).toBe(meta.entry_size);
      expect(hex(plaintext), `idx ${idx} row`).toBe(EXPECTED_ROW_HEX[idx]);
      // The row is [status, bc[0..31]]; the tail is the first 31 bytes of the fixture's own BC.
      expect(hex(plaintext.subarray(1)), `idx ${idx} bc tail`).toBe(
        meta.bcs_hex[idx].slice(0, 62),
      );
      // Cross-check against the plaintext native Rust recorded IN the fixture run, so the
      // pin above and the generator can never drift apart silently.
      expect(hex(plaintext), `idx ${idx} vs recorded expected_plain`).toBe(
        hex(read(`expected_plain_for_idx_${idx}.bin`)),
      );
    }
  });

  it("decodes with the RECORDED client state, so the fixture is self-contained", () => {
    // Before the generator wrote client_state_for_idx_*, extraction was only possible by
    // rebuilding a state from the shipped secret key; the recorded state removes even that
    // dependency and pins the exact (state, response, plaintext) triple one run produced.
    const session = newSession();
    for (const idx of meta.target_indices) {
      const plaintext = wasm.extract_response(
        session,
        crsBincode,
        read(`client_state_for_idx_${idx}.bin`),
        read(`response_for_idx_${idx}.bin`),
        meta.entry_size,
      );
      expect(hex(plaintext), `idx ${idx} via recorded state`).toBe(
        hex(read(`expected_plain_for_idx_${idx}.bin`)),
      );
    }
  });

  it("surfaces a truncated response as a typed decode error, not a wasm trap", () => {
    const session = newSession();
    const state = clientStateFor(session, 0);
    const full = read("response_for_idx_0.bin");

    let message = "";
    try {
      wasm.extract_response(
        session,
        crsBincode,
        state,
        full.subarray(0, Math.floor(full.length / 2)),
        meta.entry_size,
      );
      expect.fail("a half-length response must not decode");
    } catch (e) {
      message = String(e);
    }
    // A wasm `unreachable` trap reaches JS as an opaque RuntimeError with no operand name,
    // which is what the panic hook and the typed WasmClientError exist to prevent.
    expect(message).toContain("server_response");
    expect(message.toLowerCase()).not.toContain("unreachable");
  });

  it("surfaces a 1-byte response as a typed decode error, not a wasm trap", () => {
    const session = newSession();
    const state = clientStateFor(session, 0);
    const full = read("response_for_idx_0.bin");

    let message = "";
    let returned: Uint8Array | null = null;
    try {
      returned = wasm.extract_response(
        session,
        crsBincode,
        state,
        full.subarray(0, 1),
        meta.entry_size,
      );
    } catch (e) {
      message = String(e);
    }
    expect(returned, "a 1-byte response must not decode").toBeNull();
    expect(message).toContain("server_response");
    expect(message.toLowerCase()).not.toContain("unreachable");
  });

  it("surfaces a zero-length response as a typed decode error, never a fabricated record", () => {
    // Targets the extract() fabrication class (crates/inspire/src/pir/extract.rs): an empty
    // column_ciphertexts once decrypted a single value and pushed it num_columns times,
    // returning a well-formed all-equal record with Ok(()). The proof standard here is that
    // NOTHING comes back: a returned Uint8Array of any shape is the defect, not a soft-fail.
    const session = newSession();
    const state = clientStateFor(session, 0);

    let message = "";
    let returned: Uint8Array | null = null;
    try {
      returned = wasm.extract_response(
        session,
        crsBincode,
        state,
        new Uint8Array(0),
        meta.entry_size,
      );
    } catch (e) {
      message = String(e);
    }
    expect(returned, "an empty response must not decode to a record").toBeNull();
    expect(message).toContain("server_response");
    expect(message.toLowerCase()).not.toContain("unreachable");
  });

  it("does NOT bind the recovered row to the index the caller asked for", () => {
    // CHARACTERIZATION, not an endorsement. A server that answers row M to a query for row
    // N returns a well-formed 32-byte plaintext and no error, so the substitution has to be
    // caught above the ciphertext: T1 re-checks the row's own BC against the one requested
    // (status_row_bc_binding), and T2/T3 catch it only when the folded root fails to verify.
    const session = newSession();
    const stateForZero = clientStateFor(session, 0);

    const substituted = wasm.extract_response(
      session,
      crsBincode,
      stateForZero,
      read("response_for_idx_3.bin"),
      meta.entry_size,
    );

    expect(hex(substituted)).toBe(EXPECTED_ROW_HEX[3]);
    expect(hex(substituted)).not.toBe(EXPECTED_ROW_HEX[0]);
  });
});
