/**
 * Shared fixture loader for SDK tests that need a real
 * `ClientPirContext` (built against the precomputed binary fixture
 * shipped under `tests/fixtures/`). The fixture itself is generated
 * by the Rust `emit_test_fixture` example.
 *
 * Loaded once per test module; the underlying wasm session is shared
 * across all tests in that module (the wasm session is single-
 * threaded but reusable across sequential `build_seeded_query`
 * calls).
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import * as wasmPkg from "raven-inspire-client-wasm";

import type { ClientPirContext, RavenInspireWasm } from "../../src/index";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "fixtures");

export interface FixtureMeta {
  entry_size: number;
  list_key_hex: string;
  target_indices: number[];
  bcs_hex: string[];
}

export interface LoadedFixture {
  meta: FixtureMeta;
  paramsBundle: Uint8Array;
  crsBincode: Uint8Array;
  shardConfigBincode: Uint8Array;
  responsesByIdx: Map<number, Uint8Array>;
}

export function loadFixture(): LoadedFixture {
  const meta = JSON.parse(readFileSync(join(FIXTURES_DIR, "fixture.json"), "utf-8")) as FixtureMeta;
  const paramsBundle = new Uint8Array(readFileSync(join(FIXTURES_DIR, "params_bundle.bin")));
  const crsBincode = new Uint8Array(readFileSync(join(FIXTURES_DIR, "crs.bin")));
  const shardConfigBincode = new Uint8Array(
    readFileSync(join(FIXTURES_DIR, "shard_config.bin")),
  );
  const responsesByIdx = new Map<number, Uint8Array>();
  for (const idx of meta.target_indices) {
    responsesByIdx.set(
      idx,
      new Uint8Array(readFileSync(join(FIXTURES_DIR, `response_for_idx_${idx}.bin`))),
    );
  }
  return { meta, paramsBundle, crsBincode, shardConfigBincode, responsesByIdx };
}

export function makeClientPirContext(fixture: LoadedFixture): ClientPirContext {
  const wasm = wasmPkg as unknown as RavenInspireWasm;
  const session = wasm.build_client_session(fixture.paramsBundle, fixture.crsBincode);
  return {
    wasm,
    session,
    crsBincode: fixture.crsBincode,
    shardConfigBincode: fixture.shardConfigBincode,
    entrySize: fixture.meta.entry_size,
  };
}
