// The wasm decoder at the geometry the deployment serves: ring_dim 2048, a 512-byte
// path-10 record and two shards. Every other real-wasm test in this suite runs against
// `tests/fixtures/` at ring_dim 256 / 32 B / one shard, so multi-shard addressing and the
// production cell width had never been decoded in any executed lane. 512 B is illegal
// below ring 2048: the packing width is ceil(512/2) = 256 and legal widths stop at
// ring_dim/2 (crates/inspire/src/inspiring/inspiring2.rs:132-137).
//
// The responses came off the server path: `respond_seeded_inspiring_cached_with_session`
// then `mod_switch_response_checked(.., MOD_SWITCH_TARGET_36BIT)`, which is what
// `RavenInspireScheme::respond` does (engine/src/inspire.rs:92-101).
//
// `crs.bin` is the CRS `GET /v1/instance/{id}/params` ships, not the server's own: the
// galois keys are ~99.98% of the serialized bytes and only the server's Tree path reads
// them (http/src/admin.rs:142-158, crates/inspire/src/pir/respond.rs:681). Decoding off
// the shipped bytes is the point - a fixture built from the server's CRS could pass while
// the artifact a wallet holds does not decode at all.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import * as wasmPkg from "raven-inspire-client-wasm";

import { decodeClientPirQueryBundle } from "../src/index";
import type { RavenInspireClientSession, RavenInspireWasm } from "../src/index";

const FIXTURES_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  "fixtures",
  "production-shape",
);

const wasm = wasmPkg as unknown as RavenInspireWasm;
const wasmInit = wasmPkg as unknown as { init_panic_hook?: () => void };
if (typeof wasmInit.init_panic_hook === "function") {
  wasmInit.init_panic_hook();
}

/** `PATH10_RECORD_BYTES`, `PATH10_LEVELS`, `PATH10_MAGIC` (engine/src/pir_table/list.rs:20,22,24). */
const RECORD_BYTES = 512;
const ROW_LEVELS = 11;
const NODES_OFFSET = 38;
const NODE_BYTES = 32;
const MAGIC = "RVP2";
/** `WIRE_RESPONSE_MODULUS` (engine/src/inspire.rs:67). */
const SERVED_RESPONSE_MODULUS = 68_718_428_161n;

interface ProductionShapeMeta {
  entry_size: number;
  ring_dim: number;
  entries_per_shard: number;
  num_shards: number;
  total_entries: number;
  target_indices: number[];
  shard_ids: number[];
  local_indices: number[];
  bcs_hex: string[];
  response_modulus: number;
}

interface ManifestEntry {
  name: string;
  bytes: number;
  sha256: string;
}

function read(name: string): Uint8Array {
  return new Uint8Array(readFileSync(join(FIXTURES_DIR, name)));
}

const meta = JSON.parse(
  readFileSync(join(FIXTURES_DIR, "fixture.json"), "utf-8"),
) as ProductionShapeMeta;
const manifest = JSON.parse(
  readFileSync(join(FIXTURES_DIR, "fixture_manifest.json"), "utf-8"),
) as { inspire_params: { ring_dim: number }; entry_size: number; files: ManifestEntry[] };

const paramsBundle = read("params_bundle.bin");
const crsBincode = read("crs.bin");
const shardConfigBincode = read("shard_config.bin");
const inspireParamsBincode = read("inspire_params.bin");

/**
 * Count of `ServerCrs.galois_keys` as the shipped bytes declare it. Bincode is not
 * self-describing, so the field is located by its predecessor: the body opens with
 * `params` verbatim, and the `Vec` length follows as a u64 LE.
 */
function shippedGaloisKeyCount(): bigint {
  const bodyStart = 16; // ServerCrs::MAGIC (crates/inspire/src/pir/setup.rs:111)
  const paramsEnd = bodyStart + inspireParamsBincode.length;
  const embedded = crsBincode.subarray(bodyStart, paramsEnd);
  expect(hex(embedded), "CRS body must open with the fixture's own InspireParams").toBe(
    hex(inspireParamsBincode),
  );
  return new DataView(crsBincode.buffer, crsBincode.byteOffset).getBigUint64(paramsEnd, true);
}

/** Session construction at ring 2048 costs seconds, so the suite builds exactly one. */
let session: RavenInspireClientSession;

function seededQueryFor(globalIdx: number): Uint8Array {
  return wasm.build_seeded_query(session, shardConfigBincode, BigInt(globalIdx));
}

/** Per-query state for `globalIdx`; the query half goes to a server, this half never does. */
function clientStateFor(globalIdx: number): Uint8Array {
  return decodeClientPirQueryBundle(seededQueryFor(globalIdx)).clientStateBincode;
}

/** The clear shard selector: `SeededClientQuery.shard_id`, first bincode field, u32 LE. */
function clearShardSelector(globalIdx: number): number {
  const queryBytes = decodeClientPirQueryBundle(seededQueryFor(globalIdx)).queryBytes;
  return new DataView(queryBytes.buffer, queryBytes.byteOffset).getUint32(0, true);
}

function hex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

describe("wasm decode at the served geometry: ring 2048, 512 B record, two shards", () => {
  beforeAll(() => {
    session = wasm.build_client_session(paramsBundle, crsBincode);
  });

  afterAll(() => {
    session?.free();
  });

  it("is pinned to the production geometry, not the ring-256 fixture's", () => {
    expect(meta.ring_dim).toBe(2048);
    expect(manifest.inspire_params.ring_dim).toBe(2048);
    expect(meta.entry_size).toBe(RECORD_BYTES);
    expect(manifest.entry_size).toBe(RECORD_BYTES);
    expect(meta.entries_per_shard).toBe(2048);
    expect(meta.num_shards).toBeGreaterThanOrEqual(2);
    expect(meta.total_entries).toBe(meta.entries_per_shard * meta.num_shards);
    expect(BigInt(meta.response_modulus)).toBe(SERVED_RESPONSE_MODULUS);
    // Both shard-boundary rows are present: last of shard 0, first of shard 1.
    expect(meta.target_indices).toContain(meta.entries_per_shard - 1);
    expect(meta.target_indices).toContain(meta.entries_per_shard);
    expect(new Set(meta.shard_ids).size).toBeGreaterThanOrEqual(2);
    for (const entry of manifest.files) {
      expect(read(entry.name).length, `${entry.name} size`).toBe(entry.bytes);
    }
    // The CRS decoded above is the shipped one. At this ring dimension the server's own
    // is over a megabyte; http/tests/crs_wire_omits_galois_keys.rs:112-125 pins both ends.
    expect(shippedGaloisKeyCount()).toBe(0n);
    expect(crsBincode.length).toBeLessThan(4096);
  });

  it("recovers the 512-byte path-10 row native Rust encoded, at every fixture index", () => {
    for (const [slot, globalIdx] of meta.target_indices.entries()) {
      const plaintext = wasm.extract_response(
        session,
        crsBincode,
        clientStateFor(globalIdx),
        read(`response_for_idx_${globalIdx}.bin`),
        meta.entry_size,
      );
      expect(plaintext.length, `idx ${globalIdx} plaintext length`).toBe(RECORD_BYTES);
      expect(hex(plaintext), `idx ${globalIdx} row`).toBe(
        hex(read(`expected_plain_for_idx_${globalIdx}.bin`)),
      );
      // The row identifies itself: its BC carries its own global index, so a row served
      // from the wrong shard or the wrong offset cannot compare equal to the one asked
      // for. This is the assertion an off-by-one has to get past.
      expect(hex(plaintext.subarray(0, 32)), `idx ${globalIdx} bc`).toBe(meta.bcs_hex[slot]);
      expect(new TextDecoder().decode(plaintext.subarray(34, 38))).toBe(MAGIC);
      expect(
        plaintext.subarray(NODES_OFFSET, NODES_OFFSET + ROW_LEVELS * NODE_BYTES).some(
          (byte) => byte !== 0,
        ),
        `idx ${globalIdx} levels 0..10 must be populated`,
      ).toBe(true);
      expect(
        plaintext.subarray(NODES_OFFSET + ROW_LEVELS * NODE_BYTES).every((byte) => byte === 0),
        `idx ${globalIdx} tail past level 10 must be zero`,
      ).toBe(true);
    }
  });

  it("decodes with the RECORDED client state, so the fixture is self-contained", () => {
    for (const globalIdx of meta.target_indices) {
      const plaintext = wasm.extract_response(
        session,
        crsBincode,
        read(`client_state_for_idx_${globalIdx}.bin`),
        read(`response_for_idx_${globalIdx}.bin`),
        meta.entry_size,
      );
      expect(hex(plaintext), `idx ${globalIdx} via recorded state`).toBe(
        hex(read(`expected_plain_for_idx_${globalIdx}.bin`)),
      );
    }
  });

  it("addresses the shard boundary from the global index, one row apart", () => {
    // Where multi-shard addressing actually lives. Global 2047 is the last row of shard 0
    // and 2048 the first of shard 1, so a `global - 1` slip moves the query to the other
    // shard entirely; the local index it encrypts moves with it.
    const firstOfShardOne = meta.entries_per_shard;
    const lastOfShardZero = firstOfShardOne - 1;

    expect(clearShardSelector(0)).toBe(0);
    expect(clearShardSelector(lastOfShardZero)).toBe(0);
    expect(clearShardSelector(firstOfShardOne)).toBe(1);
    expect(clearShardSelector(meta.total_entries - 1)).toBe(1);
    for (const [slot, globalIdx] of meta.target_indices.entries()) {
      expect(clearShardSelector(globalIdx), `idx ${globalIdx} shard`).toBe(meta.shard_ids[slot]);
    }
  });

  it("does NOT bind the recovered row to the index the query asked for, even across shards", () => {
    // CHARACTERIZATION, not an endorsement, and the reason the BC equality above is the
    // real guard. At ring 256 this was known within one shard
    // (wasm_extract_fixture_decode.test.ts:221-239); it holds across a shard boundary too.
    // A server answering shard 1 row 0 to a query for shard 0 row 2047 returns a
    // well-formed 512-byte record under Ok, and only the row's own BC catches it.
    const firstOfShardOne = meta.entries_per_shard;
    const substituted = wasm.extract_response(
      session,
      crsBincode,
      clientStateFor(firstOfShardOne - 1),
      read(`response_for_idx_${firstOfShardOne}.bin`),
      meta.entry_size,
    );

    expect(substituted.length).toBe(RECORD_BYTES);
    expect(hex(substituted)).toBe(hex(read(`expected_plain_for_idx_${firstOfShardOne}.bin`)));
    expect(hex(substituted.subarray(0, 32))).not.toBe(
      hex(read(`expected_plain_for_idx_${firstOfShardOne - 1}.bin`).subarray(0, 32)),
    );
  });
});
