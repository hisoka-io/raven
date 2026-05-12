/**
 * Unit tests for the warm-cache path in `loadClientPirContext`.
 *
 * Vitest's Node test env does not expose `IndexedDB`, so the
 * session cache transparently falls through to the in-memory
 * `MemoryBackend`. These tests assert:
 *
 *   1. The first `loadClientPirContext` call invokes the cold
 *      path (`build_client_session`) and seeds the cache.
 *   2. A second call with the same `(instanceId, crsBincode)`
 *      hits the cache (`deserialize_client_session`) and skips
 *      the cold path.
 *   3. A second call with a different CRS hash (e.g. operator
 *      rotation) misses the cache and re-runs the cold path,
 *      seeding the new entry.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  loadClientPirContext,
  idbClear,
  idbGet,
  idbPut,
  type RavenInspireClientSession,
  type RavenInspireWasm,
} from "../src/index";
import { _setBackendForTests } from "../src/session-cache";

interface SpyWasm extends RavenInspireWasm {
  build_count: number;
  deserialize_count: number;
  serialize_count: number;
}

function makeSpyWasm(): SpyWasm {
  let _build = 0;
  let _deserialize = 0;
  let _serialize = 0;
  const handle: RavenInspireClientSession = { free: () => undefined };
  const spy: Partial<SpyWasm> = {
    build_count: 0,
    deserialize_count: 0,
    serialize_count: 0,
    build_instance_params_blob: (
      _inspire: Uint8Array,
      _shard: Uint8Array,
    ): Uint8Array => new Uint8Array([0xa, 0xb, 0xc]),
    build_client_session: (
      _params: Uint8Array,
      _crs: Uint8Array,
    ): RavenInspireClientSession => {
      _build += 1;
      // shadow into the spy object so callers can read after each call
      spy.build_count = _build;
      return handle;
    },
    serialize_client_session: (_session: RavenInspireClientSession): Uint8Array => {
      _serialize += 1;
      spy.serialize_count = _serialize;
      // Non-empty blob so the cache stores something deserializable.
      return new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    },
    deserialize_client_session: (
      _params: Uint8Array,
      _crs: Uint8Array,
      _blob: Uint8Array,
    ): RavenInspireClientSession => {
      _deserialize += 1;
      spy.deserialize_count = _deserialize;
      return handle;
    },
    build_seeded_query: () => new Uint8Array(),
    extract_response: () => new Uint8Array(),
    path_indices_for_leaf: () => new Uint32Array(16),
    path_indices_for_per_list_leaf: () => new Uint32Array(16),
  };
  return spy as SpyWasm;
}

afterEach(async () => {
  await idbClear();
  // Reset to the auto-detected default backend so each test gets a
  // fresh in-memory map (Node test env => MemoryBackend).
  _setBackendForTests(null);
  vi.restoreAllMocks();
});

// Test seam mirroring the in-tree MemoryBackend's storage shape:
// chunk records under `${key}#chunk-i` and a JSON meta record under
// `${key}#meta`. We expose the underlying Map so failure-injection
// tests can flip a byte inside a single chunk.
class ProbeBackend {
  readonly map = new Map<string, Uint8Array>();
  private readonly CHUNK_SIZE = 32 * 1024 * 1024;

  async get(key: string): Promise<Uint8Array | null> {
    const metaBytes = this.map.get(`${key}#meta`);
    if (!metaBytes) return null;
    let meta: { chunkCount: number; totalLen: number; sha256: string };
    try {
      meta = JSON.parse(new TextDecoder().decode(metaBytes));
    } catch {
      this.evict(key);
      return null;
    }
    const out = new Uint8Array(meta.totalLen);
    let off = 0;
    for (let i = 0; i < meta.chunkCount; i += 1) {
      const c = this.map.get(`${key}#chunk-${i}`);
      if (!c || off + c.length > meta.totalLen) {
        this.evict(key);
        return null;
      }
      out.set(c, off);
      off += c.length;
    }
    if (off !== meta.totalLen) {
      this.evict(key);
      return null;
    }
    const subtle = globalThis.crypto.subtle;
    const digest = new Uint8Array(await subtle.digest("SHA-256", out));
    let hex = "";
    for (let i = 0; i < digest.length; i += 1) {
      hex += digest[i].toString(16).padStart(2, "0");
    }
    if (hex !== meta.sha256) {
      this.evict(key);
      return null;
    }
    return out;
  }

  async put(key: string, blob: Uint8Array): Promise<void> {
    const subtle = globalThis.crypto.subtle;
    const view = new Uint8Array(blob.length);
    view.set(blob);
    const digest = new Uint8Array(await subtle.digest("SHA-256", view));
    let hex = "";
    for (let i = 0; i < digest.length; i += 1) {
      hex += digest[i].toString(16).padStart(2, "0");
    }
    this.evict(key);
    const total = blob.length;
    let i = 0;
    let off = 0;
    while (off < total || (total === 0 && i === 0)) {
      const end = Math.min(off + this.CHUNK_SIZE, total);
      const piece = new Uint8Array(end - off);
      piece.set(blob.subarray(off, end));
      this.map.set(`${key}#chunk-${i}`, piece);
      i += 1;
      off = end;
      if (total === 0) break;
    }
    const meta = { chunkCount: Math.max(i, 1), totalLen: total, sha256: hex };
    this.map.set(`${key}#meta`, new TextEncoder().encode(JSON.stringify(meta)));
  }

  async clear(): Promise<void> {
    this.map.clear();
  }

  private evict(key: string): void {
    for (const k of Array.from(this.map.keys())) {
      if (k === `${key}#meta` || k === key || k.startsWith(`${key}#chunk-`)) {
        this.map.delete(k);
      }
    }
  }
}

function deterministicBlob(len: number, seed: number): Uint8Array {
  // xorshift32 — keeps SHA-256 meaningful (not all-zeros) without
  // pulling Math.random's entropy into the test.
  let s = seed | 0;
  if (s === 0) s = 1;
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i += 1) {
    s ^= s << 13;
    s ^= s >>> 17;
    s ^= s << 5;
    out[i] = s & 0xff;
  }
  return out;
}

describe("loadClientPirContext warm-cache", () => {
  it("uses cache on second call with same params", async () => {
    const wasm = makeSpyWasm();
    const crs = new Uint8Array([0xfe, 0xed, 0xfa, 0xce]);
    const shard = new Uint8Array([0xde, 0xad]);
    const inspire = new Uint8Array([0xbe, 0xef]);

    const first = await loadClientPirContext({
      wasm,
      instanceId: "commit-tree-0",
      crsBincode: crs,
      shardConfigBincode: shard,
      inspireParamsBincode: inspire,
      entrySize: 32,
    });
    expect(first.cacheHit).toBe(false);
    expect(wasm.build_count).toBe(1);
    expect(wasm.serialize_count).toBe(1);
    expect(wasm.deserialize_count).toBe(0);

    const second = await loadClientPirContext({
      wasm,
      instanceId: "commit-tree-0",
      crsBincode: crs,
      shardConfigBincode: shard,
      inspireParamsBincode: inspire,
      entrySize: 32,
    });
    expect(second.cacheHit).toBe(true);
    expect(wasm.build_count).toBe(1);
    expect(wasm.deserialize_count).toBe(1);
  });

  it("busts cache when CRS hash changes", async () => {
    const wasm = makeSpyWasm();
    const crsA = new Uint8Array([0x01, 0x02, 0x03]);
    const crsB = new Uint8Array([0x04, 0x05, 0x06]);
    const shard = new Uint8Array([0xde, 0xad]);
    const inspire = new Uint8Array([0xbe, 0xef]);

    const first = await loadClientPirContext({
      wasm,
      instanceId: "commit-tree-0",
      crsBincode: crsA,
      shardConfigBincode: shard,
      inspireParamsBincode: inspire,
      entrySize: 32,
    });
    expect(first.cacheHit).toBe(false);
    expect(wasm.build_count).toBe(1);

    const second = await loadClientPirContext({
      wasm,
      instanceId: "commit-tree-0",
      crsBincode: crsB,
      shardConfigBincode: shard,
      inspireParamsBincode: inspire,
      entrySize: 32,
    });
    expect(second.cacheHit).toBe(false);
    expect(wasm.build_count).toBe(2);
    // Cache now holds two entries (one per CRS hash).
  });

  it("falls through to cold path when WASM lacks serde symbols", async () => {
    const wasm = makeSpyWasm();
    // Strip the optional serde methods to emulate an older WASM build.
    delete wasm.serialize_client_session;
    delete wasm.deserialize_client_session;

    const crs = new Uint8Array([0x07, 0x08, 0x09]);
    const shard = new Uint8Array([0xde, 0xad]);
    const inspire = new Uint8Array([0xbe, 0xef]);

    const first = await loadClientPirContext({
      wasm,
      instanceId: "commit-tree-1",
      crsBincode: crs,
      shardConfigBincode: shard,
      inspireParamsBincode: inspire,
      entrySize: 32,
    });
    expect(first.cacheHit).toBe(false);
    expect(wasm.build_count).toBe(1);

    const second = await loadClientPirContext({
      wasm,
      instanceId: "commit-tree-1",
      crsBincode: crs,
      shardConfigBincode: shard,
      inspireParamsBincode: inspire,
      entrySize: 32,
    });
    // No serde => no caching => cold every time.
    expect(second.cacheHit).toBe(false);
    expect(wasm.build_count).toBe(2);
  });

  it("falls through to cold rebuild when cached blob is corrupt", async () => {
    const wasm = makeSpyWasm();
    let throwOnDeserialize = false;
    const origDeserialize = wasm.deserialize_client_session!;
    wasm.deserialize_client_session = (
      params: Uint8Array,
      crs: Uint8Array,
      blob: Uint8Array,
    ): RavenInspireClientSession => {
      if (throwOnDeserialize) {
        throw new Error("simulated bincode-decode failure");
      }
      return origDeserialize(params, crs, blob);
    };

    const crs = new Uint8Array([0xab, 0xcd, 0xef]);
    const shard = new Uint8Array([0xde, 0xad]);
    const inspire = new Uint8Array([0xbe, 0xef]);

    // Cold rebuild + seed.
    await loadClientPirContext({
      wasm,
      instanceId: "commit-tree-2",
      crsBincode: crs,
      shardConfigBincode: shard,
      inspireParamsBincode: inspire,
      entrySize: 32,
    });
    expect(wasm.build_count).toBe(1);

    // Now flip the deserialize to simulate corrupt cache: the next
    // call should fall through to a cold rebuild rather than throw.
    throwOnDeserialize = true;
    const recovered = await loadClientPirContext({
      wasm,
      instanceId: "commit-tree-2",
      crsBincode: crs,
      shardConfigBincode: shard,
      inspireParamsBincode: inspire,
      entrySize: 32,
    });
    expect(recovered.cacheHit).toBe(false);
    expect(wasm.build_count).toBe(2);
  });
});

describe("idb chunked + integrity-verified storage", () => {
  it("round-trips an 80 MiB blob across multiple chunks", async () => {
    const instanceId = "test";
    const crsHash = "deadbeef".repeat(8);
    const blob = deterministicBlob(80 * 1024 * 1024, 0xc0ffee);

    await idbPut(instanceId, crsHash, blob);
    const got = await idbGet(instanceId, crsHash);
    expect(got).not.toBeNull();
    if (!got) return;
    expect(got.length).toBe(blob.length);
    // Spot-check head + tail + a mid-chunk byte to cover all 3 chunks
    // without paying the cost of a full byte-by-byte walk.
    expect(got[0]).toBe(blob[0]);
    expect(got[blob.length - 1]).toBe(blob[blob.length - 1]);
    expect(got[40 * 1024 * 1024]).toBe(blob[40 * 1024 * 1024]);
    // And a hash-equality check for the full-buffer guarantee.
    const subtle = globalThis.crypto.subtle;
    const gotCopy = new Uint8Array(got.length);
    gotCopy.set(got);
    const blobCopy = new Uint8Array(blob.length);
    blobCopy.set(blob);
    const a = new Uint8Array(await subtle.digest("SHA-256", gotCopy));
    const b = new Uint8Array(await subtle.digest("SHA-256", blobCopy));
    expect(Array.from(a)).toEqual(Array.from(b));
  });

  it("evicts and returns null when a chunk is corrupted", async () => {
    const probe = new ProbeBackend();
    _setBackendForTests(probe);

    const instanceId = "test";
    const crsHash = "deadbeef".repeat(8);
    const blob = deterministicBlob(80 * 1024 * 1024, 0xfeedface);

    await idbPut(instanceId, crsHash, blob);

    // Find the actual storage key (idbPut prefixes with the version
    // tag) so we can flip a byte inside chunk-1.
    const metaSuffix = "#meta";
    const metaEntry = Array.from(probe.map.keys()).find((k) =>
      k.endsWith(metaSuffix),
    );
    expect(metaEntry).toBeDefined();
    if (!metaEntry) return;
    const baseKey = metaEntry.slice(0, metaEntry.length - metaSuffix.length);
    const chunk1Key = `${baseKey}#chunk-1`;
    const chunk1 = probe.map.get(chunk1Key);
    expect(chunk1).toBeDefined();
    if (!chunk1) return;
    chunk1[123] ^= 0xff;
    probe.map.set(chunk1Key, chunk1);

    const got = await idbGet(instanceId, crsHash);
    expect(got).toBeNull();

    // The failed get must have evicted every record for the entry.
    const stragglers = Array.from(probe.map.keys()).filter(
      (k) => k === baseKey || k.startsWith(`${baseKey}#`),
    );
    expect(stragglers).toEqual([]);

    // A second get without re-put still misses.
    const second = await idbGet(instanceId, crsHash);
    expect(second).toBeNull();
  });

  it("treats legacy single-blob entries as cache misses", async () => {
    const probe = new ProbeBackend();
    _setBackendForTests(probe);

    const instanceId = "test";
    const crsHash = "cafebabe".repeat(8);

    // Mimic the S036 storage shape: a single record under the bare
    // key, with no `#meta` and no `#chunk-N` companions. The active
    // backend's get path looks up `#meta` first, so this must miss.
    const legacyKey = `v1:${instanceId}:${crsHash}`;
    probe.map.set(legacyKey, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));

    const got = await idbGet(instanceId, crsHash);
    expect(got).toBeNull();
  });
});
