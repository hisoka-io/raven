// Warm-cache path for loadClientPirContext. Node test env has no IndexedDB, so the
// cache falls through to the in-memory MemoryBackend.
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  loadClientPirContext,
  idbClear,
  idbGet,
  idbPut,
  sha256Hex,
  type RavenInspireClientSession,
  type RavenInspireWasm,
} from "../src/index";
import { makeRegisterSpy, type RegisterClientSessionSpy } from "./helpers/register_spy";
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
    register_client_session: makeRegisterSpy(),
    build_client_session: (
      _params: Uint8Array,
      _crs: Uint8Array,
    ): RavenInspireClientSession => {
      _build += 1;
      spy.build_count = _build;
      return handle;
    },
    serialize_client_session: (_session: RavenInspireClientSession): Uint8Array => {
      _serialize += 1;
      spy.serialize_count = _serialize;
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
  vi.unstubAllGlobals();
  _setBackendForTests(null);
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// A DUMB fake IndexedDB: stores exactly what it is told, verifies NOTHING.
//
// Its predecessor (`ProbeBackend`) replaced the whole storage layer via
// `_setBackendForTests` and reimplemented the sha256 integrity check inside the
// test file — so deleting the SDK's own check (both copies) left this file 7/7
// green (mutation M1, w4d-sdk). All integrity behaviour must come from
// `IndexedDbBackend`/`MemoryBackend` in src/session-cache.ts; the fake's one job
// is to let the real IndexedDbBackend run under node and to expose the record
// map so a test can corrupt a chunk at rest.
// ---------------------------------------------------------------------------

class FakeIdbRequest<T = unknown> {
  onsuccess: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onupgradeneeded: (() => void) | null = null;
  result: T | undefined = undefined;
  error: Error | null = null;
  transaction: null = null;
}

interface FakeCursor {
  key: string;
  delete(): void;
  continue(): void;
}

class FakeTx {
  oncomplete: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onabort: (() => void) | null = null;
  error: Error | null = null;
  private pending = 0;
  private completed = false;

  constructor(private readonly db: FakeIdbDatabase) {}

  objectStore(_name: string): FakeStore {
    return new FakeStore(this.db, this);
  }

  opBegin(): void {
    this.pending += 1;
  }

  opEnd(): void {
    this.pending -= 1;
    if (this.pending === 0 && !this.completed) {
      this.completed = true;
      queueMicrotask(() => this.oncomplete?.());
    }
  }
}

class FakeStore {
  constructor(
    private readonly db: FakeIdbDatabase,
    private readonly tx: FakeTx,
  ) {}

  private schedule<T>(fn: () => T): FakeIdbRequest<T> {
    const req = new FakeIdbRequest<T>();
    this.tx.opBegin();
    queueMicrotask(() => {
      req.result = fn();
      req.onsuccess?.();
      this.tx.opEnd();
    });
    return req;
  }

  get(key: string): FakeIdbRequest<unknown> {
    return this.schedule(() => this.db.records.get(key));
  }

  put(value: unknown, key: string): FakeIdbRequest<void> {
    if (this.db.failPuts) {
      throw new Error("FakeIndexedDb: injected put failure");
    }
    return this.schedule(() => {
      this.db.records.set(key, value);
    });
  }

  delete(key: string): FakeIdbRequest<void> {
    return this.schedule(() => {
      this.db.records.delete(key);
    });
  }

  clear(): FakeIdbRequest<void> {
    return this.schedule(() => {
      this.db.records.clear();
    });
  }

  openCursor(): FakeIdbRequest<FakeCursor | null> {
    const req = new FakeIdbRequest<FakeCursor | null>();
    this.tx.opBegin();
    const keys = Array.from(this.db.records.keys());
    let i = 0;
    const fire = (): void => {
      queueMicrotask(() => {
        if (i >= keys.length) {
          req.result = null;
          req.onsuccess?.();
          this.tx.opEnd();
          return;
        }
        const key = keys[i];
        req.result = {
          key,
          delete: () => {
            this.db.records.delete(key);
          },
          continue: () => {
            i += 1;
            fire();
          },
        };
        req.onsuccess?.();
      });
    };
    fire();
    return req;
  }
}

class FakeIdbDatabase {
  readonly records = new Map<string, unknown>();
  failPuts = false;
  readonly objectStoreNames = {
    contains: (_name: string): boolean => this.storeCreated,
  };
  private storeCreated = false;

  createObjectStore(_name: string): void {
    this.storeCreated = true;
  }

  transaction(_name: string, _mode: string): FakeTx {
    return new FakeTx(this);
  }
}

class FakeIdbFactory {
  readonly db = new FakeIdbDatabase();

  open(_name: string, _version: number): FakeIdbRequest<FakeIdbDatabase> {
    const req = new FakeIdbRequest<FakeIdbDatabase>();
    queueMicrotask(() => {
      req.result = this.db;
      req.onupgradeneeded?.();
      req.onsuccess?.();
    });
    return req;
  }
}

/** Route the module through the REAL IndexedDbBackend over a dumb fake store. */
function installFakeIndexedDb(): FakeIdbDatabase {
  const factory = new FakeIdbFactory();
  vi.stubGlobal("indexedDB", factory as unknown as IDBFactory);
  // Reset the module-level backend so ensureBackend re-selects IndexedDbBackend.
  _setBackendForTests(null);
  return factory.db;
}

function deterministicBlob(len: number, seed: number): Uint8Array {
  // xorshift32: non-trivial bytes for a meaningful SHA-256, deterministic across runs.
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
      persistSession: true,
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
      persistSession: true,
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
      persistSession: true,
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
      persistSession: true,
    });
    expect(second.cacheHit).toBe(false);
    expect(wasm.build_count).toBe(2);
  });

  it("falls through to cold path when WASM lacks serde symbols", async () => {
    const wasm = makeSpyWasm();
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
      persistSession: true,
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
      persistSession: true,
    });
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

    await loadClientPirContext({
      wasm,
      instanceId: "commit-tree-2",
      crsBincode: crs,
      shardConfigBincode: shard,
      inspireParamsBincode: inspire,
      entrySize: 32,
      persistSession: true,
    });
    expect(wasm.build_count).toBe(1);

    // Corrupt-cache simulation: the next call must cold-rebuild, not throw.
    throwOnDeserialize = true;
    const recovered = await loadClientPirContext({
      wasm,
      instanceId: "commit-tree-2",
      crsBincode: crs,
      shardConfigBincode: shard,
      inspireParamsBincode: inspire,
      entrySize: 32,
      persistSession: true,
    });
    expect(recovered.cacheHit).toBe(false);
    expect(wasm.build_count).toBe(2);
  });

  // D3 (client-pir.ts:182/:198): register_client_session exists to catch the session
  // drifting from the SERVER's instance params, but the SDK hands it the bundle
  // build_client_session just consumed — locally rebuilt from the same inputs — so the
  // guard compares a value against itself and its Err branch is unreachable in
  // production. RED-by-design until the SDK passes the server-supplied bundle; when that
  // fix lands this flips to a real failure and forces the un-marking.
  it.fails(
    "D3: the bundle handed to register_client_session is the server's, not the locally rebuilt one",
    async () => {
      const wasm = makeSpyWasm();
      const spy = wasm.register_client_session as RegisterClientSessionSpy;
      await loadClientPirContext({
        wasm,
        instanceId: "commit-tree-3",
        crsBincode: new Uint8Array([1, 2, 3]),
        shardConfigBincode: new Uint8Array([0xde, 0xad]),
        inspireParamsBincode: new Uint8Array([0xbe, 0xef]),
        entrySize: 32,
      });
      const locallyBuilt = wasm.build_instance_params_blob(
        new Uint8Array([0xbe, 0xef]),
        new Uint8Array([0xde, 0xad]),
      );
      expect(spy.calls.length).toBeGreaterThan(0);
      expect(Array.from(spy.calls[0].bundle)).not.toEqual(Array.from(locallyBuilt));
    },
  );
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
    // Head/tail/mid-chunk spot-check across all 3 chunks; full equality via the hash below.
    expect(got[0]).toBe(blob[0]);
    expect(got[blob.length - 1]).toBe(blob[blob.length - 1]);
    expect(got[40 * 1024 * 1024]).toBe(blob[40 * 1024 * 1024]);
    const subtle = globalThis.crypto.subtle;
    const gotCopy = new Uint8Array(got.length);
    gotCopy.set(got);
    const blobCopy = new Uint8Array(blob.length);
    blobCopy.set(blob);
    const a = new Uint8Array(await subtle.digest("SHA-256", gotCopy));
    const b = new Uint8Array(await subtle.digest("SHA-256", blobCopy));
    expect(Array.from(a)).toEqual(Array.from(b));
  });

  it("stores ceil(len / CHUNK_SIZE) chunks — chunking observably happened", async () => {
    // KILLS mutation M2 (CHUNK_SIZE -> 1 GiB left this file green): the chunk count is
    // read from what the real IndexedDbBackend put at rest, and the chunk size is
    // DERIVED from the stored chunk 0 rather than duplicated as a second literal the
    // real constant can drift away from. If CHUNK_SIZE ever grows past this blob, the
    // multi-chunk path has lost its only coverage and this red is the alarm.
    const db = installFakeIndexedDb();

    const instanceId = "test";
    const crsHash = "deadbeef".repeat(8);
    const blob = deterministicBlob(80 * 1024 * 1024, 0xc0ffee);
    await idbPut(instanceId, crsHash, blob);

    const chunkKeys = Array.from(db.records.keys())
      .filter((k) => k.includes("#chunk-"))
      .sort((a, b) => Number(a.split("#chunk-")[1]) - Number(b.split("#chunk-")[1]));
    expect(chunkKeys.length, "chunking must actually happen").toBeGreaterThanOrEqual(2);

    const chunks = chunkKeys.map((k) => db.records.get(k) as Uint8Array);
    const chunkSize = chunks[0].length;
    expect(chunkKeys.length).toBe(Math.ceil(blob.length / chunkSize));
    for (let i = 0; i < chunks.length - 1; i += 1) {
      expect(chunks[i].length, `chunk ${i} must be full-size`).toBe(chunkSize);
    }
    expect(chunks[chunks.length - 1].length).toBe(
      blob.length - (chunks.length - 1) * chunkSize,
    );
    expect(
      Array.from(db.records.keys()).filter((k) => k.endsWith("#meta")),
    ).toHaveLength(1);

    const got = await idbGet(instanceId, crsHash);
    expect(got).not.toBeNull();
    expect(got!.length).toBe(blob.length);
    expect(got![40 * 1024 * 1024]).toBe(blob[40 * 1024 * 1024]);
  });

  it("evicts and returns null when a chunk is corrupted (the SDK's own check)", async () => {
    // KILLS mutation M1: the corruption is planted in the dumb store and the verdict
    // comes from IndexedDbBackend.get's sha256 branch in src/session-cache.ts — delete
    // that branch and the corrupted bytes come back non-null here.
    const db = installFakeIndexedDb();

    const instanceId = "test";
    const crsHash = "deadbeef".repeat(8);
    const blob = deterministicBlob(80 * 1024 * 1024, 0xfeedface);

    await idbPut(instanceId, crsHash, blob);

    const metaSuffix = "#meta";
    const metaEntry = Array.from(db.records.keys()).find((k) => k.endsWith(metaSuffix));
    expect(metaEntry).toBeDefined();
    if (!metaEntry) return;
    const baseKey = metaEntry.slice(0, metaEntry.length - metaSuffix.length);
    const chunk1Key = `${baseKey}#chunk-1`;
    const chunk1 = db.records.get(chunk1Key) as Uint8Array | undefined;
    expect(chunk1).toBeDefined();
    if (!chunk1) return;
    chunk1[123] ^= 0xff;
    db.records.set(chunk1Key, chunk1);

    // Boolean compare, not toBeNull: a red here hands vitest an 80 MiB buffer to diff.
    const got = await idbGet(instanceId, crsHash);
    expect(got === null, "corrupted chunk must be refused, not returned").toBe(true);

    const stragglers = Array.from(db.records.keys()).filter(
      (k) => k === baseKey || k.startsWith(`${baseKey}#`),
    );
    expect(stragglers).toEqual([]);

    const second = await idbGet(instanceId, crsHash);
    expect(second === null, "the corrupted entry must stay evicted").toBe(true);
  });

  it("treats legacy single-blob entries as cache misses", async () => {
    const db = installFakeIndexedDb();

    const instanceId = "test";
    const crsHash = "cafebabe".repeat(8);

    // Pre-chunked shape: a bare-key record with no `#meta`; the get path looks up `#meta` first, so it must miss.
    const legacyKey = `v1:${instanceId}:${crsHash}`;
    db.records.set(legacyKey, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));

    const got = await idbGet(instanceId, crsHash);
    expect(got).toBeNull();
  });

  it("idbClear empties the store through the real IndexedDbBackend", async () => {
    const db = installFakeIndexedDb();
    await idbPut("test", "ab".repeat(32), deterministicBlob(1024, 7));
    expect(db.records.size).toBeGreaterThan(0);
    await idbClear();
    expect(db.records.size).toBe(0);
    expect(await idbGet("test", "ab".repeat(32))).toBeNull();
  });

  it("a failing backend degrades to a cache miss and a cold rebuild, never a throw", async () => {
    // idbPut/idbGet swallow backend exceptions BY CONTRACT (best-effort cache): the
    // observable guarantee is that a broken IndexedDB costs warmth, not correctness.
    const db = installFakeIndexedDb();
    db.failPuts = true;

    await expect(
      idbPut("test", "cd".repeat(32), deterministicBlob(1024, 9)),
    ).resolves.toBeUndefined();
    await expect(idbGet("test", "cd".repeat(32))).resolves.toBeNull();

    const wasm = makeSpyWasm();
    const args = {
      wasm,
      instanceId: "commit-tree-9",
      crsBincode: new Uint8Array([9, 9, 9]),
      shardConfigBincode: new Uint8Array([1]),
      inspireParamsBincode: new Uint8Array([2]),
      entrySize: 32,
      persistSession: true,
    };
    const first = await loadClientPirContext(args);
    const second = await loadClientPirContext(args);
    expect(first.cacheHit).toBe(false);
    expect(second.cacheHit, "a dead cache can never hit").toBe(false);
    expect(wasm.build_count, "every load must cold-build").toBe(2);
  });
});

describe("sha256Hex", () => {
  it("matches the SHA-256 KAT for the empty input", async () => {
    expect(await sha256Hex(new Uint8Array(0))).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  it("matches the SHA-256 KAT for 'abc'", async () => {
    expect(await sha256Hex(new TextEncoder().encode("abc"))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("throws a typed error when crypto.subtle is unavailable, instead of caching unverified", async () => {
    vi.stubGlobal("crypto", {});
    try {
      await expect(sha256Hex(new Uint8Array([1, 2, 3]))).rejects.toThrow(
        /crypto\.subtle is undefined/,
      );
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
