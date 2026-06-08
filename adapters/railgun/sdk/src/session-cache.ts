// WASM ClientSession blob cache. Keyed by (instanceId, sha256(crsBincode)) so a
// CRS rotation auto-invalidates every entry. Stored as `${key}#chunk-i` plus a
// `${key}#meta` {chunkCount,totalLen,sha256}; one readwrite IDB transaction makes
// the chunk+meta set atomic. Any missing chunk / length / sha256 mismatch evicts
// the entry and degrades to a miss. IndexedDB in-browser, in-memory Map under node.
import { RavenError } from "./errors";

const DB_NAME = "raven-pir-session-cache-v1";
const STORE = "sessions";
const KEY_VERSION = 1;
const CHUNK_SIZE = 32 * 1024 * 1024;

interface CacheBackend {
  get(key: string): Promise<Uint8Array | null>;
  put(key: string, blob: Uint8Array): Promise<void>;
  clear(): Promise<void>;
}

interface ChunkMeta {
  chunkCount: number;
  totalLen: number;
  sha256: string;
}

let backend: CacheBackend | null = null;

function makeKey(instanceId: string, crsHash: string): string {
  return `v${KEY_VERSION}:${instanceId}:${crsHash}`;
}

function metaKey(key: string): string {
  return `${key}#meta`;
}

function chunkKey(key: string, i: number): string {
  return `${key}#chunk-${i}`;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

/** Lower-case hex SHA-256 via Web Crypto; throws a typed error if `crypto.subtle` is unavailable. */
export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw RavenError.decodeError(
      "session-cache.sha256Hex: globalThis.crypto.subtle is undefined; Web Crypto API required",
    );
  }
  const view = new Uint8Array(bytes.length);
  view.set(bytes);
  const digest = await subtle.digest("SHA-256", view);
  return bytesToHex(new Uint8Array(digest));
}

function encodeMeta(meta: ChunkMeta): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(meta));
}

function decodeMeta(bytes: Uint8Array): ChunkMeta | null {
  try {
    const obj = JSON.parse(new TextDecoder().decode(bytes)) as Partial<ChunkMeta>;
    if (
      typeof obj.chunkCount !== "number" ||
      typeof obj.totalLen !== "number" ||
      typeof obj.sha256 !== "string" ||
      obj.chunkCount < 0 ||
      obj.totalLen < 0
    ) {
      return null;
    }
    return { chunkCount: obj.chunkCount, totalLen: obj.totalLen, sha256: obj.sha256 };
  } catch {
    return null;
  }
}

function planChunks(blobLen: number): { chunkCount: number; ranges: Array<[number, number]> } {
  if (blobLen === 0) {
    return { chunkCount: 1, ranges: [[0, 0]] };
  }
  const ranges: Array<[number, number]> = [];
  let off = 0;
  while (off < blobLen) {
    const end = Math.min(off + CHUNK_SIZE, blobLen);
    ranges.push([off, end]);
    off = end;
  }
  return { chunkCount: ranges.length, ranges };
}

class MemoryBackend implements CacheBackend {
  // Exposed so failure-injection tests can corrupt a chunk.
  readonly map = new Map<string, Uint8Array>();

  async get(key: string): Promise<Uint8Array | null> {
    const metaBytes = this.map.get(metaKey(key));
    if (!metaBytes) return null;
    const meta = decodeMeta(metaBytes);
    if (!meta) {
      await this.evict(key, 0);
      return null;
    }
    const out = new Uint8Array(meta.totalLen);
    let off = 0;
    for (let i = 0; i < meta.chunkCount; i += 1) {
      const chunk = this.map.get(chunkKey(key, i));
      if (!chunk || off + chunk.length > meta.totalLen) {
        await this.evict(key, meta.chunkCount);
        return null;
      }
      out.set(chunk, off);
      off += chunk.length;
    }
    if (off !== meta.totalLen) {
      await this.evict(key, meta.chunkCount);
      return null;
    }
    const observed = await sha256Hex(out);
    if (observed !== meta.sha256) {
      await this.evict(key, meta.chunkCount);
      return null;
    }
    return out;
  }

  async put(key: string, blob: Uint8Array): Promise<void> {
    const sha = await sha256Hex(blob);
    const { chunkCount, ranges } = planChunks(blob.length);
    // Evict any prior shape first so stale chunks cannot survive.
    await this.evict(key, chunkCount);
    for (let i = 0; i < ranges.length; i += 1) {
      const [start, end] = ranges[i];
      const piece = new Uint8Array(end - start);
      piece.set(blob.subarray(start, end));
      this.map.set(chunkKey(key, i), piece);
    }
    const meta: ChunkMeta = { chunkCount, totalLen: blob.length, sha256: sha };
    this.map.set(metaKey(key), encodeMeta(meta));
  }

  async clear(): Promise<void> {
    this.map.clear();
  }

  private async evict(key: string, knownChunkCount: number): Promise<void> {
    this.map.delete(metaKey(key));
    this.map.delete(key);
    const limit = Math.max(knownChunkCount, 1);
    for (let i = 0; i < limit; i += 1) {
      this.map.delete(chunkKey(key, i));
    }
    // Sweep stragglers past the known count.
    for (const k of Array.from(this.map.keys())) {
      if (k.startsWith(`${key}#chunk-`)) this.map.delete(k);
    }
  }
}

class IndexedDbBackend implements CacheBackend {
  private dbPromise: Promise<IDBDatabase> | null = null;

  private openDb(): Promise<IDBDatabase> {
    if (this.dbPromise) return this.dbPromise;
    this.dbPromise = new Promise<IDBDatabase>((resolve, reject) => {
      const req = globalThis.indexedDB.open(DB_NAME, KEY_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE)) {
          db.createObjectStore(STORE);
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () =>
        reject(
          RavenError.decodeError(
            `session-cache: indexedDB.open failed: ${req.error?.message ?? "unknown"}`,
          ),
        );
    });
    return this.dbPromise;
  }

  async get(key: string): Promise<Uint8Array | null> {
    const db = await this.openDb();
    const meta = await this.readMeta(db, key);
    if (!meta) return null;
    const chunks = await this.readChunks(db, key, meta.chunkCount);
    if (!chunks) {
      await this.evict(key, meta.chunkCount);
      return null;
    }
    const out = new Uint8Array(meta.totalLen);
    let off = 0;
    for (const c of chunks) {
      if (off + c.length > meta.totalLen) {
        await this.evict(key, meta.chunkCount);
        return null;
      }
      out.set(c, off);
      off += c.length;
    }
    if (off !== meta.totalLen) {
      await this.evict(key, meta.chunkCount);
      return null;
    }
    const observed = await sha256Hex(out);
    if (observed !== meta.sha256) {
      await this.evict(key, meta.chunkCount);
      return null;
    }
    return out;
  }

  async put(key: string, blob: Uint8Array): Promise<void> {
    const db = await this.openDb();
    const sha = await sha256Hex(blob);
    const { chunkCount, ranges } = planChunks(blob.length);
    // Drop any prior shape first so stale chunks cannot linger.
    await this.evict(key, Number.MAX_SAFE_INTEGER);
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      const store = tx.objectStore(STORE);
      for (let i = 0; i < ranges.length; i += 1) {
        const [start, end] = ranges[i];
        const piece = new Uint8Array(end - start);
        piece.set(blob.subarray(start, end));
        store.put(piece, chunkKey(key, i));
      }
      const meta: ChunkMeta = { chunkCount, totalLen: blob.length, sha256: sha };
      store.put(encodeMeta(meta), metaKey(key));
      tx.oncomplete = () => resolve();
      tx.onerror = () =>
        reject(
          RavenError.decodeError(
            `session-cache: idb.put tx failed: ${tx.error?.message ?? "unknown"}`,
          ),
        );
      tx.onabort = () =>
        reject(
          RavenError.decodeError(
            `session-cache: idb.put tx aborted: ${tx.error?.message ?? "unknown"}`,
          ),
        );
    });
  }

  async clear(): Promise<void> {
    const db = await this.openDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      const req = tx.objectStore(STORE).clear();
      req.onsuccess = () => resolve();
      req.onerror = () =>
        reject(
          RavenError.decodeError(
            `session-cache: idb.clear failed: ${req.error?.message ?? "unknown"}`,
          ),
        );
    });
  }

  private async readMeta(db: IDBDatabase, key: string): Promise<ChunkMeta | null> {
    const raw = await new Promise<unknown>((resolve, reject) => {
      const tx = db.transaction(STORE, "readonly");
      const req = tx.objectStore(STORE).get(metaKey(key));
      req.onsuccess = () => resolve(req.result);
      req.onerror = () =>
        reject(
          RavenError.decodeError(
            `session-cache: idb.get(meta) failed: ${req.error?.message ?? "unknown"}`,
          ),
        );
    });
    if (raw == null) return null;
    let bytes: Uint8Array | null = null;
    if (raw instanceof Uint8Array) bytes = raw;
    else if (raw instanceof ArrayBuffer) bytes = new Uint8Array(raw);
    if (!bytes) return null;
    return decodeMeta(bytes);
  }

  private async readChunks(
    db: IDBDatabase,
    key: string,
    chunkCount: number,
  ): Promise<Uint8Array[] | null> {
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readonly");
      const store = tx.objectStore(STORE);
      const out: Array<Uint8Array | null> = new Array(chunkCount).fill(null);
      let pending = chunkCount;
      if (chunkCount === 0) return resolve([]);
      let failed = false;
      for (let i = 0; i < chunkCount; i += 1) {
        const req = store.get(chunkKey(key, i));
        const idx = i;
        req.onsuccess = () => {
          if (failed) return;
          const v = req.result;
          if (v instanceof Uint8Array) out[idx] = v;
          else if (v instanceof ArrayBuffer) out[idx] = new Uint8Array(v);
          else {
            failed = true;
            return resolve(null);
          }
          pending -= 1;
          if (pending === 0 && !failed) {
            resolve(out as Uint8Array[]);
          }
        };
        req.onerror = () => {
          if (failed) return;
          failed = true;
          reject(
            RavenError.decodeError(
              `session-cache: idb.get(chunk ${idx}) failed: ${req.error?.message ?? "unknown"}`,
            ),
          );
        };
      }
    });
  }

  private async evict(key: string, knownChunkCount: number): Promise<void> {
    const db = await this.openDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      const store = tx.objectStore(STORE);
      store.delete(metaKey(key));
      store.delete(key);
      const limit =
        knownChunkCount === Number.MAX_SAFE_INTEGER ? 0 : Math.max(knownChunkCount, 0);
      for (let i = 0; i < limit; i += 1) {
        store.delete(chunkKey(key, i));
      }
      // Unknown-upper-bound path: sweep straggler chunk records via cursor.
      if (knownChunkCount === Number.MAX_SAFE_INTEGER) {
        const prefix = `${key}#chunk-`;
        const req = store.openCursor();
        req.onsuccess = () => {
          const cursor = req.result;
          if (!cursor) return;
          if (typeof cursor.key === "string" && cursor.key.startsWith(prefix)) {
            cursor.delete();
          }
          cursor.continue();
        };
        req.onerror = () =>
          reject(
            RavenError.decodeError(
              `session-cache: idb.evict cursor failed: ${req.error?.message ?? "unknown"}`,
            ),
          );
      }
      tx.oncomplete = () => resolve();
      tx.onerror = () =>
        reject(
          RavenError.decodeError(
            `session-cache: idb.evict tx failed: ${tx.error?.message ?? "unknown"}`,
          ),
        );
      tx.onabort = () =>
        reject(
          RavenError.decodeError(
            `session-cache: idb.evict tx aborted: ${tx.error?.message ?? "unknown"}`,
          ),
        );
    });
  }
}

function ensureBackend(): CacheBackend {
  if (backend) return backend;
  const idb = (globalThis as { indexedDB?: IDBFactory }).indexedDB;
  backend = idb ? new IndexedDbBackend() : new MemoryBackend();
  return backend;
}

/** Replace the active backend. Test-only seam. */
export function _setBackendForTests(b: CacheBackend | null): void {
  backend = b;
}

/** Lookup a cached session blob; storage/integrity failures degrade to `null` so a backend issue never breaks query construction. */
export async function idbGet(
  instanceId: string,
  crsHash: string,
): Promise<Uint8Array | null> {
  try {
    return await ensureBackend().get(makeKey(instanceId, crsHash));
  } catch {
    return null;
  }
}

/** Best-effort cache of a session blob under `(instanceId, crsHash)`; chunk + meta writes share one atomic IDB transaction. */
export async function idbPut(
  instanceId: string,
  crsHash: string,
  blob: Uint8Array,
): Promise<void> {
  try {
    await ensureBackend().put(makeKey(instanceId, crsHash), blob);
  } catch {
    // best-effort cache
  }
}

/** Empty the cache. Used by tests to reset between cases. */
export async function idbClear(): Promise<void> {
  try {
    await ensureBackend().clear();
  } catch {
    // best-effort
  }
}
