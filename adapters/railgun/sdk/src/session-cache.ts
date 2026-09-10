// ClientSession blob cache keyed by (instanceId, sha256(crsBincode)), so a CRS
// rotation self-invalidates. Chunks plus a `#meta` record are written in ONE
// readwrite IDB transaction; any missing chunk or digest mismatch evicts the entry.
import { RavenError } from "./errors";

const DB_NAME = "raven-pir-session-cache-v1";
const STORE = "sessions";
// Drives both `makeKey` and the IndexedDB version, so a bump rotates every key AND
// fires `onupgradeneeded`. A residue carries the client's RLWE secret key, so a
// stale one silently reinstates whatever key wrote it.
const KEY_VERSION = 2;
const CHUNK_SIZE = 32 * 1024 * 1024;

export interface SessionCacheStorageForTests {
  get(key: string): Promise<Uint8Array | null>;
  put(records: ReadonlyArray<readonly [string, Uint8Array]>): Promise<void>;
  deletePrefix(key: string): Promise<void>;
  clear(): Promise<void>;
}

interface ChunkMeta {
  chunkCount: number;
  totalLen: number;
  sha256: string;
}

let backend: IntegrityCache | null = null;

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

class IntegrityCache {
  constructor(private readonly storage: SessionCacheStorageForTests) {}

  async get(key: string): Promise<Uint8Array | null> {
    const metaBytes = await this.storage.get(metaKey(key));
    if (!metaBytes) return null;
    const meta = decodeMeta(metaBytes);
    if (!meta) {
      await this.storage.deletePrefix(key);
      return null;
    }
    const out = new Uint8Array(meta.totalLen);
    let offset = 0;
    for (let index = 0; index < meta.chunkCount; index += 1) {
      const chunk = await this.storage.get(chunkKey(key, index));
      if (!chunk || offset + chunk.length > meta.totalLen) {
        await this.storage.deletePrefix(key);
        return null;
      }
      out.set(chunk, offset);
      offset += chunk.length;
    }
    if (offset !== meta.totalLen || (await sha256Hex(out)) !== meta.sha256) {
      await this.storage.deletePrefix(key);
      return null;
    }
    return out;
  }

  async put(key: string, blob: Uint8Array): Promise<void> {
    const sha256 = await sha256Hex(blob);
    const { chunkCount, ranges } = planChunks(blob.length);
    const records: Array<readonly [string, Uint8Array]> = ranges.map(([start, end], index) => {
      const chunk = new Uint8Array(end - start);
      chunk.set(blob.subarray(start, end));
      return [chunkKey(key, index), chunk] as const;
    });
    records.push([
      metaKey(key),
      encodeMeta({ chunkCount, totalLen: blob.length, sha256 }),
    ]);
    await this.storage.deletePrefix(key);
    await this.storage.put(records);
  }

  async clear(): Promise<void> {
    await this.storage.clear();
  }
}

class MemoryStorage implements SessionCacheStorageForTests {
  readonly map = new Map<string, Uint8Array>();

  async get(key: string): Promise<Uint8Array | null> {
    return this.map.get(key) ?? null;
  }

  async put(records: ReadonlyArray<readonly [string, Uint8Array]>): Promise<void> {
    for (const [key, value] of records) {
      this.map.set(key, value);
    }
  }

  async deletePrefix(key: string): Promise<void> {
    for (const storedKey of this.map.keys()) {
      if (storedKey === key || storedKey.startsWith(`${key}#`)) {
        this.map.delete(storedKey);
      }
    }
  }

  async clear(): Promise<void> {
    this.map.clear();
  }
}

class IndexedDbStorage implements SessionCacheStorageForTests {
  private dbPromise: Promise<IDBDatabase> | null = null;

  private openDb(): Promise<IDBDatabase> {
    if (this.dbPromise) return this.dbPromise;
    this.dbPromise = new Promise<IDBDatabase>((resolve, reject) => {
      const req = globalThis.indexedDB.open(DB_NAME, KEY_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE)) {
          db.createObjectStore(STORE);
          return;
        }
        // A key-prefix rotation would orphan the RLWE-key-bearing residue, not
        // remove it from disk.
        req.transaction?.objectStore(STORE).clear();
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
    const raw = await new Promise<unknown>((resolve, reject) => {
      const tx = db.transaction(STORE, "readonly");
      const request = tx.objectStore(STORE).get(key);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () =>
        reject(
          RavenError.decodeError(
            `session-cache: idb.get failed for ${key}: ${request.error?.message ?? "unknown"}`,
          ),
        );
    });
    if (raw instanceof Uint8Array) return raw;
    if (raw instanceof ArrayBuffer) return new Uint8Array(raw);
    return null;
  }

  async put(records: ReadonlyArray<readonly [string, Uint8Array]>): Promise<void> {
    const db = await this.openDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      const store = tx.objectStore(STORE);
      for (const [key, value] of records) {
        store.put(value, key);
      }
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

  async deletePrefix(key: string): Promise<void> {
    const db = await this.openDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      const store = tx.objectStore(STORE);
      store.delete(key);
      const prefix = `${key}#`;
      const request = store.openCursor();
      request.onsuccess = () => {
        const cursor = request.result;
        if (!cursor) return;
        if (typeof cursor.key === "string" && cursor.key.startsWith(prefix)) {
          cursor.delete();
        }
        cursor.continue();
      };
      request.onerror = () =>
        reject(
          RavenError.decodeError(
            `session-cache: idb.deletePrefix failed: ${request.error?.message ?? "unknown"}`,
          ),
        );
      tx.oncomplete = () => resolve();
      tx.onerror = () =>
        reject(
          RavenError.decodeError(
            `session-cache: idb.deletePrefix tx failed: ${tx.error?.message ?? "unknown"}`,
          ),
        );
      tx.onabort = () =>
        reject(
          RavenError.decodeError(
            `session-cache: idb.deletePrefix tx aborted: ${tx.error?.message ?? "unknown"}`,
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

}

function ensureBackend(): IntegrityCache {
  if (backend) return backend;
  const idb = (globalThis as { indexedDB?: IDBFactory }).indexedDB;
  backend = new IntegrityCache(idb ? new IndexedDbStorage() : new MemoryStorage());
  return backend;
}

/** Replace only raw storage beneath the production integrity layer. */
export function _setStorageForTests(storage: SessionCacheStorageForTests | null): void {
  backend = storage ? new IntegrityCache(storage) : null;
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
