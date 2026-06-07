/** Two-layer IMT node cache: synchronous in-memory L1 over an optional IndexedDB L2. */

const ASYNC_TIMEOUT_MS = 5000;

/** Bounded LRU backed by `Map` insertion order; evicts oldest on overflow. */
class InMemoryLru {
  private readonly map: Map<string, Uint8Array> = new Map();
  private readonly capacity: number;

  constructor(capacity: number) {
    this.capacity = Math.max(1, capacity);
  }

  get(key: string): Uint8Array | undefined {
    const v = this.map.get(key);
    if (v !== undefined) {
      // re-insert to mark most-recently-used (Map keeps insertion order)
      this.map.delete(key);
      this.map.set(key, v);
    }
    return v;
  }

  set(key: string, value: Uint8Array): void {
    if (this.map.has(key)) {
      this.map.delete(key);
    }
    this.map.set(key, value);
    if (this.map.size > this.capacity) {
      const oldestKey = this.map.keys().next().value;
      if (oldestKey !== undefined) {
        this.map.delete(oldestKey);
      }
    }
  }

  clear(): void {
    this.map.clear();
  }

  size(): number {
    return this.map.size;
  }
}

/** Optional IndexedDB-backed L2; null when the runtime lacks `indexedDB`. */
interface IndexedDbBacking {
  get(key: string): Promise<Uint8Array | undefined>;
  set(key: string, value: Uint8Array): Promise<void>;
  clear(): Promise<void>;
}

function makeIndexedDbBacking(dbName: string): IndexedDbBacking | null {
  const idb = (globalThis as unknown as { indexedDB?: IDBFactory }).indexedDB;
  if (!idb) {
    return null;
  }
  let dbPromise: Promise<IDBDatabase> | null = null;
  function openDb(): Promise<IDBDatabase> {
    if (dbPromise) return dbPromise;
    dbPromise = new Promise<IDBDatabase>((resolve, reject) => {
      const req = idb.open(dbName, 1);
      req.onupgradeneeded = (): void => {
        const db = req.result;
        if (!db.objectStoreNames.contains("nodes")) {
          db.createObjectStore("nodes");
        }
      };
      req.onsuccess = (): void => resolve(req.result);
      req.onerror = (): void => reject(new Error(`indexedDB open: ${req.error?.message ?? "unknown"}`));
    });
    return dbPromise;
  }

  function withTimeout<T>(p: Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("indexedDB timeout")), ASYNC_TIMEOUT_MS);
      p.then(
        (v) => {
          clearTimeout(timer);
          resolve(v);
        },
        (e) => {
          clearTimeout(timer);
          reject(e);
        },
      );
    });
  }

  return {
    async get(key: string): Promise<Uint8Array | undefined> {
      const db = await openDb();
      return withTimeout(
        new Promise<Uint8Array | undefined>((resolve, reject) => {
          const tx = db.transaction("nodes", "readonly");
          const store = tx.objectStore("nodes");
          const req = store.get(key);
          req.onsuccess = (): void => {
            const v = req.result as ArrayBuffer | Uint8Array | undefined;
            if (v === undefined) {
              resolve(undefined);
            } else if (v instanceof Uint8Array) {
              resolve(v);
            } else {
              resolve(new Uint8Array(v));
            }
          };
          req.onerror = (): void => reject(new Error(`indexedDB get: ${req.error?.message ?? "unknown"}`));
        }),
      );
    },
    async set(key: string, value: Uint8Array): Promise<void> {
      const db = await openDb();
      return withTimeout(
        new Promise<void>((resolve, reject) => {
          const tx = db.transaction("nodes", "readwrite");
          const store = tx.objectStore("nodes");
          const req = store.put(value, key);
          req.onsuccess = (): void => resolve();
          req.onerror = (): void => reject(new Error(`indexedDB set: ${req.error?.message ?? "unknown"}`));
        }),
      );
    },
    async clear(): Promise<void> {
      const db = await openDb();
      return withTimeout(
        new Promise<void>((resolve, reject) => {
          const tx = db.transaction("nodes", "readwrite");
          const store = tx.objectStore("nodes");
          const req = store.clear();
          req.onsuccess = (): void => resolve();
          req.onerror = (): void => reject(new Error(`indexedDB clear: ${req.error?.message ?? "unknown"}`));
        }),
      );
    },
  };
}

/** Cache key over `(chainId, scope, level, idxAtLevel, epochTag, schemaVersion)`; `scope` is `tree-N` or `list-<hex>`. */
export function imtCacheKey(parts: {
  chainId: number;
  scope: string;
  level: number;
  idxAtLevel: number;
  epochTag: string;
  schemaVersion: number;
}): string {
  return [
    `c=${parts.chainId}`,
    `s=${parts.scope}`,
    `l=${parts.level}`,
    `i=${parts.idxAtLevel}`,
    `e=${parts.epochTag}`,
    `v=${parts.schemaVersion}`,
  ].join("|");
}

/** Construction options for [`ImtCache`]. */
export interface ImtCacheConfig {
  /** Opaque cache namespace; allows unrelated SDK instances to coexist. */
  readonly namespace?: string;
  /** Maximum entries kept in the in-memory layer. Default 1024. */
  readonly inMemoryCapacity?: number;
  /** Force-disable IndexedDB even if available. Default `false`. */
  readonly disableIndexedDb?: boolean;
}

export class ImtCache {
  private readonly memory: InMemoryLru;
  private readonly idb: IndexedDbBacking | null;
  private currentEpochTag: string = "";
  private currentSchemaVersion: number = 0;

  constructor(config: ImtCacheConfig = {}) {
    this.memory = new InMemoryLru(config.inMemoryCapacity ?? 1024);
    this.idb = config.disableIndexedDb ? null : makeIndexedDbBacking(`raven-imt-cache-${config.namespace ?? "default"}`);
  }

  /** Synchronous L1-only lookup; use `getAsync` to also probe IDB. */
  getSync(key: string): Uint8Array | undefined {
    return this.memory.get(key);
  }

  /** Probe both layers; promotes IDB hits into memory. */
  async getAsync(key: string): Promise<Uint8Array | undefined> {
    const m = this.memory.get(key);
    if (m !== undefined) return m;
    if (!this.idb) return undefined;
    try {
      const v = await this.idb.get(key);
      if (v !== undefined) {
        this.memory.set(key, v);
      }
      return v;
    } catch {
      return undefined;
    }
  }

  /** Insert into both layers; the IDB write is best-effort fire-and-forget. */
  set(key: string, value: Uint8Array): void {
    this.memory.set(key, value);
    if (this.idb) {
      this.idb.set(key, value).catch(() => undefined);
    }
  }

  /** Drop both layers if epoch or schema version advanced, so no stale node survives a reorg/schema bump. */
  noteFreshness(epochTag: string, schemaVersion: number): void {
    if (epochTag === this.currentEpochTag && schemaVersion === this.currentSchemaVersion) {
      return;
    }
    this.currentEpochTag = epochTag;
    this.currentSchemaVersion = schemaVersion;
    this.memory.clear();
    if (this.idb) {
      this.idb.clear().catch(() => undefined);
    }
  }

  /** Force-drop both cache layers. */
  async clearAll(): Promise<void> {
    this.memory.clear();
    if (this.idb) {
      try {
        await this.idb.clear();
      } catch {
        // best-effort
      }
    }
  }

  /** Snapshot of current in-memory layer occupancy. */
  inMemorySize(): number {
    return this.memory.size();
  }
}
