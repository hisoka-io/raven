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
      // Map keeps insertion order, so re-inserting marks most-recently-used.
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

  deleteByPrefix(prefix: string): void {
    for (const key of Array.from(this.map.keys())) {
      if (key.startsWith(prefix)) {
        this.map.delete(key);
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
  deleteByPrefix(prefix: string): Promise<void>;
  clear(): Promise<void>;
}

function makeIndexedDbBacking(dbName: string): IndexedDbBacking | null {
  const idb = (globalThis as unknown as { indexedDB?: IDBFactory }).indexedDB;
  return idb === undefined ? null : indexedDbBacking(idb, dbName);
}

function indexedDbBacking(idb: IDBFactory, dbName: string): IndexedDbBacking {
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
    async deleteByPrefix(prefix: string): Promise<void> {
      const db = await openDb();
      return withTimeout(
        new Promise<void>((resolve, reject) => {
          const tx = db.transaction("nodes", "readwrite");
          const store = tx.objectStore("nodes");
          const req = store.delete(IDBKeyRange.bound(prefix, `${prefix}\uffff`));
          req.onsuccess = (): void => resolve();
          req.onerror = (): void =>
            reject(new Error(`indexedDB deleteByPrefix: ${req.error?.message ?? "unknown"}`));
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

/** Key prefix every node of one instance's scope shares; `scope` is `tree-N` or `list-<hex>`. */
export function imtCacheScopeKey(parts: { chainId: number; scope: string }): string {
  return `c=${parts.chainId}|s=${parts.scope}|`;
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
  return (
    imtCacheScopeKey(parts) +
    [
      `l=${parts.level}`,
      `i=${parts.idxAtLevel}`,
      `e=${parts.epochTag}`,
      `v=${parts.schemaVersion}`,
    ].join("|")
  );
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

interface ScopeFreshness {
  epochTag: string;
  schemaVersion: number;
}

export class ImtCache {
  private readonly memory: InMemoryLru;
  private readonly idb: IndexedDbBacking | null;
  private readonly freshness: Map<string, ScopeFreshness> = new Map();

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

  /** Drop one scope's nodes from both layers on its own epoch or schema advance, so no node
   * survives a reorg. Snapshots advance per instance, so a sibling scope keeps its nodes. */
  noteFreshness(scopeKey: string, epochTag: string, schemaVersion: number): void {
    const seen = this.freshness.get(scopeKey);
    if (seen !== undefined && seen.epochTag === epochTag && seen.schemaVersion === schemaVersion) {
      return;
    }
    this.freshness.set(scopeKey, { epochTag, schemaVersion });
    this.memory.deleteByPrefix(scopeKey);
    if (this.idb) {
      this.idb.deleteByPrefix(scopeKey).catch(() => undefined);
    }
  }

  /** Force-drop both cache layers, every scope. */
  async clearAll(): Promise<void> {
    this.freshness.clear();
    this.memory.clear();
    if (this.idb) {
      try {
        await this.idb.clear();
      } catch {
      }
    }
  }

  /** Snapshot of current in-memory layer occupancy. */
  inMemorySize(): number {
    return this.memory.size();
  }
}
