/**
 * Client-side IMT (Incremental Merkle Tree) node cache.
 *
 * Layered to handle both browser-wallet and Node-test environments:
 * - **IndexedDB** is preferred when the runtime exposes
 *   `globalThis.indexedDB` (modern browsers, desktop wallets backed by
 *   electron, hybrid mobile webviews).
 * - **In-memory** fallback always available; used by Node tests and as
 *   the L1 layer in browsers (so a cache hit doesn't have to await an
 *   async IndexedDB transaction every time).
 *
 * Cache keys are tuples (encoded as string) keyed on the chain ID,
 * tree number (commit-tree) or list_key hex (per-list), level, and
 * idx-at-level. The flat-global-index could be used directly but
 * (level, idx_at_level) is the wallet's natural lookup key from
 * `path_indices_for_leaf` (the wallet computes the sibling indices,
 * not the flat layout).
 *
 * Invalidation: the cache is parameterised by an opaque "epoch tag"
 * (Raven's `X-Raven-Epoch` header) AND a wire-schema-version tag
 * (`X-Raven-Schema-Version`). Either advancing in the response from
 * the server clears the cache slice for the affected chain ID.
 */

const ASYNC_TIMEOUT_MS = 5000;

/**
 * Bounded in-memory LRU. Backed by `Map` (insertion-order iteration);
 * on overflow the oldest key is evicted. The whole cache occupies at
 * most `capacity` entries × 32 byte values = 32 KB at the default
 * 1024 entries.
 */
class InMemoryLru {
  private readonly map: Map<string, Uint8Array> = new Map();
  private readonly capacity: number;

  constructor(capacity: number) {
    this.capacity = Math.max(1, capacity);
  }

  get(key: string): Uint8Array | undefined {
    const v = this.map.get(key);
    if (v !== undefined) {
      // Touch: re-insert to move to back (Map preserves insertion order).
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
      // Evict oldest.
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

/**
 * Optional IndexedDB-backed L2. Constructed lazily only if the runtime
 * exposes an `indexedDB` global; otherwise stays as a no-op shim.
 */
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
  // Open on first use.
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

/**
 * Compose a cache key from `(chainId, scope, level, idxAtLevel,
 * epochTag, schemaVersion)`. `scope` is either `tree-N` for a commit
 * tree or `list-<hex>` for a per-list PPOI tree.
 */
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

/**
 * Configurable IMT cache with a synchronous in-memory L1 and an
 * optional async IndexedDB L2.
 */
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

  /**
   * Synchronous fast-path. Returns the cached node hash bytes if
   * present in the in-memory layer; otherwise undefined. Callers
   * must NOT block on this; use `getAsync` to also probe IDB.
   */
  getSync(key: string): Uint8Array | undefined {
    return this.memory.get(key);
  }

  /**
   * Probe both layers; falls through to IDB on a memory miss.
   * Promotes IDB hits into memory before returning.
   */
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
      // IDB transient failure: fall through to memory-only behaviour.
      return undefined;
    }
  }

  /**
   * Insert into both layers. The IDB write is fire-and-forget so
   * callers don't need to await it on the hot path; rejections are
   * swallowed (the cache is best-effort, not authoritative).
   */
  set(key: string, value: Uint8Array): void {
    this.memory.set(key, value);
    if (this.idb) {
      this.idb.set(key, value).catch(() => undefined);
    }
  }

  /**
   * Note the latest epoch + schema version observed from a server
   * response. If either has advanced, drop both cache layers so a
   * stale node can't survive a server-side reorg or schema bump.
   */
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

  /**
   * Force-drop both cache layers. Test helper.
   */
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
