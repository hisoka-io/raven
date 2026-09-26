/**
 * Where a list's commitment index lives between runs, so a restarted client resolves an index
 * with no request and resumes the channel from its cursor instead of re-walking the whole list.
 *
 * A record is opaque bytes the SDK writes and verifies itself: a store only has to hand back what
 * it was given. It is checked on the way in because an index answers absences, and a corrupted
 * prefix would turn a note that is on the list into `Missing` without any request to catch it.
 */

import { BC_INDEX_PREFIX_BYTES, type BcPrefixIndex } from "./bc-prefix-index";
import { hexToBytes } from "./poi-pir";

/** Browsers get IndexedDB by default. Node has none, so a Node caller supplies its own. */
export interface PoiListIndexStore {
  load(key: string): Promise<Uint8Array | undefined>;
  save(key: string, record: Uint8Array): Promise<void>;
}

export interface IndexedDbPoiListIndexStoreConfig {
  /** Separates unrelated SDK instances sharing one origin. */
  readonly namespace?: string;
  /** Defaults to `globalThis.indexedDB`. */
  readonly indexedDB?: IDBFactory;
}

const RECORD_MAGIC = new Uint8Array([0x52, 0x56, 0x58, 0x31]);
const LIST_KEY_BYTES = 32;
const EPOCH_AT = RECORD_MAGIC.length + LIST_KEY_BYTES;
const TOTAL_AT = EPOCH_AT + 8;
const HEADER_BYTES = TOTAL_AT + 4;
const DIGEST_BYTES = 32;
const STORE = "indexes";
const IDB_TIMEOUT_MS = 5_000;

/** One record per chain, node and list: a node's index is only ever resumed against that node. */
export function poiListIndexStoreKey(chainId: number, endpoint: string, listKeyHex: string): string {
  return `v1|c=${chainId}|e=${endpoint}|l=${listKeyHex}`;
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error("poi list index store: Web Crypto is unavailable");
  }
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return new Uint8Array(await subtle.digest("SHA-256", copy));
}

export async function encodePoiListIndexRecord(
  listKeyHex: string,
  index: BcPrefixIndex,
): Promise<Uint8Array> {
  const body = new Uint8Array(HEADER_BYTES + index.prefixes.length);
  body.set(RECORD_MAGIC, 0);
  body.set(hexToBytes(listKeyHex), RECORD_MAGIC.length);
  const view = new DataView(body.buffer);
  view.setUint32(EPOCH_AT, Math.floor(index.epoch / 0x1_0000_0000));
  view.setUint32(EPOCH_AT + 4, index.epoch >>> 0);
  view.setUint32(TOTAL_AT, index.total);
  body.set(index.prefixes, HEADER_BYTES);
  const out = new Uint8Array(body.length + DIGEST_BYTES);
  out.set(body, 0);
  out.set(await sha256(body), body.length);
  return out;
}

/** `undefined` for anything but an intact record of this list: a bad record costs a re-walk. */
export async function decodePoiListIndexRecord(
  listKeyHex: string,
  record: Uint8Array,
): Promise<BcPrefixIndex | undefined> {
  if (!(record instanceof Uint8Array) || record.length < HEADER_BYTES + DIGEST_BYTES) {
    return undefined;
  }
  const body = record.subarray(0, record.length - DIGEST_BYTES);
  const expectedKey = hexToBytes(listKeyHex);
  for (let byte = 0; byte < RECORD_MAGIC.length; byte += 1) {
    if (body[byte] !== RECORD_MAGIC[byte]) return undefined;
  }
  for (let byte = 0; byte < LIST_KEY_BYTES; byte += 1) {
    if (body[RECORD_MAGIC.length + byte] !== expectedKey[byte]) return undefined;
  }
  const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
  const epoch = view.getUint32(EPOCH_AT) * 0x1_0000_0000 + view.getUint32(EPOCH_AT + 4);
  const total = view.getUint32(TOTAL_AT);
  if (!Number.isSafeInteger(epoch) || body.length !== HEADER_BYTES + total * BC_INDEX_PREFIX_BYTES) {
    return undefined;
  }
  const digest = await sha256(body);
  const stored = record.subarray(body.length);
  for (let byte = 0; byte < DIGEST_BYTES; byte += 1) {
    if (digest[byte] !== stored[byte]) return undefined;
  }
  return { epoch, total, prefixes: body.slice(HEADER_BYTES) };
}

function withTimeout<T>(pending: Promise<T>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("indexedDB timeout")), IDB_TIMEOUT_MS);
    pending.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (cause: unknown) => {
        clearTimeout(timer);
        reject(cause);
      },
    );
  });
}

/** An IndexedDB-backed store, or `undefined` where the runtime has no IndexedDB. */
export function indexedDbPoiListIndexStore(
  config: IndexedDbPoiListIndexStoreConfig = {},
): PoiListIndexStore | undefined {
  const idb = config.indexedDB ?? (globalThis as { indexedDB?: IDBFactory }).indexedDB;
  if (idb === undefined) return undefined;
  const dbName = `raven-poi-list-index-${config.namespace ?? "default"}`;
  let opened: Promise<IDBDatabase> | undefined;
  const open = (): Promise<IDBDatabase> => {
    opened ??= new Promise<IDBDatabase>((resolve, reject) => {
      const req = idb.open(dbName, 1);
      req.onupgradeneeded = (): void => {
        if (!req.result.objectStoreNames.contains(STORE)) {
          req.result.createObjectStore(STORE);
        }
      };
      req.onsuccess = (): void => resolve(req.result);
      req.onerror = (): void => reject(new Error(`indexedDB open: ${req.error?.message ?? "unknown"}`));
    });
    return opened;
  };
  const run = async <T>(
    mode: IDBTransactionMode,
    op: (store: IDBObjectStore) => IDBRequest<T>,
  ): Promise<T> => {
    const db = await open();
    return withTimeout(
      new Promise<T>((resolve, reject) => {
        const req = op(db.transaction(STORE, mode).objectStore(STORE));
        req.onsuccess = (): void => resolve(req.result);
        req.onerror = (): void => reject(new Error(`indexedDB: ${req.error?.message ?? "unknown"}`));
      }),
    );
  };
  return {
    async load(key: string): Promise<Uint8Array | undefined> {
      const value: unknown = await run("readonly", (store) => store.get(key));
      if (value instanceof Uint8Array) return value;
      if (value instanceof ArrayBuffer) return new Uint8Array(value);
      return undefined;
    },
    async save(key: string, record: Uint8Array): Promise<void> {
      await run("readwrite", (store) => store.put(record, key));
    },
  };
}
