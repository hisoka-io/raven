/**
 * The commitments this device submitted a proof for, per chain and list, so status can answer
 * `ProofSubmitted` until the commitment reaches the list instead of `Missing`, which would make
 * the engine generate and submit the same proof again on every refresh.
 *
 * An entry is dropped only once its commitment appears in the list's index, so a device submits
 * at most once per list and commitment for as long as the store keeps what it was given.
 */

import type { BcPrefixIndex } from "./bc-prefix-index";
import { indexCandidatesForEach } from "./bc-prefix-index";
import { bytesToHex, hexToBytes } from "./poi-pir";

/** Opaque records keyed by string. Any `{ load, save }` works, including
 *  `indexedDbPoiListIndexStore({ namespace })`, which has this shape. */
export interface SubmittedProofStore {
  load(key: string): Promise<Uint8Array | undefined>;
  save(key: string, record: Uint8Array): Promise<void>;
}

const RECORD_MAGIC = new Uint8Array([0x52, 0x56, 0x53, 0x31]);
const HASH_BYTES = 32;
const COUNT_AT = RECORD_MAGIC.length + HASH_BYTES;
const HEADER_BYTES = COUNT_AT + 4;

export function memorySubmittedProofStore(): SubmittedProofStore {
  const records = new Map<string, Uint8Array>();
  return {
    async load(key) {
      const record = records.get(key);
      return record === undefined ? undefined : new Uint8Array(record);
    },
    async save(key, record) {
      records.set(key, new Uint8Array(record));
    },
  };
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error("submitted proofs: Web Crypto is unavailable");
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return new Uint8Array(await subtle.digest("SHA-256", copy));
}

async function encodeRecord(listKeyHex: string, commitments: readonly string[]): Promise<Uint8Array> {
  const body = new Uint8Array(HEADER_BYTES + commitments.length * HASH_BYTES);
  body.set(RECORD_MAGIC, 0);
  body.set(hexToBytes(listKeyHex), RECORD_MAGIC.length);
  new DataView(body.buffer).setUint32(COUNT_AT, commitments.length);
  commitments.forEach((bcHex, at) => body.set(hexToBytes(bcHex), HEADER_BYTES + at * HASH_BYTES));
  const out = new Uint8Array(body.length + HASH_BYTES);
  out.set(body, 0);
  out.set(await sha256(body), body.length);
  return out;
}

/** An unreadable record reads as empty: refusing it would block status on that list forever,
 *  and the next submission rewrites it. */
async function decodeRecord(listKeyHex: string, record: Uint8Array): Promise<Set<string>> {
  const empty = new Set<string>();
  if (!(record instanceof Uint8Array) || record.length < HEADER_BYTES + HASH_BYTES) return empty;
  const body = record.subarray(0, record.length - HASH_BYTES);
  const listKey = hexToBytes(listKeyHex);
  for (let byte = 0; byte < RECORD_MAGIC.length; byte += 1) {
    if (body[byte] !== RECORD_MAGIC[byte]) return empty;
  }
  for (let byte = 0; byte < HASH_BYTES; byte += 1) {
    if (body[RECORD_MAGIC.length + byte] !== listKey[byte]) return empty;
  }
  const count = new DataView(body.buffer, body.byteOffset, body.byteLength).getUint32(COUNT_AT);
  if (body.length !== HEADER_BYTES + count * HASH_BYTES) return empty;
  const digest = await sha256(body);
  for (let byte = 0; byte < HASH_BYTES; byte += 1) {
    if (digest[byte] !== record[body.length + byte]) return empty;
  }
  const out = new Set<string>();
  for (let at = 0; at < count; at += 1) {
    const start = HEADER_BYTES + at * HASH_BYTES;
    out.add(bytesToHex(body.subarray(start, start + HASH_BYTES)));
  }
  return out;
}

/** 64 lower-case hex chars, or `undefined` for anything that names no commitment. Engine writes
 *  `0x00` for a transaction without an unshield, and upstream ignores zero commitments. */
export function submittedCommitmentHex(value: string): string | undefined {
  if (typeof value !== "string") return undefined;
  const hex = (value.startsWith("0x") || value.startsWith("0X") ? value.slice(2) : value).toLowerCase();
  if (hex.length === 0 || hex.length > 64 || !/^[0-9a-f]+$/.test(hex) || /^0+$/.test(hex)) {
    return undefined;
  }
  return hex.padStart(64, "0");
}

function recordKey(chainType: number, chainId: number, listKeyHex: string): string {
  return `v1|submitted|t=${chainType}|c=${chainId}|l=${listKeyHex}`;
}

export class SubmittedProofs {
  private readonly held = new Map<string, Set<string>>();
  private readonly loads = new Map<string, Promise<Set<string>>>();
  private readonly writes = new Map<string, Promise<void>>();
  private readonly unsaved = new Map<string, Set<string>>();

  constructor(private readonly store: SubmittedProofStore) {}

  /** Never throws: the submission it follows has already been accepted upstream. */
  async record(
    chainType: number,
    chainId: number,
    listKey: string,
    commitments: readonly string[],
  ): Promise<void> {
    const lkHex = submittedCommitmentHex(listKey);
    if (lkHex === undefined) return;
    const fresh = commitments
      .map(submittedCommitmentHex)
      .filter((bcHex): bcHex is string => bcHex !== undefined);
    if (fresh.length === 0) return;
    const key = recordKey(chainType, chainId, lkHex);
    let set: Set<string>;
    try {
      set = await this.load(key, lkHex);
    } catch {
      // Kept for this run and merged into the record once it can be read; saving now would
      // overwrite entries the unread record holds.
      const unsaved = this.unsaved.get(key) ?? new Set<string>();
      for (const bcHex of fresh) unsaved.add(bcHex);
      this.unsaved.set(key, unsaved);
      return;
    }
    const before = set.size;
    for (const bcHex of fresh) set.add(bcHex);
    if (set.size !== before) await this.persist(key, lkHex, set);
  }

  /** Entries still off the list once `index` is read, dropping those the index now holds.
   *  Throws when the store cannot be read, so a caller never answers `Missing` for a commitment
   *  it may have submitted. */
  async pendingAfter(
    chainType: number,
    chainId: number,
    lkHex: string,
    index: BcPrefixIndex,
  ): Promise<ReadonlySet<string>> {
    const key = recordKey(chainType, chainId, lkHex);
    const set = await this.load(key, lkHex);
    if (set.size === 0) return set;
    const entries = [...set];
    const found = indexCandidatesForEach(index, entries);
    let dropped = false;
    entries.forEach((bcHex, at) => {
      if (found[at].length > 0) {
        set.delete(bcHex);
        dropped = true;
      }
    });
    if (dropped) await this.persist(key, lkHex, set);
    return set;
  }

  private load(key: string, lkHex: string): Promise<Set<string>> {
    const held = this.held.get(key);
    if (held !== undefined) return Promise.resolve(held);
    let load = this.loads.get(key);
    if (load === undefined) {
      load = this.store.load(key).then(
        async (record) => {
          const set = record === undefined ? new Set<string>() : await decodeRecord(lkHex, record);
          const unsaved = this.unsaved.get(key);
          this.unsaved.delete(key);
          for (const bcHex of unsaved ?? []) set.add(bcHex);
          this.held.set(key, set);
          this.loads.delete(key);
          if (unsaved !== undefined) await this.persist(key, lkHex, set);
          return set;
        },
        (cause: unknown) => {
          this.loads.delete(key);
          throw cause;
        },
      );
      this.loads.set(key, load);
    }
    return load;
  }

  /** Saves run one at a time per key and each writes the set as it is when it runs, so the
   *  last save holds every entry. A failed save costs at most one resubmission after a restart. */
  private async persist(key: string, lkHex: string, set: Set<string>): Promise<void> {
    const prior = this.writes.get(key) ?? Promise.resolve();
    const run = prior
      .then(async () => this.store.save(key, await encodeRecord(lkHex, [...set])))
      .catch(() => undefined);
    this.writes.set(key, run);
    await run;
    if (this.writes.get(key) === run) this.writes.delete(key);
  }
}
