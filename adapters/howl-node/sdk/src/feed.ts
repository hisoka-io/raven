/** Bytes per row of the public tag-prefix feed. */
export const TAG_PREFIX_BYTES = 6;

/** A row's prefix as a number: 48 bits fit a double exactly. */
function key(bytes: Uint8Array, offset: number): number {
  return (
    (bytes[offset]! * 0x100 + bytes[offset + 1]!) * 0x1_0000_0000 +
    ((bytes[offset + 2]! << 24) >>> 0) +
    (bytes[offset + 3]! << 16) +
    (bytes[offset + 4]! << 8) +
    bytes[offset + 5]!
  );
}

/** The feed prefix of a 32-byte big-endian tag: its low-order six bytes. */
export function tagPrefix(tag: Uint8Array): Uint8Array {
  if (tag.length !== 32) throw new RangeError(`a tag is 32 bytes, got ${tag.length}`);
  return tag.slice(32 - TAG_PREFIX_BYTES);
}

/** A position whose feed row equals the prefix of one of the candidate tags. */
export interface FeedMatch {
  readonly position: number;
  /** Index of the matching tag in the list searched for. */
  readonly candidate: number;
}

/** The feed rows a source holds, read-only: what a wallet scans without a request. */
export interface FeedView {
  /** Rows held: `[0, length)`. */
  readonly length: number;
  /** The rows held, for the wallet to store. */
  bytes(): Uint8Array;
  /** As {@link PrefixFeed.matches}. */
  matches(tags: readonly Uint8Array[], from?: number): FeedMatch[];
}

/** The wallet's copy of the feed: rows `[0, length)`, appended in order. */
export class PrefixFeed implements FeedView {
  #rows: Uint8Array;
  #length = 0;

  constructor(rows?: Uint8Array) {
    if (rows !== undefined && rows.length % TAG_PREFIX_BYTES !== 0) {
      throw new RangeError(`feed of ${rows.length} bytes is not whole rows`);
    }
    this.#rows = new Uint8Array(Math.max(rows?.length ?? 0, 1024 * TAG_PREFIX_BYTES));
    if (rows !== undefined) {
      this.#rows.set(rows);
      this.#length = rows.length / TAG_PREFIX_BYTES;
    }
  }

  /** Rows held; also the position the next read starts at. */
  get length(): number {
    return this.#length;
  }

  /** The rows held, for the wallet to store. */
  bytes(): Uint8Array {
    return this.#rows.slice(0, this.#length * TAG_PREFIX_BYTES);
  }

  /** Append rows that start exactly at the rows held. */
  append(base: number, rows: Uint8Array): void {
    if (base !== this.#length) {
      throw new RangeError(`rows start at ${base}, the feed holds ${this.#length}`);
    }
    if (rows.length % TAG_PREFIX_BYTES !== 0) {
      throw new RangeError(`${rows.length} bytes is not whole rows`);
    }
    const end = this.#length * TAG_PREFIX_BYTES + rows.length;
    if (end > this.#rows.length) {
      const grown = new Uint8Array(Math.max(end, this.#rows.length * 2));
      grown.set(this.#rows.subarray(0, this.#length * TAG_PREFIX_BYTES));
      this.#rows = grown;
    }
    this.#rows.set(rows, this.#length * TAG_PREFIX_BYTES);
    this.#length += rows.length / TAG_PREFIX_BYTES;
  }

  /** Drop every row from `length` on. */
  truncate(length: number): void {
    if (length < this.#length) this.#length = Math.max(0, length);
  }

  /**
   * Every position at or after `from` (and never the genesis row 0) whose row equals the
   * prefix of one of `tags`, in position order. A tag held by several notes matches at each.
   */
  matches(tags: readonly Uint8Array[], from = 1): FeedMatch[] {
    const wanted = new Map<number, number[]>();
    tags.forEach((tag, candidate) => {
      const k = key(tagPrefix(tag), 0);
      const list = wanted.get(k);
      if (list === undefined) wanted.set(k, [candidate]);
      else list.push(candidate);
    });
    const found: FeedMatch[] = [];
    const rows = this.#rows;
    for (let position = Math.max(from, 1); position < this.#length; position++) {
      const candidates = wanted.get(key(rows, position * TAG_PREFIX_BYTES));
      if (candidates === undefined) continue;
      for (const candidate of candidates) found.push({ position, candidate });
    }
    return found;
  }
}
