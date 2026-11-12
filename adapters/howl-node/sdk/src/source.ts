import { HowlError, MAX_RETRY_AFTER_SECONDS, protocol, retryAfterSeconds, type AnswerState } from "./errors.js";
import { PrefixFeed, TAG_PREFIX_BYTES, type FeedMatch, type FeedView } from "./feed.js";
import { neverAnswered, type Exchange, type HowlTransport } from "./http.js";
import { COMMITMENT_PREFIX_BYTES, decodeCell, missRecord, type FieldCodec, type HowlNoteRecord } from "./record.js";
import { decode, KIND, type Answer, type HowlClientHandle, type HowlTreeHandle, type HowlWasm } from "./wasm.js";

/** Leaves per tree block; the node serves leaves block by block. */
export const LEAF_BLOCK_SIZE = 1024;
const NODE_BYTES = 32;
const TREE_DEPTH = 32;
// A node that keeps disagreeing with what the client verified is refused rather than followed.
const MAX_REWINDS_PER_SYNC = 8;
// After a node had no seat to give, reads carry their key inline this long before a seat is asked
// for again, so a key is not uploaded twice per read while the seats stay full.
const SEAT_RETRY_MS = MAX_RETRY_AFTER_SECONDS * 1000;
/**
 * The step a sync resumes the feed and the newest block at. A sync reads a short tail of both
 * again, at most 2,394 bytes more when nothing is new. It divides the block and the feed segment.
 */
export const SYNC_CURSOR_GRANULE = 64;
const granular = (n: number): number => n - (n % SYNC_CURSOR_GRANULE);

/**
 * How private reads carry the packing key.
 * - `session`: uploaded once per session, then batches go by handle (the smallest bytes per
 *   sync). An expired session is replaced by a new one under a new secret. When the node has no
 *   seat free, the read carries its key inline instead, and a seat is asked for again later.
 * - `inline`: every request carries a key built for it alone, under a fresh secret; the node
 *   keeps nothing between requests.
 */
export type KeyMode = "session" | "inline";

/** What the client verified and holds, for a wallet to store and resume from. */
export interface SyncSnapshot {
  /**
   * Feed rows `[0, rows.length / 6)`. Fewer rows than `leafCount` when a sync stopped between
   * feed segments; the next sync reads on from the last row held.
   */
  readonly rows: Uint8Array;
  /** Level-10 nodes of the full blocks, 32 bytes each. */
  readonly upper: Uint8Array;
  /** The block holding leaf `leafCount - 1`, and its leaves up to `leafCount`. */
  readonly newestIndex: number;
  readonly newestLeaves: Uint8Array;
  /** The tree state the rows, nodes and leaves were verified at. */
  readonly leafCount: number;
  readonly block: number;
  readonly root: Uint8Array;
}

export interface RavenHowlSourceOptions<F> {
  readonly transport: HowlTransport;
  readonly wasm: HowlWasm;
  readonly field: FieldCodec<F>;
  /** Default `session`. */
  readonly keyMode?: KeyMode;
  /** Resume from a stored snapshot. */
  readonly snapshot?: SyncSnapshot;
}

/** One read of the public feed, in the shape of the discovery contract's `fetchTagPrefixes`. */
export interface TagPrefixSegment {
  /** leafIndex of the first row; the `since` asked for. */
  readonly base: number;
  /** leafIndex after the last row: the next `since`. */
  readonly next: number;
  /** `(next - base) * 6` bytes, in leaf order. Row 0 is the genesis filler. */
  readonly prefixes: Uint8Array;
  /** On the newest segment: the feed length and the chain block it reflects. */
  readonly end?: { readonly total: number; readonly block: number };
}

export interface SyncResult extends AnswerState {
  /** The pool's root at `leafCount`, checked against the client's own tree. */
  readonly root: Uint8Array;
  /** Feed rows downloaded by this sync. */
  readonly rowsAdded: number;
  /**
   * Set when the chain was reorganised below the client's old cursor: every row from this
   * position on was dropped and read again, so notes found there must be found again. The cells
   * read before are kept when every feed row and tree leaf held came back unchanged; otherwise
   * the next private read reads all of them again.
   */
  readonly rewoundTo?: number;
}

/** A note's path at a chosen leaf count, verified against the client's own tree. */
export interface MerkleWitness<F> {
  readonly leafIndex: number;
  readonly leafCount: number;
  /**
   * The chain block of the newest state the client verified, which is not the block at which
   * the pool reached `leafCount` when the witness is built at an older count.
   */
  readonly block: number;
  /** Level 0 up; a zero sibling means the node is carried up unhashed. */
  readonly siblings: readonly F[];
  /** The pool's root at `leafCount`; confirm it with the pool's `isKnownRoot`. */
  readonly root: F;
  readonly leaf: F;
}

/** Howl's round-1 answer shape, served from the feed and one private read. */
export interface FirstOccurrence<F> {
  readonly tag: F;
  /**
   * The record at the first matching position. On a miss, a well-formed record that opens to
   * nothing (`occurrenceCount` 0).
   */
  readonly record: HowlNoteRecord<F>;
  readonly occurrenceCount: number;
  /** Every position whose feed row matches the tag, in order. */
  readonly positions: readonly number[];
  /**
   * The record at each of `positions`. A feed row is six bytes, so another note's row can match
   * a tag and sort before the tag's own: a tag is in use when any of these opens, not only
   * `record`.
   */
  readonly records: readonly HowlNoteRecord<F>[];
}

/**
 * What `confirmNote` could check without a request: `"confirmed"` when the note is the verified
 * tree's leaf, `"unconfirmed"` when the client does not hold that leaf's block yet or the leaf is
 * at or past the verified count.
 */
export type NoteCheck = "confirmed" | "unconfirmed";

/** Howl's round-2 request shape; `occurrence` is 1-based beyond the first. */
export interface OccurrenceRequest<F> {
  readonly tag: F;
  readonly occurrence: number;
}

function hex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// Answer header: version and set [0, 4), route and zeros [4, 8), then leaf count, block and
// root [8, 56), which move with the chain.
const HEADER_BYTES = 56;
const HEADER_STATE_START = 8;

/**
 * Whether two params answers name the same serving material: the same bytes apart from the
 * header's chain state. A node restarted under another set, or re-seeded with new key
 * material, answers other bytes here.
 */
function sameServing(a: Uint8Array, b: Uint8Array): boolean {
  return (
    a.length === b.length &&
    a.length >= HEADER_BYTES &&
    equal(a.subarray(0, HEADER_STATE_START), b.subarray(0, HEADER_STATE_START)) &&
    equal(a.subarray(HEADER_BYTES), b.subarray(HEADER_BYTES))
  );
}

function nodeAt(list: Uint8Array, index: number): Uint8Array {
  return list.subarray(index * NODE_BYTES, (index + 1) * NODE_BYTES);
}

/**
 * The tree and feed held when a rewind first set the cells aside, and the cells set aside.
 * `readTo` is the count of the one full read made since the last rewind, `null` before it.
 */
interface Suspect {
  readonly rows: Uint8Array;
  readonly upper: Uint8Array;
  readonly newestIndex: number;
  readonly newestLeaves: Uint8Array;
  readonly leafCount: number;
  readonly cells: Map<number, Uint8Array>;
  readTo: number | null;
}

function checkPosition(value: number, what: string): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new RangeError(`${what} ${value} is not a leaf index`);
  }
}

/**
 * Howl discovery over a Raven node.
 *
 * The wallet scans the public tag-prefix feed on the device and reads only the cells of the
 * positions that match, in padded private batches. Every answer names the leaf count and
 * chain block it was read at; the client checks each sync against the tree it already
 * verified, so a reorganisation below its cursor is found and read again.
 */
export class RavenHowlSource<F> {
  readonly #transport: HowlTransport;
  readonly #wasm: HowlWasm;
  readonly #field: FieldCodec<F>;
  readonly #keyMode: KeyMode;
  readonly #feed: PrefixFeed;
  readonly #feedView: FeedView;
  readonly #tree: HowlTreeHandle;
  #state: { leafCount: number; block: number; root: Uint8Array };
  #params: Uint8Array | null = null;
  #session: HowlClientHandle | null = null;
  #noSeatUntil = 0;
  readonly #occurrences = new Map<string, number[]>();
  // Cells already opened, by position: a cell never changes unless its feed row or leaf does.
  readonly #cells = new Map<number, Uint8Array>();
  // Every cell, set aside by a rewind with the tree and feed it was verified under, until a sync
  // reaches the old count and shows whether all of those rows and leaves came back unchanged.
  #suspect: Suspect | null = null;
  // Cells the next private read covers again, all of them, so the read is the same wherever the
  // chain changed.
  readonly #reread = new Set<number>();
  // Pads and slot order of reads not yet answered, so a read sent again asks for the same rows.
  readonly #plans = new Map<string, { targets: Uint32Array; slots: Uint32Array }>();
  #lastRead: AnswerState | null = null;
  // One call at a time: a sync appends to the feed and the tree, and a read may replace the
  // session, so calls made together run in order.
  #queue: Promise<unknown> = Promise.resolve();

  constructor(options: RavenHowlSourceOptions<F>) {
    this.#transport = options.transport;
    this.#wasm = options.wasm;
    this.#field = options.field;
    this.#keyMode = options.keyMode ?? "session";
    const s = options.snapshot;
    this.#feed = new PrefixFeed(s?.rows);
    const feed = this.#feed;
    this.#feedView = Object.freeze({
      get length() {
        return feed.length;
      },
      bytes: () => feed.bytes(),
      matches: (tags: readonly Uint8Array[], from?: number) => feed.matches(tags, from),
    });
    this.#tree = new this.#wasm.HowlTree();
    this.#state = { leafCount: 0, block: 0, root: new Uint8Array(32) };
    if (s !== undefined) {
      if (this.#feed.length > s.leafCount) {
        throw new RangeError(`snapshot holds ${this.#feed.length} rows for ${s.leafCount} leaves`);
      }
      protocol("snapshot", () => {
        this.#tree.appendUpper(s.upper);
        this.#tree.setNewest(s.newestIndex, s.newestLeaves);
      });
      const root = protocol("snapshot", () => this.#tree.root(s.leafCount));
      if (!equal(root, s.root)) throw new RangeError("snapshot leaves do not hash to its root");
      this.#state = { leafCount: s.leafCount, block: s.block, root: s.root.slice() };
    }
  }

  /** The verified tree: leaf count, chain block and root. The feed may end before it until a sync completes. */
  get state(): AnswerState & { readonly root: Uint8Array } {
    return { ...this.#state, root: this.#state.root.slice() };
  }

  /** The state the last private read was answered at. */
  get lastRead(): AnswerState | null {
    return this.#lastRead;
  }

  /**
   * The feed rows held, as verified by the last sync: for a wallet's own occupancy or
   * preflight checks, which need no request. Read-only; `sync` moves it.
   */
  get feed(): FeedView {
    return this.#feedView;
  }

  snapshot(): SyncSnapshot {
    return {
      rows: this.#feed.bytes(),
      upper: this.#tree.upperNodes(),
      newestIndex: this.#tree.newestIndex,
      newestLeaves: this.#tree.newestLeaves(),
      leafCount: this.#state.leafCount,
      block: this.#state.block,
      root: this.#state.root.slice(),
    };
  }

  #exclusive<T>(call: () => Promise<T>): Promise<T> {
    const run = this.#queue.then(call, call);
    this.#queue = run.catch(() => undefined);
    return run;
  }

  /** Release the wasm-held session. The source stays usable and opens a new one on demand. */
  close(): void {
    this.#session?.free();
    this.#session = null;
  }

  async #get(path: string): Promise<Exchange> {
    return this.#transport.get(path);
  }

  #answer(ex: Exchange, kind: number, what: string): Answer {
    if (ex.status === 409) {
      const stale = protocol(what, () => decode(this.#wasm, ex.body));
      throw new HowlError("Stale", `${what}: the node holds ${stale.leafCount} leaves`, {
        status: 409,
        state: { leafCount: stale.leafCount, block: stale.block },
      });
    }
    if (ex.status === 410) {
      throw new HowlError("SessionExpired", `${what}: session expired`, { status: 410 });
    }
    if (ex.status === 503 || ex.status === 429) {
      const retryAfter = retryAfterSeconds(ex.headers?.get("retry-after") ?? null);
      throw new HowlError("Busy", `${what}: ${ex.status} ${new TextDecoder().decode(ex.body)}`, {
        status: ex.status,
        ...(retryAfter === undefined ? {} : { retryAfter }),
      });
    }
    if (ex.status !== 200) {
      throw new HowlError("Refused", `${what}: ${ex.status} ${new TextDecoder().decode(ex.body)}`, {
        status: ex.status,
      });
    }
    const answer = protocol(what, () => decode(this.#wasm, ex.body));
    if (answer.kind !== kind) {
      throw new HowlError("Protocol", `${what}: answer of route ${answer.kind}`);
    }
    return answer;
  }

  /** Full block `b` from the node, held after it hashes to the verified upper node. */
  async #fullBlock(b: number): Promise<Uint8Array> {
    if (b >= this.#tree.fullBlocks) throw new RangeError(`block ${b} is not full in the verified tree`);
    const answer = this.#answer(await this.#get(`/howl/v1/block/${b}`), KIND.block, `block ${b}`);
    if (answer.blockIndex !== b) throw new HowlError("Protocol", `block ${b}: answered block ${answer.blockIndex}`);
    protocol("block", () => this.#tree.addBlock(b, answer.blockLeaves));
    return answer.blockLeaves;
  }

  async #hold(b: number): Promise<void> {
    if (!this.#tree.holdsBlock(b)) await this.#fullBlock(b);
  }

  /**
   * The first leaf count at which the node's tree may differ from the held one: the start of
   * the first full block whose upper node differs, or of the first block not held.
   */
  async #divergence(): Promise<number> {
    const fresh = this.#answer(await this.#get("/howl/v1/upper?since=0"), KIND.upper, "upper");
    const held = this.#tree.upperNodes();
    const shared = Math.min(held.length, fresh.upperNodes.length) / NODE_BYTES;
    for (let d = 0; d < shared; d++) {
      if (!equal(nodeAt(held, d), nodeAt(fresh.upperNodes, d))) return d * LEAF_BLOCK_SIZE;
    }
    return shared * LEAF_BLOCK_SIZE;
  }

  /**
   * `held` names the verified newest block and upper-node count when an answer not yet accepted
   * has been applied to the tree; the cells set aside are compared against those.
   */
  #rewindTo(r: number, held: { upper: number; index: number; leaves: Uint8Array } | null): number {
    // Back to a block boundary: the root there follows from the upper nodes alone.
    const limit = Math.max(0, Math.min(r, this.#feed.length, this.#state.leafCount));
    const at = Math.floor(limit / LEAF_BLOCK_SIZE) * LEAF_BLOCK_SIZE;
    this.#suspect ??= {
      rows: this.#feed.bytes(),
      upper: this.#tree.upperNodes().slice(0, (held?.upper ?? this.#tree.fullBlocks) * NODE_BYTES),
      newestIndex: held?.index ?? this.#tree.newestIndex,
      newestLeaves: held?.leaves ?? this.#tree.newestLeaves(),
      leafCount: this.#state.leafCount,
      cells: new Map(),
      readTo: null,
    };
    this.#suspect!.readTo = null;
    this.#feed.truncate(at);
    this.#tree.truncate(at);
    this.#state = { leafCount: at, block: this.#state.block, root: this.#tree.root(at) };
    this.#occurrences.clear();
    for (const [p, cell] of this.#cells) if (!this.#suspect!.cells.has(p)) this.#suspect!.cells.set(p, cell);
    this.#cells.clear();
    this.#plans.clear();
    return at;
  }

  /**
   * Once a sync reaches the count the cells were set aside at, restore them all when every row
   * and leaf held then came back unchanged, or mark them all to be read again. The old newest
   * block, when it has filled since, is read as a sync without a rewind reads it.
   */
  async #settle(): Promise<void> {
    const s = this.#suspect;
    if (s === null || this.#state.leafCount < s.leafCount) return;
    const filled = s.leafCount % LEAF_BLOCK_SIZE !== 0 && s.newestIndex < this.#tree.fullBlocks;
    if (filled && !this.#tree.holdsBlock(s.newestIndex)) await this.#fullBlock(s.newestIndex);
    if (this.#unchanged(s)) {
      for (const [p, cell] of s.cells) if (!this.#cells.has(p)) this.#cells.set(p, cell);
    } else {
      for (const p of s.cells.keys()) this.#reread.add(p);
      for (const p of this.#cells.keys()) this.#reread.add(p);
      this.#cells.clear();
    }
    this.#suspect = null;
  }

  /** Whether the tree and feed now hold every row and leaf `s` held. */
  #unchanged(s: Suspect): boolean {
    if (this.#feed.length * TAG_PREFIX_BYTES < s.rows.length || this.#feed.firstDifference(0, s.rows) !== null) {
      return false;
    }
    const oldFull = s.upper.length / NODE_BYTES;
    if (oldFull > this.#tree.fullBlocks) return false;
    const upper = this.#tree.upperNodes();
    for (let b = 0; b < oldFull; b++) if (!equal(nodeAt(upper, b), nodeAt(s.upper, b))) return false;
    const start = s.newestIndex * LEAF_BLOCK_SIZE;
    if (s.leafCount <= start || s.leafCount % LEAF_BLOCK_SIZE === 0) return true;
    for (let p = start; p < s.leafCount; p++) {
      const was = nodeAt(s.newestLeaves, p - start);
      let now: Uint8Array;
      try {
        now = this.#tree.leaf(p);
      } catch {
        return false;
      }
      if (was.length !== NODE_BYTES || !equal(now, was)) return false;
    }
    return true;
  }

  /** The leaf count up to which the held newest block runs: its leaves need not be sent again. */
  #heldTo(): number {
    const to = this.#tree.newestIndex * LEAF_BLOCK_SIZE + this.#tree.newestLeaves().length / NODE_BYTES;
    return to === this.#state.leafCount ? to : 0;
  }

  /**
   * The newest block's leaves from an answer that carries them from the leaf it names: the
   * leaves before that are the ones held. `null` when the block is full and wholly held, so
   * the upper nodes alone fix the root.
   */
  #newestFrom(a: Answer, held: number, before: { index: number; leaves: Uint8Array }): Uint8Array | null {
    const start = a.blockIndex * LEAF_BLOCK_SIZE;
    const begin = a.leafCount - a.blockLeaves.length / NODE_BYTES;
    if (begin === start) return a.blockLeaves;
    if (begin !== held || begin < start || begin > start + LEAF_BLOCK_SIZE) {
      throw new HowlError("Protocol", `sync sent block ${a.blockIndex} from leaf ${begin}, ${held} held`);
    }
    const own = (begin - start) * NODE_BYTES;
    if (before.index === a.blockIndex && before.leaves.length >= own) {
      const leaves = new Uint8Array(own + a.blockLeaves.length);
      leaves.set(before.leaves.subarray(0, own));
      leaves.set(a.blockLeaves, own);
      return leaves;
    }
    if (begin === start + LEAF_BLOCK_SIZE && a.blockLeaves.length === 0) return null;
    throw new HowlError("Protocol", `sync skipped leaves of block ${a.blockIndex} the client does not hold`);
  }

  /** Whether the held leaves `[b * 1024, v)` of the old newest block are a prefix of `leaves`. */
  #keeps(held: Uint8Array, v: number, leaves: Uint8Array): boolean {
    const need = (v - Math.floor((v - 1) / LEAF_BLOCK_SIZE) * LEAF_BLOCK_SIZE) * NODE_BYTES;
    return leaves.length >= need && equal(held.subarray(0, need), leaves.subarray(0, need));
  }

  /**
   * Bring the feed, the upper nodes and the newest block up to the node's newest state,
   * downloading only rows past those held. Each answer must hash to its own root from the
   * held tree plus what it carries, and must keep the leaves the client verified before.
   */
  sync(): Promise<SyncResult> {
    return this.#exclusive(() => this.#sync());
  }

  async #sync(): Promise<SyncResult> {
    const startRows = this.#feed.length;
    let rewoundTo: number | undefined;
    let rewinds = 0;
    // The verified tree while an answer not yet accepted is applied to it.
    let applied: { upper: number; index: number; leaves: Uint8Array } | null = null;
    const rewind = (r: number): void => {
      if (++rewinds > MAX_REWINDS_PER_SYNC) {
        throw new HowlError("Protocol", "the node keeps disagreeing with the verified tree");
      }
      const at = this.#rewindTo(r, applied);
      applied = null;
      rewoundTo = Math.min(rewoundTo ?? at, at);
    };
    // The node is behind the cursor: a lagging replica, or a chain that got shorter. Only a root
    // that differs from the held tree's at the node's count proves the latter.
    const behindCursor = async (node: { leafCount: number; block: number; root: Uint8Array }, status?: number) => {
      // A node at or past the verified block with fewer leaves follows a chain that dropped
      // them, even when the leaves it kept are the held ones.
      let ours: Uint8Array | null = null;
      try {
        ours = this.#tree.root(node.leafCount);
      } catch {
        ours = null;
      }
      if (node.block < this.#state.block && (ours === null || equal(ours, node.root))) {
        throw new HowlError(
          "Stale",
          `the node holds ${node.leafCount} leaves, behind the ${this.#state.leafCount} held`,
          { ...(status === undefined ? {} : { status }), state: { leafCount: node.leafCount, block: node.block } },
        );
      }
      rewind(Math.min(await this.#divergence(), node.leafCount));
    };
    for (;;) {
      const since = granular(this.#feed.length);
      const upperSince = this.#tree.fullBlocks;
      const held = granular(this.#heldTo());
      const ex = await this.#get(
        `/howl/v1/sync?since=${since}&upper=${upperSince}` + (held > 0 ? `&held=${held}` : ""),
      );
      if (ex.status === 409) {
        await behindCursor(protocol("sync", () => decode(this.#wasm, ex.body)), 409);
        continue;
      }
      const a = this.#answer(ex, KIND.sync, "sync");
      if (a.base !== since || a.upperBase !== upperSince) {
        throw new HowlError("Protocol", `sync answered from ${a.base}/${a.upperBase}, asked ${since}/${upperSince}`);
      }
      const n = a.leafCount;
      const v = this.#state.leafCount;
      if (n < v) {
        // A node behind the held count may answer from the resume point instead of refusing.
        await behindCursor(a);
        continue;
      }
      const before = { index: this.#tree.newestIndex, leaves: this.#tree.newestLeaves() };
      if (upperSince + a.upperNodes.length / NODE_BYTES !== Math.floor(n / LEAF_BLOCK_SIZE)) {
        throw new HowlError("Protocol", `sync carries ${a.upperNodes.length / NODE_BYTES} upper nodes for ${n} leaves`);
      }
      const newest = this.#newestFrom(a, held, before);
      applied = { upper: upperSince, index: before.index, leaves: before.leaves };
      protocol("sync", () => {
        this.#tree.appendUpper(a.upperNodes);
        if (newest !== null) this.#tree.setNewest(a.blockIndex, newest);
      });
      if (!equal(protocol("sync", () => this.#tree.root(n)), a.root)) {
        // The nodes held below the cursor are not the node's: the chain changed under them.
        rewind(await this.#divergence());
        continue;
      }
      if (v > 0 && v % LEAF_BLOCK_SIZE !== 0) {
        // The leaves of the old newest block up to the old count must still be there.
        const b = Math.floor((v - 1) / LEAF_BLOCK_SIZE);
        let kept = false;
        if (b === before.index) {
          kept =
            b === a.blockIndex
              ? newest !== null && this.#keeps(before.leaves, v, newest)
              : this.#keeps(before.leaves, v, await this.#fullBlock(b));
        }
        if (!kept) {
          rewind(b * LEAF_BLOCK_SIZE);
          continue;
        }
      }
      // Rows below the cursor come again; a node that now serves other rows there moved them.
      const moved = this.#feed.firstDifference(a.base, a.rows);
      if (moved !== null) {
        rewind(moved);
        continue;
      }
      const resent = Math.min(this.#feed.length, a.next) - a.base;
      this.#feed.append(this.#feed.length, a.rows.subarray(resent * TAG_PREFIX_BYTES));
      this.#state = { leafCount: n, block: a.block, root: a.root };
      applied = null;
      if (a.next === n) {
        await this.#settle();
        const result: SyncResult = {
          leafCount: n,
          block: a.block,
          root: a.root.slice(),
          rowsAdded: this.#feed.length - Math.min(startRows, rewoundTo ?? startRows),
        };
        return rewoundTo === undefined ? result : { ...result, rewoundTo };
      }
    }
  }

  /** The public feed from `since`, as served: no state of the client changes. */
  async fetchTagPrefixes(since: number): Promise<TagPrefixSegment> {
    checkPosition(since, "since");
    const a = this.#answer(await this.#get(`/howl/v1/prefixes?since=${since}`), KIND.prefixes, "prefixes");
    if (a.base !== since) throw new HowlError("Protocol", `feed answered from ${a.base}, asked ${since}`);
    const segment = { base: a.base, next: a.next, prefixes: a.rows };
    return a.next === a.leafCount ? { ...segment, end: { total: a.leafCount, block: a.block } } : segment;
  }

  /** Positions in the held feed whose row matches one of `tags`. */
  matches(tags: readonly F[], from = 1): FeedMatch[] {
    return this.#feed.matches(
      tags.map((t) => this.#field.toBytes(t)),
      from,
    );
  }

  async #paramsAnswer(): Promise<Uint8Array> {
    if (this.#params === null) {
      const ex = await this.#get("/howl/v1/params");
      this.#answer(ex, KIND.params, "params");
      this.#params = ex.body;
    }
    return this.#params;
  }

  async #newClient(): Promise<HowlClientHandle> {
    const params = await this.#paramsAnswer();
    return protocol("client", () => new this.#wasm.HowlClient(params));
  }

  async #sessionClient(): Promise<HowlClientHandle> {
    if (this.#session !== null) return this.#session;
    const client = await this.#newClient();
    try {
      const ex = await this.#transport.post("/howl/v1/session", client.sessionBody());
      this.#answer(ex, KIND.session, "session");
      protocol("session", () => client.installSession(ex.body));
    } catch (e) {
      client.free();
      throw e;
    }
    this.#session = client;
    return client;
  }

  /** The seated client, or `null` when the node has no seat to give now. */
  async #seated(): Promise<HowlClientHandle | null> {
    if (this.#session === null && Date.now() < this.#noSeatUntil) return null;
    try {
      return await this.#sessionClient();
    } catch (e) {
      if (!(e instanceof HowlError) || e.kind !== "Busy") throw e;
      this.#noSeatUntil = Date.now() + SEAT_RETRY_MS;
      return null;
    }
  }

  /**
   * After a private read the node refused, or whose answer did not open, whether the node now
   * serves other material than the params held: another set, or the same set re-seeded with
   * new key material. When it does, the params and session are dropped for the node's.
   */
  async #nodeChanged(error: unknown): Promise<boolean> {
    if (!(error instanceof HowlError) || (error.kind !== "Refused" && error.kind !== "Protocol")) return false;
    if (this.#params === null) return false;
    let ex: Exchange;
    try {
      ex = await this.#get("/howl/v1/params");
      this.#answer(ex, KIND.params, "params");
    } catch {
      // Unread params tell nothing about the node; the refusal stands.
      return false;
    }
    if (sameServing(ex.body, this.#params)) return false;
    this.close();
    this.#params = ex.body;
    return true;
  }

  /**
   * Private read of `positions`. An expired session is replaced once; a read that fails
   * because the node changed is built again once under the node's params, with the same rows
   * and slots as the first request.
   */
  async #readBatch(positions: number[]): Promise<Uint8Array> {
    const key = positions.join(",");
    let renewed = false;
    let reread = false;
    for (;;) {
      const inline = this.#keyMode === "inline";
      try {
        return await this.#readOnce(key, positions, inline);
      } catch (e) {
        if (!inline && !renewed && e instanceof HowlError && e.kind === "SessionExpired") {
          renewed = true;
          this.close();
          continue;
        }
        if (!reread && (await this.#nodeChanged(e))) {
          reread = true;
          continue;
        }
        if (!reread || !(e instanceof HowlError)) throw e;
        throw new HowlError(e.kind, `${e.message} (after reading the node's params again)`, {
          ...(e.status === undefined ? {} : { status: e.status }),
          ...(e.state === undefined ? {} : { state: e.state }),
          ...(e.retryAfter === undefined ? {} : { retryAfter: e.retryAfter }),
          cause: e,
        });
      }
    }
  }

  /**
   * A read that got no response at all, as on a keep-alive socket the node closed when it
   * restarted, is sent once more with the same bytes: the same key and rows. A read is free of
   * side effects apart from renewing its seat. A read that got any status is never sent again
   * here.
   */
  async #postNotes(body: Uint8Array): Promise<Exchange> {
    try {
      return await this.#transport.post("/howl/v1/notes", body);
    } catch (e) {
      if (!neverAnswered(e)) throw e;
      return this.#transport.post("/howl/v1/notes", body);
    }
  }

  async #readOnce(key: string, positions: number[], inline: boolean): Promise<Uint8Array> {
    // A read the node has no seat for goes inline under a key of its own.
    const seated = inline ? null : await this.#seated();
    const client = seated ?? (await this.#newClient());
    try {
      const plan = this.#plans.get(key);
      const batch = protocol("batch", () =>
        plan === undefined
          ? client.buildBatch(Uint32Array.from(positions), this.#state.leafCount)
          : client.buildBatchAt(plan.targets, plan.slots, this.#state.leafCount),
      );
      if (plan === undefined) this.#plans.set(key, { targets: batch.targets, slots: batch.realSlots });
      try {
        const ex = await this.#postNotes(batch.body);
        this.#answer(ex, KIND.notes, "notes");
        const cells = protocol("notes", () => client.openNotes(batch, ex.body));
        try {
          const out = cells.cells;
          // A key built under material the node no longer holds opens to cells that fail here.
          positions.forEach((p, k) => decodeCell(out.subarray(k * 256, (k + 1) * 256), p, this.#field));
          this.#lastRead = { leafCount: cells.leafCount, block: cells.block };
          this.#plans.delete(key);
          return out;
        } finally {
          cells.free();
        }
      } finally {
        batch.free();
      }
    } finally {
      if (seated === null) client.free();
    }
  }

  /**
   * Private read of the cells at `leafIndices` (1 and up; 0 is the genesis filler and is
   * refused), one record per index in request order, in batches of at most the node's ladder
   * cap. A cell read once is kept. A source that holds no leaves yet syncs once first. A position
   * at or past `state.leafCount` takes a slot like any other and answers a record that opens to
   * nothing at that index (`commitmentPrefix` all zero): sync, then ask for it again.
   *
   * After a rewind finds any feed row or tree leaf changed, the next read covers every cell read
   * before as well. While a shorter chain holds the cells aside, the next read syncs first and
   * covers them all, each one past the count in a slot of its own. After that read, a cell held
   * aside past its count answers a record that opens to nothing, as above, until a sync reaches
   * the count the cells were set aside at. One rewind costs at most two full re-reads, and one
   * sync before the first.
   */
  fetchNotes(leafIndices: readonly number[]): Promise<HowlNoteRecord<F>[]> {
    return this.#exclusive(() => this.#fetchNotes(leafIndices));
  }

  async #fetchNotes(leafIndices: readonly number[]): Promise<HowlNoteRecord<F>[]> {
    if (leafIndices.length === 0) return [];
    leafIndices.forEach((p) => {
      checkPosition(p, "leaf index");
      if (p === 0) throw new RangeError("leaf 0 is the genesis filler and holds no note");
    });
    // Whether to sync, and the slots, follow the cells held, never where the asked positions sit
    // against the count.
    if (this.#state.leafCount === 0 || this.#suspect?.readTo === null) await this.#sync();
    const n = this.#state.leafCount;
    const s = this.#suspect;
    const covering = s !== null && s.readTo === null;
    // A cell held aside after its full read keeps no slot, as a cell held keeps none.
    const held = (p: number): boolean => this.#cells.has(p) || (s !== null && !covering && s.cells.has(p));
    const wanted = new Set(leafIndices.filter((p) => !held(p)));
    const again = new Set(s === null ? this.#reread : covering ? [...this.#reread, ...s.cells.keys()] : []);
    const reads = [...new Set([...wanted, ...again])].filter((p) => p < n).sort((a, b) => a - b);
    // A position past the count still takes a slot, so the read keeps its size.
    const size = new Set([...wanted, ...again]).size;
    const taken = new Set(reads);
    const fill: number[] = [];
    for (let p = 1; reads.length + fill.length < size && p < n; p++) if (!taken.has(p)) fill.push(p);
    const all = [...reads, ...fill];
    if (all.length > 0) {
      const cap = decode(this.#wasm, await this.#paramsAnswer()).ladderCap;
      for (let i = 0; i < all.length; i += cap) {
        const chunk = all.slice(i, i + cap);
        const cells = await this.#readBatch(chunk);
        chunk.forEach((p, k) => {
          if (taken.has(p)) this.#cells.set(p, cells.slice(k * 256, (k + 1) * 256));
        });
      }
    }
    if (covering) s.readTo = n;
    if (this.#suspect === null) this.#reread.clear();
    return leafIndices.map((p) => {
      const cell = this.#cells.get(p);
      return cell === undefined ? missRecord(this.#field, p) : decodeCell(cell, p, this.#field);
    });
  }

  /**
   * Check a note the wallet opened from `record` against the verified tree: `commitment`, the
   * commitment the wallet recomputed from the plaintext, must start with the record's prefix
   * and be the tree's leaf at `record.leafIndex`. A cell that opens but whose note is not that
   * leaf is refused with a `Protocol` error, so it is never spent or counted.
   *
   * It sends no request: it reads only the blocks the client already holds. When the client
   * does not hold the note's block, or `record.leafIndex` is at or past `state.leafCount`, it
   * answers `"unconfirmed"`, and the check falls to a later sync or to spend time: the `leaf` of
   * `merkleWitness`, which reads the block anyway, must equal `commitment` (or call this again
   * after the witness).
   */
  confirmNote(record: HowlNoteRecord<F>, commitment: F): Promise<NoteCheck> {
    return this.#exclusive(() => this.#confirmNote(record, commitment));
  }

  async #confirmNote(record: HowlNoteRecord<F>, commitment: F): Promise<NoteCheck> {
    const p = record.leafIndex;
    checkPosition(p, "leaf index");
    if (p === 0) throw new RangeError("leaf 0 is the genesis filler and holds no note");
    const c = this.#field.toBytes(commitment);
    if (!equal(record.commitmentPrefix, c.subarray(0, COMMITMENT_PREFIX_BYTES))) {
      throw new HowlError("Protocol", `leaf ${p}: the commitment does not start with the record's prefix`);
    }
    // no sync here: a request would then depend on where p sits against the count
    if (p >= this.#state.leafCount || !this.#tree.holdsBlock(Math.floor(p / LEAF_BLOCK_SIZE))) {
      return "unconfirmed";
    }
    const leaf = protocol("leaf", () => this.#tree.leaf(p));
    if (!equal(leaf, c)) throw new HowlError("Protocol", `leaf ${p}: the verified tree holds another commitment`);
    return "confirmed";
  }

  /** The leaves of block `blockIndex` in the verified tree: a full block, or the newest. */
  fetchLeafBlock(blockIndex: number): Promise<F[]> {
    return this.#exclusive(() => this.#fetchLeafBlock(blockIndex));
  }

  async #fetchLeafBlock(blockIndex: number): Promise<F[]> {
    checkPosition(blockIndex, "block index");
    let leaves: Uint8Array;
    if (blockIndex === this.#tree.newestIndex) leaves = this.#tree.newestLeaves();
    else if (blockIndex < this.#tree.fullBlocks) leaves = await this.#fullBlock(blockIndex);
    else leaves = new Uint8Array(0);
    const out: F[] = [];
    for (let i = 0; i < leaves.length; i += NODE_BYTES) {
      out.push(this.#field.fromBytes(leaves.slice(i, i + NODE_BYTES)));
    }
    return out;
  }

  /**
   * The path of `leafIndex` in the tree of the first `leafCount` leaves (default: the newest
   * verified count), built from the verified tree and checked by folding it. Its `block` is
   * that of the newest verified state, whatever `leafCount` is asked for.
   */
  merkleWitness(leafIndex: number, leafCount?: number): Promise<MerkleWitness<F>> {
    return this.#exclusive(() => this.#merkleWitness(leafIndex, leafCount));
  }

  async #merkleWitness(leafIndex: number, leafCount?: number): Promise<MerkleWitness<F>> {
    checkPosition(leafIndex, "leaf index");
    if (this.#state.leafCount === 0 || (leafCount ?? 0) > this.#state.leafCount) await this.#sync();
    const n = leafCount ?? this.#state.leafCount;
    checkPosition(n, "leaf count");
    if (leafIndex >= n || n > this.#state.leafCount) {
      throw new RangeError(`leaf ${leafIndex} at count ${n}: the verified tree holds ${this.#state.leafCount}`);
    }
    const own = Math.floor(leafIndex / LEAF_BLOCK_SIZE);
    await this.#hold(own);
    if (n % LEAF_BLOCK_SIZE !== 0) await this.#hold(Math.floor((n - 1) / LEAF_BLOCK_SIZE));
    // a full block evicted while the other was fetched is fetched again
    await this.#hold(own);
    const path = protocol("path", () => this.#tree.path(leafIndex, n));
    const siblings = path.subarray(0, TREE_DEPTH * NODE_BYTES);
    const root = path.slice(TREE_DEPTH * NODE_BYTES);
    const leaf = protocol("leaf", () => this.#tree.leaf(leafIndex));
    const folded = protocol("fold", () => this.#wasm.foldPath(leaf, leafIndex, siblings));
    if (!equal(folded, root) || (n === this.#state.leafCount && !equal(root, this.#state.root))) {
      throw new HowlError("Protocol", `path of leaf ${leafIndex} does not fold to the root at ${n}`);
    }
    const list: F[] = [];
    for (let i = 0; i < TREE_DEPTH; i++) {
      list.push(this.#field.fromBytes(siblings.slice(i * NODE_BYTES, (i + 1) * NODE_BYTES)));
    }
    return {
      leafIndex,
      leafCount: n,
      block: this.#state.block,
      siblings: list,
      root: this.#field.fromBytes(root),
      leaf: this.#field.fromBytes(leaf),
    };
  }

  /**
   * Howl's round 1, answered from the feed: pull the feed delta, match every tag locally and
   * read every matching position in one private read (padded batches). Each answer carries the
   * first record and all of them; `fetchOccurrences` then serves the rest without a request. A
   * tag with no match gets a record that opens to nothing, as Howl's self-mint preflight
   * requires.
   */
  probeFirst(tags: readonly F[]): Promise<FirstOccurrence<F>[]> {
    return this.#exclusive(() => this.#probeFirst(tags));
  }

  async #probeFirst(tags: readonly F[]): Promise<FirstOccurrence<F>[]> {
    await this.#sync();
    const keys = tags.map((t) => hex(this.#field.toBytes(t)));
    const found = new Map<string, number[]>();
    for (const m of this.matches(tags)) {
      const k = keys[m.candidate]!;
      const list = found.get(k) ?? [];
      if (list[list.length - 1] !== m.position) list.push(m.position);
      found.set(k, list);
    }
    for (const [k, list] of found) this.#occurrences.set(k, list);
    const every = [...new Set([...found.values()].flat())];
    const records = new Map<number, HowlNoteRecord<F>>();
    (await this.#fetchNotes(every)).forEach((r, i) => records.set(every[i]!, r));
    return tags.map((tag, i) => {
      const list = found.get(keys[i]!) ?? [];
      const all = list.map((p) => records.get(p)!);
      return {
        tag,
        record: all[0] ?? missRecord(this.#field),
        occurrenceCount: list.length,
        positions: list,
        records: all,
      };
    });
  }

  /**
   * Howl's round 2: the remaining matches of tags seen by `probeFirst`. Their cells were read in
   * round 1, so this sends a request only after a rewind dropped them.
   */
  fetchOccurrences(requests: readonly OccurrenceRequest<F>[]): Promise<(HowlNoteRecord<F> | null)[]> {
    return this.#exclusive(() => this.#fetchOccurrences(requests));
  }

  async #fetchOccurrences(
    requests: readonly OccurrenceRequest<F>[],
  ): Promise<(HowlNoteRecord<F> | null)[]> {
    const positions = requests.map(
      (r) => this.#occurrences.get(hex(this.#field.toBytes(r.tag)))?.[r.occurrence],
    );
    const wanted = [...new Set(positions.filter((p): p is number => p !== undefined))];
    const records = new Map<number, HowlNoteRecord<F>>();
    (await this.#fetchNotes(wanted)).forEach((r, i) => records.set(wanted[i]!, r));
    return positions.map((p) => (p === undefined ? null : records.get(p)!));
  }
}
