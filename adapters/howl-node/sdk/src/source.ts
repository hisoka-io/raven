import { HowlError, protocol, type AnswerState } from "./errors.js";
import { PrefixFeed, type FeedMatch } from "./feed.js";
import type { Exchange, HowlTransport } from "./http.js";
import { decodeCell, missRecord, type FieldCodec, type HowlNoteRecord } from "./record.js";
import { decode, KIND, type Answer, type HowlClientHandle, type HowlTreeHandle, type HowlWasm } from "./wasm.js";

/** Leaves per tree block; the node serves leaves block by block. */
export const LEAF_BLOCK_SIZE = 1024;
const NODE_BYTES = 32;
const TREE_DEPTH = 32;
// A node that keeps disagreeing with what the client verified is refused rather than followed.
const MAX_REWINDS_PER_SYNC = 8;

/**
 * How private reads carry the packing key.
 * - `session`: uploaded once per session, then batches go by handle (the smallest bytes per
 *   sync). An expired session is replaced by a new one under a new secret.
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
   * position on was dropped and read again, so notes found there must be found again.
   */
  readonly rewoundTo?: number;
}

/** A note's path at a chosen leaf count, verified against the client's own tree. */
export interface MerkleWitness<F> {
  readonly leafIndex: number;
  readonly leafCount: number;
  /** The chain block of the newest state the client verified. */
  readonly block: number;
  /** Level 0 up; a zero sibling means the node is carried up unhashed. */
  readonly siblings: readonly F[];
  /** The pool's root at `leafCount`; confirm it with the pool's `isKnownRoot`. */
  readonly root: F;
  readonly leaf: F;
}

/** Howl's round-1 answer shape, served from the feed and one private batch. */
export interface FirstOccurrence<F> {
  readonly tag: F;
  /** On a miss, a well-formed record that opens to nothing (`occurrenceCount` 0). */
  readonly record: HowlNoteRecord<F>;
  readonly occurrenceCount: number;
}

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

function nodeAt(list: Uint8Array, index: number): Uint8Array {
  return list.subarray(index * NODE_BYTES, (index + 1) * NODE_BYTES);
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
  readonly #tree: HowlTreeHandle;
  #state: { leafCount: number; block: number; root: Uint8Array };
  #params: Uint8Array | null = null;
  #session: HowlClientHandle | null = null;
  readonly #occurrences = new Map<string, number[]>();
  // Cells already opened, by position: a cell never changes unless a rewind drops its row.
  readonly #cells = new Map<number, Uint8Array>();
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

  /** The feed rows held; scan them with `matches`. */
  get feed(): PrefixFeed {
    return this.#feed;
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
    if (ex.status === 503) {
      throw new HowlError("Busy", `${what}: ${new TextDecoder().decode(ex.body)}`, { status: 503 });
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

  #rewindTo(r: number): number {
    // Back to a block boundary: the root there follows from the upper nodes alone.
    const limit = Math.max(0, Math.min(r, this.#feed.length, this.#state.leafCount));
    const at = Math.floor(limit / LEAF_BLOCK_SIZE) * LEAF_BLOCK_SIZE;
    this.#feed.truncate(at);
    this.#tree.truncate(at);
    this.#state = { leafCount: at, block: this.#state.block, root: this.#tree.root(at) };
    this.#occurrences.clear();
    for (const p of this.#cells.keys()) if (p >= at) this.#cells.delete(p);
    this.#plans.clear();
    return at;
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
    const rewind = (r: number): void => {
      if (++rewinds > MAX_REWINDS_PER_SYNC) {
        throw new HowlError("Protocol", "the node keeps disagreeing with the verified tree");
      }
      const at = this.#rewindTo(r);
      rewoundTo = Math.min(rewoundTo ?? at, at);
    };
    for (;;) {
      const since = this.#feed.length;
      const upperSince = this.#tree.fullBlocks;
      const held = this.#heldTo();
      const ex = await this.#get(
        `/howl/v1/sync?since=${since}&upper=${upperSince}` + (held > 0 ? `&held=${held}` : ""),
      );
      if (ex.status === 409) {
        const stale = protocol("sync", () => decode(this.#wasm, ex.body));
        // The node is behind the cursor: a lagging replica, or a chain that got shorter. Only
        // a root that differs from the held tree's at the node's count proves the latter.
        const behind = new HowlError(
          "Stale",
          `the node holds ${stale.leafCount} leaves, behind the ${since} held`,
          { status: 409, state: { leafCount: stale.leafCount, block: stale.block } },
        );
        // A node at or past the verified block with fewer leaves follows a chain that dropped
        // them, even when the leaves it kept are the held ones.
        let ours: Uint8Array | null = null;
        try {
          ours = this.#tree.root(stale.leafCount);
        } catch {
          ours = null;
        }
        if (stale.block < this.#state.block && (ours === null || equal(ours, stale.root))) throw behind;
        rewind(Math.min(await this.#divergence(), stale.leafCount));
        continue;
      }
      const a = this.#answer(ex, KIND.sync, "sync");
      if (a.base !== since || a.upperBase !== upperSince) {
        throw new HowlError("Protocol", `sync answered from ${a.base}/${a.upperBase}, asked ${since}/${upperSince}`);
      }
      const n = a.leafCount;
      const v = this.#state.leafCount;
      const before = { index: this.#tree.newestIndex, leaves: this.#tree.newestLeaves() };
      if (upperSince + a.upperNodes.length / NODE_BYTES !== Math.floor(n / LEAF_BLOCK_SIZE)) {
        throw new HowlError("Protocol", `sync carries ${a.upperNodes.length / NODE_BYTES} upper nodes for ${n} leaves`);
      }
      const newest = this.#newestFrom(a, held, before);
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
        if (n >= v && b === before.index) {
          kept =
            b === a.blockIndex
              ? newest !== null && this.#keeps(before.leaves, v, newest)
              : this.#keeps(before.leaves, v, await this.#fullBlock(b));
        }
        if (!kept) {
          rewind(b * LEAF_BLOCK_SIZE);
          continue;
        }
      } else if (n < v) {
        rewind(n);
        continue;
      }
      this.#feed.append(a.base, a.rows);
      this.#state = { leafCount: n, block: a.block, root: a.root };
      if (a.next === n) {
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

  async #readBatch(positions: number[]): Promise<Uint8Array> {
    const key = positions.join(",");
    for (let attempt = 0; ; attempt++) {
      const inline = this.#keyMode === "inline";
      const client = inline ? await this.#newClient() : await this.#sessionClient();
      try {
        const plan = this.#plans.get(key);
        const batch = protocol("batch", () =>
          plan === undefined
            ? client.buildBatch(Uint32Array.from(positions), this.#state.leafCount)
            : client.buildBatchAt(plan.targets, plan.slots, this.#state.leafCount),
        );
        if (plan === undefined) this.#plans.set(key, { targets: batch.targets, slots: batch.realSlots });
        try {
          const ex = await this.#transport.post("/howl/v1/notes", batch.body);
          if (ex.status === 410 && !inline && attempt === 0) {
            this.close();
            continue;
          }
          this.#answer(ex, KIND.notes, "notes");
          const cells = protocol("notes", () => client.openNotes(batch, ex.body));
          try {
            this.#lastRead = { leafCount: cells.leafCount, block: cells.block };
            this.#plans.delete(key);
            return cells.cells;
          } finally {
            cells.free();
          }
        } finally {
          batch.free();
        }
      } finally {
        if (inline) client.free();
      }
    }
  }

  /**
   * Private read of the cells at `leafIndices` (1 and up), one record per index in request
   * order. Indices are padded to the node's ladder in batches of at most its cap. A cell read
   * once is kept, and read again only after a rewind drops its row.
   */
  fetchNotes(leafIndices: readonly number[]): Promise<HowlNoteRecord<F>[]> {
    return this.#exclusive(() => this.#fetchNotes(leafIndices));
  }

  async #fetchNotes(leafIndices: readonly number[]): Promise<HowlNoteRecord<F>[]> {
    if (leafIndices.length === 0) return [];
    leafIndices.forEach((p) => checkPosition(p, "leaf index"));
    const highest = Math.max(...leafIndices);
    if (highest >= this.#state.leafCount) await this.#sync();
    if (highest >= this.#state.leafCount) {
      throw new RangeError(`leaf ${highest} is past the ${this.#state.leafCount} leaves of the pool`);
    }
    const wanted = [...new Set(leafIndices)].filter((p) => !this.#cells.has(p)).sort((a, b) => a - b);
    if (wanted.length > 0) {
      const cap = decode(this.#wasm, await this.#paramsAnswer()).ladderCap;
      for (let i = 0; i < wanted.length; i += cap) {
        const chunk = wanted.slice(i, i + cap);
        const cells = await this.#readBatch(chunk);
        chunk.forEach((p, k) => {
          const cell = cells.slice(k * 256, (k + 1) * 256);
          decodeCell(cell, p, this.#field);
          this.#cells.set(p, cell);
        });
      }
    }
    return leafIndices.map((p) => decodeCell(this.#cells.get(p)!, p, this.#field));
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
   * verified count), built from the verified tree and checked by folding it.
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
   * read the first match of each tag that has one in one padded private batch. A tag with no
   * match gets a record that opens to nothing, as Howl's self-mint preflight requires.
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
    const firsts = [...new Set([...found.values()].map((list) => list[0]!))];
    const records = new Map<number, HowlNoteRecord<F>>();
    (await this.#fetchNotes(firsts)).forEach((r, i) => records.set(firsts[i]!, r));
    return tags.map((tag, i) => {
      const list = found.get(keys[i]!) ?? [];
      return {
        tag,
        record: list.length === 0 ? missRecord(this.#field) : records.get(list[0]!)!,
        occurrenceCount: list.length,
      };
    });
  }

  /** Howl's round 2: the remaining matches of tags seen by `probeFirst`, in one private read. */
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
