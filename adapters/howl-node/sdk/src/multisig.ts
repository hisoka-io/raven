import { HowlError } from "./errors.js";
import { COMMITMENT_PREFIX_BYTES, RECORD_KIND_INCOMING, RECORD_KIND_SELF, bigintField, type FieldCodec, type HowlNoteRecord } from "./record.js";
import type { FirstOccurrence, MerkleWitness, NoteCheck, RavenHowlSource } from "./source.js";

// Howl's multisig scanner floors and caps its lookahead windows at these; the mirror here must
// register exactly the tags it does, or a note one side sees is invisible to the other.
const MIN_WINDOW = 16;
const MAX_FIRST_WINDOW = 1_000;
const DEFAULT_SELF_WINDOW = 100;
const DEFAULT_INCOMING_WINDOW = 20;
const CIPHERTEXT_WORDS = 7;

/**
 * A chain event in the shape Howl's `MultisigScanner.readNote` takes, rebuilt from a Raven cell:
 * the full seven ciphertext words and the commitment the note opened to.
 */
export interface MultisigChainEvent {
  readonly type: "NEW_NOTE" | "NEW_MEMO";
  /** Unknown from a cell: 0, so the scanner tries every compliance key version it holds. */
  readonly blockNumber: number;
  readonly txHash: string;
  readonly args: {
    readonly leafIndex: bigint;
    /** 0x-prefixed, 32 bytes. */
    readonly commitment: string;
    readonly ephemeralX: bigint;
    /** 0x-prefixed words, 32 bytes each. */
    readonly packedCiphertext: string[];
    readonly tag?: bigint;
    readonly cekWrap?: bigint;
  };
}

/** What the adaptor needs of Howl's `MultisigScanner`; an instance of it fits as it is. */
export interface MultisigEventScanner<V> {
  readNote(event: MultisigChainEvent): Promise<V | null>;
  ensureSelfLookahead(window: number): Promise<boolean>;
  ensureIncomingLookahead(window: number): Promise<boolean>;
}

/** Where a tag came from: a member's self ephemeral, or one of the group's receiving addresses. */
export type MultisigTagSource =
  | { readonly family: "self"; readonly memberId: bigint; readonly j: bigint }
  | { readonly family: "incoming"; readonly index: bigint };

/** A note a cell decrypts to under one content key. */
export interface OpenedCell<F> {
  /** All seven ciphertext words, 0 and 5 rebuilt (Howl's `reconstructCiphertext` with owner = `multisigOwner(gpk)`). */
  readonly words: readonly F[];
  /** The commitment of the decrypted note (Howl's `leaf`). */
  readonly commitment: F;
}

/**
 * The group's keys, supplied by the wallet from Howl's own functions; the package holds no curve
 * or hash code. `S` is whatever secret the wallet wants handed back with a match.
 */
export interface MultisigKeys<F, S = unknown> {
  /** Member `memberId`'s self ephemeral `j` (`deriveSelfEph`): its tag, or null when its y is odd. */
  selfTag(memberId: bigint, j: bigint): Promise<{ readonly tag: F; readonly secret: S } | null>;
  /** The first receiving address at index `from` or later (`multisigIncomingKeyAt`). */
  incomingAt(from: bigint): Promise<{ readonly index: bigint; readonly tag: F; readonly secret: S }>;
  /**
   * The notes `record` decrypts to, one per content key it could be under (one per compliance key
   * version for a self note, `memberReadIncoming` for an incoming one). Empty when none decrypts.
   */
  open(record: HowlNoteRecord<F>, source: MultisigTagSource, secret: S): Promise<readonly OpenedCell<F>[]>;
}

export interface MultisigScanOptions<F, V, S> {
  readonly source: Pick<RavenHowlSource<F>, "probeFirst" | "confirmNote">;
  readonly field: FieldCodec<F>;
  readonly keys: MultisigKeys<F, S>;
  /** Howl's scanner for the same group, created with the same windows. */
  readonly scanner: MultisigEventScanner<V>;
  readonly memberIds: readonly bigint[];
  /** Howl's `selfWindow` (default 100). */
  readonly selfWindow?: number;
  /** Howl's `incomingWindow` (default 20). */
  readonly incomingWindow?: number;
}

export interface MultisigFound<F, V> {
  /** What Howl's scanner returned for the event. */
  readonly view: V;
  readonly event: MultisigChainEvent;
  readonly leafIndex: number;
  readonly commitment: F;
  readonly source: MultisigTagSource;
  /** `confirmNote` on the commitment: `"unconfirmed"` until the note's block is held. */
  readonly check: NoteCheck;
}

export interface MultisigScanResult<F, V> {
  /** Notes Howl's scanner accepted, by leaf index. */
  readonly found: readonly MultisigFound<F, V>[];
  /** Positions whose cell opened under the group's key but which Howl's scanner refused (type, owner, asset). */
  readonly refused: readonly number[];
  /** Positions of the right record kind that opened to no note with the cell's commitment prefix. */
  readonly unopened: readonly number[];
  /** Private probe rounds: 1 when no match moved a lookahead window. */
  readonly rounds: number;
}

function window(value: number | undefined, fallback: number, label: string): number {
  const w = value ?? fallback;
  if (!Number.isInteger(w) || w < MIN_WINDOW) {
    throw new RangeError(`multisig ${label} lookahead must be an integer of at least ${MIN_WINDOW}, got ${w}`);
  }
  return w;
}

function hex(bytes: Uint8Array): string {
  let out = "0x";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

/**
 * Multisig discovery over Raven for Howl's `MultisigScanner`.
 *
 * The scanner reads chain events, whose seven ciphertext words and full commitment a Raven cell
 * does not carry, and keeps its tag maps to itself. This adaptor registers the same tags with the
 * same lookahead rules, probes them through the source, opens every matched position of the
 * right record kind with the wallet's keys, accepts a note whose commitment starts with the
 * cell's prefix, checks it against the verified tree, and hands the scanner the event it would
 * have read from the chain. Both grow their windows from the same matches, so they stay in step.
 */
export class MultisigRavenScan<F, V, S = unknown> {
  readonly #o: MultisigScanOptions<F, V, S>;
  readonly #selfWindow: number;
  readonly #incomingWindow: number;
  readonly #tags = new Map<string, { source: MultisigTagSource; tag: F; secret: S }>();
  readonly #selfNext = new Map<bigint, bigint>();
  readonly #selfHigh = new Map<bigint, bigint>();
  #incomingNext = 0n;
  #incomingHigh = -1n;
  #ready = false;

  constructor(options: MultisigScanOptions<F, V, S>) {
    if (options.memberIds.length === 0) throw new RangeError("a multisig group has members");
    this.#o = options;
    this.#selfWindow = window(options.selfWindow, DEFAULT_SELF_WINDOW, "self");
    this.#incomingWindow = window(options.incomingWindow, DEFAULT_INCOMING_WINDOW, "incoming");
  }

  /** Tags registered: what the next scan probes. */
  get tagCount(): number {
    return this.#tags.size;
  }

  #key(tag: F): string {
    return hex(this.#o.field.toBytes(tag));
  }

  async #addSelf(memberId: bigint, j: bigint): Promise<boolean> {
    const k = await this.#o.keys.selfTag(memberId, j);
    if (k === null) return false;
    const key = this.#key(k.tag);
    const fresh = !this.#tags.has(key);
    this.#tags.set(key, { source: { family: "self", memberId, j }, tag: k.tag, secret: k.secret });
    return fresh;
  }

  async #nextIncoming(from: bigint): Promise<{ index: bigint; fresh: boolean }> {
    const k = await this.#o.keys.incomingAt(from);
    if (k.index < from) throw new RangeError(`incomingAt(${from}) answered index ${k.index}`);
    const key = this.#key(k.tag);
    const fresh = !this.#tags.has(key);
    this.#tags.set(key, { source: { family: "incoming", index: k.index }, tag: k.tag, secret: k.secret });
    return { index: k.index, fresh };
  }

  // As MultisigScanner.create: raw indices below the first window, capped.
  async #init(): Promise<void> {
    const selfLimit = BigInt(Math.min(this.#selfWindow, MAX_FIRST_WINDOW));
    for (const id of this.#o.memberIds) {
      for (let j = 0n; j < selfLimit; j++) await this.#addSelf(id, j);
      this.#selfNext.set(id, selfLimit);
    }
    const incomingLimit = BigInt(Math.min(this.#incomingWindow, MAX_FIRST_WINDOW));
    for (let next = 0n; next < incomingLimit; ) {
      const k = await this.#o.keys.incomingAt(next);
      if (k.index < next) throw new RangeError(`incomingAt(${next}) answered index ${k.index}`);
      if (k.index >= incomingLimit) break;
      this.#tags.set(this.#key(k.tag), { source: { family: "incoming", index: k.index }, tag: k.tag, secret: k.secret });
      next = k.index + 1n;
    }
    this.#incomingNext = incomingLimit;
    this.#ready = true;
  }

  // As ensureSelfLookahead / ensureIncomingLookahead, on this side and on Howl's scanner.
  async #grow(): Promise<boolean> {
    let advanced = false;
    for (const id of this.#o.memberIds) {
      const target = (this.#selfHigh.get(id) ?? -1n) + 1n + BigInt(this.#selfWindow);
      let next = this.#selfNext.get(id) ?? 0n;
      for (; next < target; next++) if (await this.#addSelf(id, next)) advanced = true;
      this.#selfNext.set(id, next);
    }
    const target = this.#incomingHigh + 1n + BigInt(this.#incomingWindow);
    while (this.#incomingNext < target) {
      const k = await this.#nextIncoming(this.#incomingNext);
      if (k.fresh) advanced = true;
      this.#incomingNext = k.index + 1n;
    }
    const theirs = [
      await this.#o.scanner.ensureSelfLookahead(this.#selfWindow),
      await this.#o.scanner.ensureIncomingLookahead(this.#incomingWindow),
    ];
    return advanced || theirs.some(Boolean);
  }

  /**
   * Probe every registered tag (the feed is synced first), open and hand over each note, then
   * grow the windows past the matches and probe the new tags, until no window moves.
   */
  async scan(): Promise<MultisigScanResult<F, V>> {
    if (!this.#ready) await this.#init();
    const found = new Map<number, MultisigFound<F, V>>();
    const refused = new Set<number>();
    const unopened = new Set<number>();
    const probed = new Set<string>();
    let rounds = 0;
    for (;;) {
      const fresh = [...this.#tags.entries()].filter(([k]) => !probed.has(k));
      if (fresh.length > 0) {
        fresh.forEach(([k]) => probed.add(k));
        rounds++;
        const answers = await this.#o.source.probeFirst(fresh.map(([, t]) => t.tag));
        for (const a of answers) await this.#read(a, found, refused, unopened);
      }
      if (!(await this.#grow())) break;
    }
    const sorted = [...found.values()].sort((a, b) => a.leafIndex - b.leafIndex);
    const byIndex = (s: Set<number>) => [...s].filter((p) => !found.has(p)).sort((a, b) => a - b);
    return { found: sorted, refused: byIndex(refused), unopened: byIndex(unopened), rounds };
  }

  async #read(
    answer: FirstOccurrence<F>,
    found: Map<number, MultisigFound<F, V>>,
    refused: Set<number>,
    unopened: Set<number>,
  ): Promise<void> {
    const entry = this.#tags.get(this.#key(answer.tag));
    if (entry === undefined) throw new HowlError("Protocol", "a probe answered a tag it was not asked");
    const { source, secret } = entry;
    const kind = source.family === "self" ? RECORD_KIND_SELF : RECORD_KIND_INCOMING;
    // every matched position: another note's six-byte row can sort before this tag's own
    for (const record of answer.records) {
      if (record.recordKind !== kind || found.has(record.leafIndex)) continue;
      const opened = await this.#o.keys.open(record, source, secret);
      const note = opened.find((c) =>
        sameBytes(record.commitmentPrefix, this.#o.field.toBytes(c.commitment).subarray(0, COMMITMENT_PREFIX_BYTES)),
      );
      if (note === undefined) {
        unopened.add(record.leafIndex);
        continue;
      }
      if (note.words.length !== CIPHERTEXT_WORDS) {
        throw new RangeError(`an opened cell carries ${note.words.length} ciphertext words, not ${CIPHERTEXT_WORDS}`);
      }
      const check = await this.#o.source.confirmNote(record, note.commitment);
      // the window moves on a note of the group, as the scanner's own does on a tag match
      if (source.family === "self") {
        if (source.j > (this.#selfHigh.get(source.memberId) ?? -1n)) this.#selfHigh.set(source.memberId, source.j);
      } else if (source.index > this.#incomingHigh) {
        this.#incomingHigh = source.index;
      }
      const event = this.#event(record, source, entry.tag, note);
      const view = await this.#o.scanner.readNote(event);
      if (view === null) {
        refused.add(record.leafIndex);
        continue;
      }
      found.set(record.leafIndex, {
        view,
        event,
        leafIndex: record.leafIndex,
        commitment: note.commitment,
        source,
        check,
      });
    }
  }

  #event(record: HowlNoteRecord<F>, source: MultisigTagSource, tag: F, note: OpenedCell<F>): MultisigChainEvent {
    const big = (f: F) => bigintField.fromBytes(this.#o.field.toBytes(f));
    const common = {
      leafIndex: BigInt(record.leafIndex),
      commitment: hex(this.#o.field.toBytes(note.commitment)),
      packedCiphertext: note.words.map((w) => hex(this.#o.field.toBytes(w))),
    };
    if (source.family === "self") {
      // a self row carries no ephemeral key: the tag is its x
      return { type: "NEW_NOTE", blockNumber: 0, txHash: "", args: { ...common, ephemeralX: big(tag) } };
    }
    return {
      type: "NEW_MEMO",
      blockNumber: 0,
      txHash: "",
      args: { ...common, ephemeralX: big(record.ephemeralPkX), tag: big(tag), cekWrap: big(record.cekWrap) },
    };
  }
}

/** Why a signer refused a signing session. */
export type SigningRefusalReason =
  /** The signer's own scan holds no note at a session leaf index, or another one. */
  | "unknown-note"
  /** The verified tree's leaf at that index is not the signer's note. */
  | "leaf"
  /** The signer's own path at the session count folds to another root. */
  | "root"
  /** The signer's node does not reach the session count. */
  | "count";

export class SigningSessionRefused extends Error {
  readonly reason: SigningRefusalReason;
  readonly leafIndex: number;

  constructor(reason: SigningRefusalReason, leafIndex: number, message: string) {
    super(message);
    this.name = "SigningSessionRefused";
    this.reason = reason;
    this.leafIndex = leafIndex;
  }
}

/**
 * What a coordinator sends each signer: the notes spent and the one tree state their paths are
 * taken at. The FROST message binds `root`, and the signers re-fold their own paths to it.
 */
export interface SigningSession<F> {
  readonly leafCount: number;
  readonly root: F;
  readonly notes: readonly { readonly leafIndex: number; readonly leaf: F }[];
}

/**
 * Coordinator: the session for spending the notes at `leafIndices`, with every path at one count
 * (default: the newest verified, read once). The witnesses are those the proof takes; the root
 * must still be confirmed on chain (`isKnownRoot`) before proving.
 */
export async function openSigningSession<F>(
  source: Pick<RavenHowlSource<F>, "merkleWitness" | "sync" | "state">,
  leafIndices: readonly number[],
  leafCount?: number,
): Promise<{ session: SigningSession<F>; witnesses: MerkleWitness<F>[] }> {
  if (leafIndices.length === 0) throw new RangeError("a session spends at least one note");
  if (new Set(leafIndices).size !== leafIndices.length) throw new RangeError("a note is spent once per session");
  let n = leafCount;
  if (n === undefined) {
    await source.sync();
    n = source.state.leafCount;
  }
  const witnesses: MerkleWitness<F>[] = [];
  for (const i of leafIndices) witnesses.push(await source.merkleWitness(i, n));
  return {
    session: { leafCount: n, root: witnesses[0]!.root, notes: witnesses.map((w) => ({ leafIndex: w.leafIndex, leaf: w.leaf })) },
    witnesses,
  };
}

/**
 * Signer, before it commits: every session note must be one its own scan found (`owned`, leaf
 * index to commitment), and its own path to that note at the session count must hold the note
 * and fold to the session root. Throws {@link SigningSessionRefused} otherwise; returns the
 * signer's own witnesses.
 */
export async function checkSigningSession<F>(
  source: Pick<RavenHowlSource<F>, "merkleWitness">,
  field: FieldCodec<F>,
  session: SigningSession<F>,
  owned: ReadonlyMap<number, F>,
): Promise<MerkleWitness<F>[]> {
  const bytes = (f: F) => field.toBytes(f);
  const out: MerkleWitness<F>[] = [];
  for (const note of session.notes) {
    const i = note.leafIndex;
    const mine = owned.get(i);
    if (mine === undefined || !sameBytes(bytes(mine), bytes(note.leaf))) {
      throw new SigningSessionRefused("unknown-note", i, `leaf ${i} is not a note this signer found`);
    }
    let w: MerkleWitness<F>;
    try {
      w = await source.merkleWitness(i, session.leafCount);
    } catch (e) {
      if (!(e instanceof RangeError)) throw e;
      throw new SigningSessionRefused("count", i, `leaf ${i} at count ${session.leafCount}: ${e.message}`);
    }
    if (!sameBytes(bytes(w.leaf), bytes(mine))) {
      throw new SigningSessionRefused("leaf", i, `the verified tree holds another leaf at ${i}`);
    }
    if (!sameBytes(bytes(w.root), bytes(session.root))) {
      throw new SigningSessionRefused(
        "root",
        i,
        `the path of leaf ${i} at count ${session.leafCount} folds to ${hex(bytes(w.root))}, the session names ${hex(bytes(session.root))}`,
      );
    }
    out.push(w);
  }
  return out;
}
