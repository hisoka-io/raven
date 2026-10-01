/**
 * The 6-byte-per-row index channel, client side: segmented one PPOI block per response and
 * resumable from a cursor, so a wallet downloads the list once and then only its tail.
 *
 * A 6-byte prefix is not a blinded commitment, so a lookup returns every candidate index. A
 * blinded commitment is a BN254 field element, so its first six bytes take about 2^45.6 values;
 * over ~360k rows some two rows share a prefix with probability about 0.12%. A proof resolves
 * candidates by the full commitment its row carries. Status fetches no row, so a note whose
 * prefix matches a listed one reads `Valid` until its proof, which binds all 32 bytes, is refused.
 */

import { RavenError } from "./errors";
import { LEAVES_PER_PPOI_BLOCK } from "./pin-resolver";

/** Bytes of each blinded commitment the channel publishes. Must match the server's constant. */
export const BC_INDEX_PREFIX_BYTES = 6;

/** Response headers the channel uses to make itself resumable. */
const HEADER_NEXT = "x-raven-index-next";
const HEADER_TOTAL = "x-raven-index-total";
const HEADER_EPOCH = "x-raven-index-epoch";
const HEADER_BASE = "x-raven-index-base";

/**
 * A resumed walk restarts at the multiple of this at or below the rows already held. It costs at
 * most 12 KB of re-read rows, and those rows are checked against what is held.
 */
export const BC_INDEX_RESUME_ALIGN_ROWS = 2_048;

/**
 * One list's index, as served: prefixes packed back to back, position IS the global index.
 *
 * `epoch` is returned as the server stamps it, and for a mirrored PPOI list it stays 0 as the
 * list grows: mirrored rows carry no chain height. `total` is the quantity that moves when the
 * list grows, so it is what binds an index to the list a node serves; an epoch that differs from
 * the held one names a different list, and the held index is discarded.
 */
export interface BcPrefixIndex {
  /** The frontier segment's `x-raven-index-epoch`; 0 for a mirrored PPOI list. */
  readonly epoch: number;
  /** `total * BC_INDEX_PREFIX_BYTES` bytes; row `i` occupies `[i*6, i*6+6)`. */
  readonly prefixes: Uint8Array;
  /** Rows the server held when the frontier segment was read. */
  readonly total: number;
}

function headerInt(res: Response, name: string, url: string): number {
  const raw = res.headers.get(name);
  if (raw === null) {
    throw RavenError.decodeError(`bc-prefixes: response is missing ${name}`, { url });
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 0) {
    throw RavenError.decodeError(`bc-prefixes: ${name} is ${raw}, not a non-negative integer`, {
      url,
    });
  }
  return value;
}

/** Refuse an index whose byte length does not match its row count before anything reads it. */
export function assertBcPrefixIndex(index: BcPrefixIndex, label: string): void {
  if (
    !Number.isSafeInteger(index.total) ||
    index.total < 0 ||
    index.total > 0xffff_ffff ||
    !Number.isSafeInteger(index.epoch) ||
    index.epoch < 0 ||
    !(index.prefixes instanceof Uint8Array) ||
    index.prefixes.length !== index.total * BC_INDEX_PREFIX_BYTES
  ) {
    throw RavenError.invalidQuery(
      `${label}: an index of ${String(index.total)} rows must carry exactly ` +
        `${String(index.total)} x ${BC_INDEX_PREFIX_BYTES} prefix bytes and a non-negative epoch`,
    );
  }
}

/** The node answered 416: its list ends before the cursor, at `total` rows when it said. */
interface PastFrontier {
  readonly pastFrontier: true;
  readonly since: number;
  readonly total: number | undefined;
  readonly url: string;
}

type Walked = { readonly epoch: number; readonly total: number; readonly rows: Uint8Array };

function pastFrontierRefusal(past: PastFrontier): RavenError {
  return RavenError.staleAdapter(
    `bc-prefixes: the node serves ${past.total === undefined ? "fewer than" : "only"} ` +
      `${past.total ?? past.since} rows of this list`,
    { url: past.url, status: 416 },
  );
}

/**
 * Walk the channel from row `from` to the frontier.
 *
 * A sealed segment (a whole PPOI block) is served `immutable` and a cache may replay it with stale
 * headers, so the walk takes only its bytes and cursor, and reads the list's total and epoch from
 * the frontier, the one segment that is always current.
 */
async function walkBcPrefixes(
  fetchImpl: typeof fetch,
  endpoint: string,
  listKeyHex: string,
  headers: Record<string, string>,
  from: number,
  onRequest?: (url: string) => void,
): Promise<Walked | PastFrontier> {
  const segments: Uint8Array[] = [];
  let since = from;

  for (let walked = 0; ; walked += 1) {
    const url = `${endpoint}/v1/poi/${listKeyHex}/bc-prefixes?since=${since}`;
    // Sealed segments always advance a whole block, so this only stops a server that never
    // reaches a frontier: 4,096 blocks is 268 million rows.
    if (walked > 4_096) {
      throw RavenError.decodeError("bc-prefixes: too many segments; refusing to walk further", {
        url,
      });
    }
    onRequest?.(url);
    let res: Response;
    try {
      // The frontier is served `max-age=15`: a cached one would let an absence read as current
      // against a list up to 15 s old. A sealed segment revalidates to a bodiless 304.
      res = await fetchImpl(url, { headers, cache: "no-cache" });
    } catch (cause) {
      throw RavenError.network("fetchBcPrefixIndex", { url, cause: String(cause) });
    }
    if (res.status === 416) {
      const total = res.headers.has(HEADER_TOTAL) ? headerInt(res, HEADER_TOTAL, url) : undefined;
      if (total !== undefined && total >= since) {
        throw RavenError.decodeError(
          `bc-prefixes: a 416 for row ${since} reports ${total} rows, which would include it`,
          { url },
        );
      }
      return { pastFrontier: true, since, total, url };
    }
    if (!res.ok) {
      throw RavenError.serverError(`bc-prefixes: ${res.status}`, { url, status: res.status });
    }

    const base = headerInt(res, HEADER_BASE, url);
    const next = headerInt(res, HEADER_NEXT, url);
    if (base !== since) {
      throw RavenError.decodeError(
        `bc-prefixes: asked from ${since} and was answered from ${base}`,
        { url },
      );
    }
    const blockEnd = (Math.floor(since / LEAVES_PER_PPOI_BLOCK) + 1) * LEAVES_PER_PPOI_BLOCK;
    if (next < since || next > blockEnd) {
      throw RavenError.decodeError(
        `bc-prefixes: segment from ${since} ends at ${next}, outside its block ${since}..${blockEnd}`,
        { url },
      );
    }

    const body = new Uint8Array(await res.arrayBuffer());
    const expected = (next - since) * BC_INDEX_PREFIX_BYTES;
    if (body.length !== expected) {
      throw RavenError.decodeError(
        `bc-prefixes: ${body.length} bytes for rows ${since}..${next}, expected ${expected}`,
        { url },
      );
    }
    segments.push(body);

    if (next === blockEnd) {
      since = next;
      continue;
    }

    const total = headerInt(res, HEADER_TOTAL, url);
    const epoch = headerInt(res, HEADER_EPOCH, url);
    if (total !== next) {
      throw RavenError.decodeError(
        `bc-prefixes: the frontier segment from ${since} stops at ${next} of ${total} rows; ` +
          "refusing to guess where the list ends",
        { url },
      );
    }
    const rows = new Uint8Array((total - from) * BC_INDEX_PREFIX_BYTES);
    let at = 0;
    for (const segment of segments) {
      rows.set(segment, at);
      at += segment.length;
    }
    return { epoch, total, rows };
  }
}

/** Walk every segment of one list's prefix channel. */
export async function fetchBcPrefixIndex(
  fetchImpl: typeof fetch,
  endpoint: string,
  listKeyHex: string,
  headers: Record<string, string>,
  onRequest?: (url: string) => void,
): Promise<BcPrefixIndex> {
  const walked = await walkBcPrefixes(fetchImpl, endpoint, listKeyHex, headers, 0, onRequest);
  if ("pastFrontier" in walked) throw pastFrontierRefusal(walked);
  return { epoch: walked.epoch, prefixes: walked.rows, total: walked.total };
}

/**
 * Bring a held index up to the list the node serves now.
 *
 * The list is append-only, so a re-read row that differs from the held one, or a node serving
 * fewer rows than the index holds, is refused. A frontier with another epoch is another list, and
 * the whole list is read again. Every held row is re-read unless the caller passes
 * `confirmedRows`, rows this node already served or confirmed; then only the tail from the aligned
 * cursor below it is. A 416 resumes from the aligned cursor below the total the node reports.
 */
export async function resumeBcPrefixIndex(
  fetchImpl: typeof fetch,
  endpoint: string,
  listKeyHex: string,
  headers: Record<string, string>,
  held: BcPrefixIndex,
  onRequest?: (url: string) => void,
  confirmedRows = 0,
): Promise<BcPrefixIndex> {
  assertBcPrefixIndex(held, "bc-prefixes: held index");
  if (!Number.isSafeInteger(confirmedRows) || confirmedRows < 0) {
    throw RavenError.invalidQuery(
      `bc-prefixes: confirmedRows must be a non-negative integer, got ${String(confirmedRows)}`,
    );
  }
  const aligned = (rows: number): number => rows - (rows % BC_INDEX_RESUME_ALIGN_ROWS);
  const trusted = Math.min(confirmedRows, held.total);
  let from = aligned(trusted);
  let walk = await walkBcPrefixes(fetchImpl, endpoint, listKeyHex, headers, from, onRequest);
  if ("pastFrontier" in walk) {
    if (walk.total === undefined) throw pastFrontierRefusal(walk);
    from = aligned(walk.total);
    walk = await walkBcPrefixes(fetchImpl, endpoint, listKeyHex, headers, from, onRequest);
    if ("pastFrontier" in walk) throw pastFrontierRefusal(walk);
  }
  const walked = walk;
  if (walked.epoch !== held.epoch) {
    return from === 0
      ? { epoch: walked.epoch, prefixes: walked.rows, total: walked.total }
      : fetchBcPrefixIndex(fetchImpl, endpoint, listKeyHex, headers, onRequest);
  }
  if (walked.total < held.total) {
    throw RavenError.staleAdapter(
      `bc-prefixes: the node serves ${walked.total} rows of a list this index holds ` +
        `${held.total} rows of`,
    );
  }
  const heldTail = held.prefixes.subarray(from * BC_INDEX_PREFIX_BYTES);
  for (let byte = 0; byte < heldTail.length; byte += 1) {
    if (walked.rows[byte] !== heldTail[byte]) {
      throw RavenError.decodeError(
        `bc-prefixes: row ${from + Math.floor(byte / BC_INDEX_PREFIX_BYTES)} differs from the ` +
          "row this index already holds, and an append-only list cannot rewrite one",
      );
    }
  }
  const prefixes = new Uint8Array(walked.total * BC_INDEX_PREFIX_BYTES);
  prefixes.set(held.prefixes.subarray(0, from * BC_INDEX_PREFIX_BYTES), 0);
  prefixes.set(walked.rows, from * BC_INDEX_PREFIX_BYTES);
  return { epoch: walked.epoch, prefixes, total: walked.total };
}

/**
 * Every global index whose published prefix matches this commitment.
 *
 * Returns all candidates rather than the first: see the module header. A caller with one
 * candidate proceeds; with several it tries each and lets the fold's commitment check decide;
 * with none the commitment is absent from the first `total` rows, which is all an index can say:
 * it does not know whether the list has grown since it was read.
 */
export function indexCandidatesFor(index: BcPrefixIndex, blindedCommitmentHex: string): number[] {
  return indexCandidatesForEach(index, [blindedCommitmentHex])[0];
}

/** `indexCandidatesFor` for many commitments in one pass over the rows. */
export function indexCandidatesForEach(
  index: BcPrefixIndex,
  blindedCommitmentsHex: readonly string[],
): number[][] {
  const wanted = new Map<number, number[]>();
  blindedCommitmentsHex.forEach((commitment, position) => {
    const hex =
      commitment.startsWith("0x") || commitment.startsWith("0X") ? commitment.slice(2) : commitment;
    if (hex.length !== 64 || !/^[0-9a-fA-F]+$/.test(hex)) {
      throw RavenError.invalidQuery(
        `bc-prefixes: blinded commitment must be 64 hex chars, got ${hex.length}`,
      );
    }
    const key = Number.parseInt(hex.slice(0, BC_INDEX_PREFIX_BYTES * 2), 16);
    const positions = wanted.get(key);
    if (positions === undefined) wanted.set(key, [position]);
    else positions.push(position);
  });
  const out = blindedCommitmentsHex.map((): number[] => []);
  const p = index.prefixes;
  for (let row = 0; row < index.total; row += 1) {
    const at = row * BC_INDEX_PREFIX_BYTES;
    // 48 bits: exact in a double, so one Map probe per row replaces a byte loop per commitment.
    const key =
      ((p[at] << 16) | (p[at + 1] << 8) | p[at + 2]) * 0x1_000_000 +
      ((p[at + 3] << 16) | (p[at + 4] << 8) | p[at + 5]);
    const positions = wanted.get(key);
    if (positions !== undefined) {
      for (const position of positions) out[position].push(row);
    }
  }
  return out;
}

/**
 * True when a served row names a DIFFERENT commitment that shares this one's published prefix:
 * the collision the module header describes, so the caller moves to the next candidate. A row
 * that does not even carry the prefix is the node contradicting its own index, and this returns
 * false so the caller's ordinary commitment check refuses it.
 */
export function sharesOnlyPrefix(rowCommitment: Uint8Array, commitment: Uint8Array): boolean {
  const width = Math.min(rowCommitment.length, commitment.length);
  if (width <= BC_INDEX_PREFIX_BYTES) return false;
  for (let byte = 0; byte < BC_INDEX_PREFIX_BYTES; byte += 1) {
    if (rowCommitment[byte] !== commitment[byte]) return false;
  }
  for (let byte = BC_INDEX_PREFIX_BYTES; byte < width; byte += 1) {
    if (rowCommitment[byte] !== commitment[byte]) return true;
  }
  return false;
}
