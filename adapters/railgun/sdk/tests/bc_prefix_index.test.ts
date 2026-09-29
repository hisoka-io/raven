/**
 * The 6-byte index channel, client side.
 *
 * Two properties that are easy to state and easy to get wrong: the walk must follow the server's
 * cursor to the end of a multi-block list, and it must take the list's size from the frontier
 * alone. A sealed segment is served `immutable`, so what arrives for it may be a copy any cache
 * stored months ago; its bytes are still right, its view of the whole list is not.
 *
 * The collision case is asserted on purpose rather than treated as unreachable. A 6-byte prefix
 * is not a commitment: a BN254 element's first six bytes take about 2^45.6 values, so over a real
 * list two rows sharing a prefix is rare and not impossible, and a lookup that returned only the
 * first would hand a wallet the wrong index and a refusal blaming the node.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  BC_INDEX_PREFIX_BYTES,
  RavenError,
  fetchBcPrefixIndex,
  indexCandidatesFor,
} from "../src/index";
import { startMockServer, type MockServer } from "./helpers/mock_server";

const LIST_KEY_HEX = "ab".repeat(32);
const BLOCK = 65_536;

// 8 hex chars x 8 = 64. The obvious 4-char version silently produces an 80-char string past row
// 65,535, which is exactly the range this file has to cover.
function bcHex(seed: number): string {
  return seed.toString(16).padStart(8, "0").repeat(8);
}

function rows(count: number, from = 0): string[] {
  return Array.from({ length: count }, (_u, i) => bcHex(from + i + 1));
}

/** Exactly what the server packs: the first six bytes of each commitment, back to back. */
function packPrefixes(bcs: readonly string[]): Uint8Array {
  const out = new Uint8Array(bcs.length * BC_INDEX_PREFIX_BYTES);
  bcs.forEach((hex, row) => {
    for (let byte = 0; byte < BC_INDEX_PREFIX_BYTES; byte += 1) {
      out[row * BC_INDEX_PREFIX_BYTES + byte] = Number.parseInt(hex.slice(byte * 2, byte * 2 + 2), 16);
    }
  });
  return out;
}

/** The list as the server holds it right now; tests mutate it to grow the list. */
interface ListState {
  bcs: string[];
  epoch: number;
}

interface ChannelOptions {
  /** Also put the list-wide total and epoch on sealed segments, as the server once did and as
   *  a cache still holding one of those responses does for a year. */
  readonly listWideOnSealed?: boolean;
  /** Advance the cursor by this many rows instead of one block, to model a stuck server. */
  readonly nextOverride?: (since: number, total: number) => number;
  /** Runs after each segment is answered, to move the list mid-walk. */
  readonly afterServe?: (since: number) => void;
}

function mountChannel(server: MockServer, list: ListState, options: ChannelOptions = {}): void {
  server.route(
    (req) => (req.url ?? "").startsWith(`/v1/poi/${LIST_KEY_HEX}/bc-prefixes`),
    (req, _body, res) => {
      const since = Number(new URL(req.url ?? "", "http://x").searchParams.get("since") ?? "0");
      const total = list.bcs.length;
      if (since > total) {
        res.writeHead(416);
        res.end();
        return true;
      }
      const blockEnd = (Math.floor(since / BLOCK) + 1) * BLOCK;
      const next = options.nextOverride
        ? options.nextOverride(since, total)
        : Math.min(blockEnd, total);
      const sealed = next === blockEnd;
      const headers: Record<string, string> = {
        "content-type": "application/octet-stream",
        "x-raven-index-base": String(since),
        "x-raven-index-next": String(next),
        "cache-control": sealed
          ? "public, max-age=31536000, immutable"
          : "public, max-age=15, must-revalidate",
      };
      if (!sealed || options.listWideOnSealed) {
        headers["x-raven-index-total"] = String(total);
        headers["x-raven-index-epoch"] = String(list.epoch);
      }
      res.writeHead(200, headers);
      res.end(Buffer.from(packPrefixes(list.bcs.slice(since, next))));
      options.afterServe?.(since);
      return true;
    },
  );
}

/**
 * An HTTP cache that honours `immutable` as a browser or CDN does: once stored, the response is
 * replayed, headers and all, and the server is not asked again.
 */
function immutableCachingFetch(): typeof fetch {
  const stored = new Map<string, Response>();
  return async (input, init) => {
    const key = String(input);
    const hit = stored.get(key);
    if (hit) return hit.clone();
    const res = await fetch(input, init);
    if ((res.headers.get("cache-control") ?? "").includes("immutable")) {
      stored.set(key, res.clone());
    }
    return res;
  };
}

async function refusal(walk: Promise<unknown>): Promise<unknown> {
  try {
    await walk;
  } catch (e) {
    return e;
  }
  throw new Error("the walk was expected to refuse and returned an index");
}

describe("the six-byte index channel", () => {
  let server: MockServer;

  beforeAll(async () => {
    server = await startMockServer();
  });
  afterAll(async () => {
    await server.close();
  });
  afterEach(() => {
    server.reset();
  });

  function segmentRequests(): number {
    return server.requests.filter((r) => (r.url ?? "").includes("bc-prefixes")).length;
  }

  it("walks one segment and returns the epoch the server served", async () => {
    const bcs = rows(3);
    mountChannel(server, { bcs, epoch: 42 });
    const index = await fetchBcPrefixIndex(fetch, server.url, LIST_KEY_HEX, {});
    expect(index.total).toBe(3);
    expect(index.epoch).toBe(42);
    expect(index.prefixes).toHaveLength(3 * BC_INDEX_PREFIX_BYTES);
    expect(indexCandidatesFor(index, bcs[1])).toEqual([1]);
  });

  // The whole reason the channel is segmented: a list larger than one block must still resolve,
  // and the walk is what makes the cursor worth serving.
  it("follows the cursor across a block boundary", async () => {
    const bcs = rows(BLOCK + 3);
    mountChannel(server, { bcs, epoch: 7 });
    const index = await fetchBcPrefixIndex(fetch, server.url, LIST_KEY_HEX, {});
    expect(index.total).toBe(BLOCK + 3);
    expect(indexCandidatesFor(index, bcs[BLOCK + 2])).toEqual([BLOCK + 2]);
    expect(segmentRequests()).toBe(2);
  });

  // A list of exactly one full block ends in an EMPTY frontier segment. Stopping at the sealed
  // one would be right today and silently short the moment a row lands.
  it("reads past a full block to the empty frontier behind it", async () => {
    const bcs = rows(BLOCK);
    mountChannel(server, { bcs, epoch: 7 });
    const index = await fetchBcPrefixIndex(fetch, server.url, LIST_KEY_HEX, {});
    expect(index.total).toBe(BLOCK);
    expect(segmentRequests()).toBe(2);
  });

  // Two rows may share a six-byte prefix. Returning only the first would hand a wallet the wrong
  // index; the caller resolves it against the row's full commitment, which it checks anyway.
  it("returns every candidate when two rows share a prefix", async () => {
    const shared = "0000000900".slice(0, 12).padEnd(12, "0");
    const twin = `${shared}${"11".repeat(26)}`;
    const other = `${shared}${"22".repeat(26)}`;
    expect(twin).toHaveLength(64);
    expect(other).toHaveLength(64);
    expect(twin.slice(0, 12)).toBe(other.slice(0, 12));
    mountChannel(server, { bcs: [bcHex(1), twin, bcHex(2), other], epoch: 7 });
    const index = await fetchBcPrefixIndex(fetch, server.url, LIST_KEY_HEX, {});
    expect(indexCandidatesFor(index, twin)).toEqual([1, 3]);
    expect(indexCandidatesFor(index, other)).toEqual([1, 3]);
  });

  it("reports an absent commitment as no candidates, not as an error", async () => {
    mountChannel(server, { bcs: rows(2), epoch: 7 });
    const index = await fetchBcPrefixIndex(fetch, server.url, LIST_KEY_HEX, {});
    expect(indexCandidatesFor(index, bcHex(99))).toEqual([]);
  });

  // A sealed block cannot change, so rows read from it before the list grew are the rows it
  // holds after. The walk is therefore the list as of its frontier read, never a splice.
  it("reads a list that grows mid-walk as of its frontier", async () => {
    const list: ListState = { bcs: rows(BLOCK + 2), epoch: 5 };
    mountChannel(server, list, {
      afterServe: (since) => {
        if (since === 0) {
          list.bcs.push(...rows(2, BLOCK + 2));
          list.epoch = 6;
        }
      },
    });
    const index = await fetchBcPrefixIndex(fetch, server.url, LIST_KEY_HEX, {});
    expect(index.total).toBe(BLOCK + 4);
    expect(index.epoch).toBe(6);
    expect(indexCandidatesFor(index, list.bcs[BLOCK + 3])).toEqual([BLOCK + 3]);
    expect(indexCandidatesFor(index, list.bcs[BLOCK - 1])).toEqual([BLOCK - 1]);
  });

  // Segment 0 replayed from an HTTP cache with the total and epoch it was stored under, segment 1
  // fresh. Comparing the two refuses every walk for the year the cache keeps segment 0.
  it("reads a sealed segment a cache replays stale, and takes the list from the frontier", async () => {
    const list: ListState = { bcs: rows(BLOCK + 3), epoch: 5 };
    mountChannel(server, list, { listWideOnSealed: true });
    const cached = immutableCachingFetch();
    await fetchBcPrefixIndex(cached, server.url, LIST_KEY_HEX, {});

    list.bcs.push(...rows(2, BLOCK + 3));
    list.epoch = 6;
    const index = await fetchBcPrefixIndex(cached, server.url, LIST_KEY_HEX, {});

    expect(
      server.requests.filter((r) => (r.url ?? "").endsWith("bc-prefixes?since=0")),
      "segment 0 must come from the cache the second time, or this test proves nothing",
    ).toHaveLength(1);
    expect(index.total).toBe(BLOCK + 5);
    expect(index.epoch).toBe(6);
    expect(indexCandidatesFor(index, list.bcs[0])).toEqual([0]);
    expect(indexCandidatesFor(index, list.bcs[BLOCK + 4])).toEqual([BLOCK + 4]);
  });

  // The quieter half of the same trap: a stale total that happens to equal the sealed segment's
  // own cursor reads as "the list ends here", and a walk believing it returns a short index with
  // no error at all.
  it("does not end the walk on a stale total that equals a sealed segment's cursor", async () => {
    const list: ListState = { bcs: rows(BLOCK), epoch: 5 };
    mountChannel(server, list, { listWideOnSealed: true });
    const cached = immutableCachingFetch();
    await fetchBcPrefixIndex(cached, server.url, LIST_KEY_HEX, {});

    list.bcs.push(...rows(2, BLOCK));
    const index = await fetchBcPrefixIndex(cached, server.url, LIST_KEY_HEX, {});

    expect(index.total).toBe(BLOCK + 2);
    expect(indexCandidatesFor(index, list.bcs[BLOCK + 1])).toEqual([BLOCK + 1]);
  });

  // A frontier that reports more rows than it served has lost its cursor. Following it could
  // only loop, so the walk refuses on the one request.
  it("refuses a cursor that does not advance instead of looping", async () => {
    mountChannel(server, { bcs: rows(BLOCK + 2), epoch: 7 }, { nextOverride: (since) => since });
    const thrown = await refusal(fetchBcPrefixIndex(fetch, server.url, LIST_KEY_HEX, {}));
    expect(RavenError.is(thrown, "DecodeError"), `got ${String(thrown)}`).toBe(true);
    expect(String((thrown as Error).message)).toContain("stops at 0 of 65538 rows");
    expect(segmentRequests()).toBe(1);
  });

  it("refuses a segment that runs past its own block", async () => {
    mountChannel(
      server,
      { bcs: rows(BLOCK + 2), epoch: 7 },
      { nextOverride: (_since, total) => total },
    );
    const thrown = await refusal(fetchBcPrefixIndex(fetch, server.url, LIST_KEY_HEX, {}));
    expect(RavenError.is(thrown, "DecodeError"), `got ${String(thrown)}`).toBe(true);
    expect(String((thrown as Error).message)).toContain("outside its block");
  });

  it("refuses a body whose length disagrees with the cursor it was served under", async () => {
    server.route(
      (req) => (req.url ?? "").includes("bc-prefixes"),
      (_req, _body, res) => {
        res.writeHead(200, {
          "content-type": "application/octet-stream",
          "x-raven-index-base": "0",
          "x-raven-index-next": "4",
          "x-raven-index-total": "4",
          "x-raven-index-epoch": "1",
        });
        res.end(Buffer.from(new Uint8Array(3 * BC_INDEX_PREFIX_BYTES)));
        return true;
      },
    );
    const thrown = await refusal(fetchBcPrefixIndex(fetch, server.url, LIST_KEY_HEX, {}));
    expect(RavenError.is(thrown, "DecodeError"), `got ${String(thrown)}`).toBe(true);
    expect(String((thrown as Error).message)).toContain("expected 24");
  });

  // A 416 says the list ends before the cursor; one whose own total reaches the cursor contradicts
  // itself, and read as the list's end it would turn rows the node holds into absences.
  it("refuses a 416 whose reported total reaches the cursor it refused", async () => {
    for (const total of [0, 3]) {
      server.reset();
      server.route(
        (req) => (req.url ?? "").includes("bc-prefixes"),
        (_req, _body, res) => {
          res.writeHead(416, { "x-raven-index-total": String(total) });
          res.end();
          return true;
        },
      );
      const thrown = await refusal(fetchBcPrefixIndex(fetch, server.url, LIST_KEY_HEX, {}));
      expect(RavenError.is(thrown, "DecodeError"), `total ${total}: got ${String(thrown)}`).toBe(true);
      expect(String((thrown as Error).message)).toContain(`reports ${total} rows, which would include it`);
    }
  });
});
