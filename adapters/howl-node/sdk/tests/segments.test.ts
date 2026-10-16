// A pool past one feed segment (65,536 rows), served by an in-test node that encodes answers in
// the wire layout, with the connection lost between the two segments of a cold sync.
import { randomBytes } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { bigintField, HowlError, KIND, RavenHowlSource, type Exchange, type HowlTransport } from "../src/index.js";
import { hex, wasm } from "./helpers/fixture.js";

const SEGMENT_ROWS = 65_536;
const BLOCK = 1024;
const LEAVES = 70_000;
const CHAIN_BLOCK = 4_242;

function u16(v: number): number[] {
  return [(v >> 8) & 0xff, v & 0xff];
}
function u32(v: number): number[] {
  return [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff];
}
function u64(v: number): number[] {
  return [...u32(Math.floor(v / 0x1_0000_0000)), ...u32(v >>> 0)];
}

/** One pool state and the answers a node gives for it. */
class Pool {
  readonly leaves: Uint8Array;
  readonly rows: Uint8Array;
  readonly upper: Uint8Array;
  readonly root: Uint8Array;

  constructor(readonly count: number, planted: Map<number, Uint8Array>) {
    this.leaves = new Uint8Array(randomBytes(count * 32));
    for (let i = 0; i < count; i++) this.leaves[i * 32]! &= 0x0f;
    this.rows = new Uint8Array(randomBytes(count * 6));
    for (const [position, prefix] of planted) this.rows.set(prefix, position * 6);
    const full = Math.floor(count / BLOCK);
    this.upper = new Uint8Array(full * 32);
    for (let b = 0; b < full; b++) {
      this.upper.set(wasm.blockNode(this.leaves.subarray(b * BLOCK * 32, (b + 1) * BLOCK * 32)), b * 32);
    }
    this.root = wasm.treeRoot(count, this.upper, this.leaves.subarray(full * BLOCK * 32));
  }

  #answer(kind: number, body: number[] | Uint8Array[]): Uint8Array {
    const head = [...u16(1), ...u16(1), kind, 0, 0, 0, ...u64(this.count), ...u64(CHAIN_BLOCK), ...this.root];
    const parts: Uint8Array[] = [Uint8Array.from(head)];
    for (const part of body) parts.push(part instanceof Uint8Array ? part : Uint8Array.from([part]));
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of parts) {
      out.set(p, at);
      at += p.length;
    }
    return out;
  }

  sync(since: number, upperSince: number): Exchange {
    if (since > this.count) return { status: 409, body: this.#answer(KIND.stale, []) };
    const next = Math.min((Math.floor(since / SEGMENT_ROWS) + 1) * SEGMENT_ROWS, this.count);
    const full = Math.floor(this.count / BLOCK);
    const newest = Math.floor((this.count - 1) / BLOCK);
    const newestLeaves = this.leaves.subarray(newest * BLOCK * 32, this.count * 32);
    return {
      status: 200,
      body: this.#answer(KIND.sync, [
        Uint8Array.from([...u64(since), ...u64(next)]),
        this.rows.subarray(since * 6, next * 6),
        Uint8Array.from([...u64(upperSince), ...u64(full)]),
        this.upper.subarray(upperSince * 32, full * 32),
        Uint8Array.from([...u32(newest), ...u32(newestLeaves.length / 32)]),
        newestLeaves,
      ]),
    };
  }
}

/** A transport over `pool` that loses the connection on the requests numbered in `drop`. */
function served(pool: Pool, drop: Set<number>): HowlTransport & { paths: string[] } {
  const paths: string[] = [];
  return {
    paths,
    get: async (path) => {
      paths.push(path);
      if (drop.has(paths.length)) throw new HowlError("Network", `GET ${path}: connection reset`);
      const m = /^\/howl\/v1\/sync\?since=(\d+)&upper=(\d+)$/.exec(path);
      if (m === null) throw new Error(`unexpected ${path}`);
      return pool.sync(Number(m[1]), Number(m[2]));
    },
    post: async (path) => {
      throw new Error(`unexpected POST ${path}`);
    },
  };
}

describe("a pool past one feed segment", () => {
  const early = new Uint8Array(32).fill(7);
  const late = new Uint8Array(32).fill(9);
  let pool: Pool;

  beforeAll(() => {
    pool = new Pool(
      LEAVES,
      new Map([
        [100, early.slice(26)],
        [69_999, late.slice(26)],
      ]),
    );
  });

  it("a sync cut between segments leaves a snapshot that loads and reads on", async () => {
    const transport = served(pool, new Set([2]));
    const first = new RavenHowlSource({ transport, wasm, field: bigintField });
    await expect(first.sync()).rejects.toMatchObject({ kind: "Network" });
    expect(transport.paths).toEqual([
      "/howl/v1/sync?since=0&upper=0",
      `/howl/v1/sync?since=${SEGMENT_ROWS}&upper=${Math.floor(LEAVES / BLOCK)}`,
    ]);
    const stored = first.snapshot();
    expect(stored.rows.length / 6).toBe(SEGMENT_ROWS);

    const again = served(pool, new Set());
    const resumed = new RavenHowlSource({ transport: again, wasm, field: bigintField, snapshot: stored });
    const result = await resumed.sync();
    expect(again.paths).toEqual([`/howl/v1/sync?since=${SEGMENT_ROWS}&upper=${Math.floor(LEAVES / BLOCK)}`]);
    expect(result.leafCount).toBe(LEAVES);
    expect(result.rowsAdded).toBe(LEAVES - SEGMENT_ROWS);
    expect(hex(result.root)).toBe(hex(pool.root));
    expect(resumed.feed.length).toBe(LEAVES);
    const tags = [bigintField.fromBytes(early), bigintField.fromBytes(late)];
    expect(resumed.matches(tags).map((m) => [m.position, m.candidate])).toEqual([
      [100, 0],
      [69_999, 1],
    ]);
    expect(hex(resumed.snapshot().rows)).toBe(hex(pool.rows));
  });

  it("an unbroken cold sync takes both segments in one call", async () => {
    const transport = served(pool, new Set());
    const src = new RavenHowlSource({ transport, wasm, field: bigintField });
    const result = await src.sync();
    expect(transport.paths.length).toBe(2);
    expect([result.leafCount, result.rowsAdded, src.feed.length]).toEqual([LEAVES, LEAVES, LEAVES]);
    expect(src.snapshot().rows.length).toBe(LEAVES * 6);
  });
});
