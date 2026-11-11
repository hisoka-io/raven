// After a rewind the next private read is the same whatever block, leaf or row the node changed
// or claimed to change: nothing when the tree and feed came back unchanged, every cell otherwise.
import { describe, expect, it } from "vitest";
import {
  bigintField,
  KIND,
  RavenHowlSource,
  type Exchange,
  type HowlAnswerView,
  type HowlBatchHandle,
  type HowlClientHandle,
  type HowlTransport,
  type HowlWasm,
} from "../src/index.js";
import { hex, wasm } from "./helpers/fixture.js";
import { BLOCK, Pool, served } from "./helpers/pool.js";

const COUNT = 3_100;
const OWNED = [5, 700, 1_030, 2_000, 2_500, 3_075, 3_090];

type Lie = (path: string) => Promise<Exchange | null>;

interface Node {
  at: Pool;
  /** Answers in place of the pool while armed; `null` passes a request through. */
  lie: Lie | null;
  reads: number[][];
  paths: string[];
}

/** A header-only answer of route `kind`. */
function bare(kind: number): Uint8Array {
  const body = new Uint8Array(56);
  body[4] = kind;
  return body;
}

const prefixAt = (pool: Pool, p: number): string => hex(pool.leaves.subarray(p * 32, p * 32 + 16));

/** A node over whichever pool `node.at` names, and a wasm whose private reads open from that pool. */
function rig(start: Pool) {
  const node: Node = { at: start, lie: null, reads: [], paths: [] };
  const cell = (p: number): Uint8Array => {
    const out = new Uint8Array(256);
    out[0] = 1;
    out[1] = 1;
    new DataView(out.buffer).setUint32(2, p, false);
    out.set(node.at.leaves.subarray(p * 32, p * 32 + 16), 6);
    return out;
  };
  const view = (kind: number): HowlAnswerView => ({
    kind,
    paramSet: 1,
    leafCount: node.at.count,
    block: 0,
    root: new Uint8Array(32),
    base: 0,
    next: 0,
    rows: new Uint8Array(0),
    upperBase: 0,
    upperNext: 0,
    upperNodes: new Uint8Array(0),
    blockIndex: 0,
    blockLeaves: new Uint8Array(0),
    ladderCap: 16,
    sessionTtlSecs: 0,
    free() {},
  });
  const batchOf = (targets: readonly number[]): HowlBatchHandle => ({
    body: new Uint8Array(4),
    slots: targets.length,
    targets: Uint32Array.from(targets),
    realSlots: Uint32Array.from(targets.map((_, i) => i)),
    free() {},
  });
  const Client = function (): HowlClientHandle {
    return {
      paramSet: 1,
      hasSession: false,
      ladderCap: 16,
      sessionBody: () => new Uint8Array(0),
      installSession: () => 0,
      buildBatch: (positions: Uint32Array) => {
        node.reads.push([...positions]);
        return batchOf([...positions]);
      },
      buildBatchAt: (targets: Uint32Array) => batchOf([...targets]),
      openNotes: (batch: HowlBatchHandle) => {
        const cells = new Uint8Array(batch.targets.length * 256);
        batch.targets.forEach((p, k) => cells.set(cell(p), k * 256));
        return { cells, leafCount: node.at.count, block: 0, root: node.at.root, free() {} };
      },
      free() {},
    };
  } as unknown as HowlWasm["HowlClient"];
  const fake: HowlWasm = {
    ...wasm,
    HowlClient: Client,
    HowlTree: wasm.HowlTree,
    decodeAnswer: (bytes: Uint8Array) =>
      bytes.length === 56 && (bytes[4] === KIND.params || bytes[4] === KIND.notes)
        ? view(bytes[4]!)
        : wasm.decodeAnswer(bytes),
  };
  const transport: HowlTransport = {
    get: async (path) => {
      node.paths.push(path);
      const told = node.lie === null ? null : await node.lie(path);
      if (told !== null) return told;
      if (path === "/howl/v1/params") return { status: 200, body: bare(KIND.params) };
      const u = /^\/howl\/v1\/upper\?since=(\d+)$/.exec(path);
      if (u !== null) return node.at.upperAnswer(Number(u[1]));
      return served(node.at, new Set()).get(path);
    },
    post: async (path) => {
      if (path !== "/howl/v1/notes") throw new Error(`unexpected POST ${path}`);
      return { status: 200, body: bare(KIND.notes) };
    },
  };
  const src = new RavenHowlSource({ transport, wasm: fake, field: bigintField, keyMode: "inline" });
  return { node, src };
}

/** `pool` with leaf `p` changed, every node and the root recomputed. */
function withLeaf(pool: Pool, p: number): Pool {
  const changed = new Pool(pool.count, new Map(), pool);
  changed.leaves[p * 32 + 5]! ^= 1;
  return new Pool(pool.count, new Map(), changed);
}

/** The first `n` leaves and rows of `pool`. */
function prefixOf(pool: Pool, n: number): Pool {
  const short = new Pool(n, new Map());
  short.leaves.set(pool.leaves.subarray(0, n * 32));
  short.rows.set(pool.rows.subarray(0, n * 6));
  return new Pool(n, new Map(), short);
}

/** The next sync answers with a changed root, and the upper nodes then differ from block `k` on. */
function armRoot(node: Node, k: number): void {
  let stage = 0;
  node.lie = async (path) => {
    if (stage === 0 && path.startsWith("/howl/v1/sync")) {
      stage = 1;
      const ex = await served(node.at, new Set()).get(path);
      const body = ex.body.slice();
      body[55]! ^= 1;
      return { ...ex, body };
    }
    if (stage === 1 && path === "/howl/v1/upper?since=0") {
      stage = 2;
      const ex = node.at.upperAnswer(0);
      const body = ex.body.slice();
      if (k < Math.floor(node.at.count / BLOCK)) body[56 + 16 + k * 32 + 31]! ^= 1;
      return { ...ex, body };
    }
    return null;
  };
}

/** The next sync is refused as from a node at `c` leaves whose tree agrees up to there. */
function armBehind(node: Node, c: number): void {
  let armed = true;
  node.lie = async (path) => {
    if (!armed || !path.startsWith("/howl/v1/sync")) return null;
    armed = false;
    return prefixOf(node.at, c).sync(node.at.count, 0);
  };
}

/** The next sync serves feed row `p`, under the held count, otherwise. */
function armMoved(node: Node, p: number): void {
  let armed = true;
  node.lie = async (path) => {
    if (!armed || !path.startsWith("/howl/v1/sync")) return null;
    armed = false;
    return served(new Pool(node.at.count, new Map([[p, new Uint8Array(6).fill(9)]]), node.at), new Set()).get(path);
  };
}

/** Sync, read the owned cells, sync again past what `arm` sets up, and read them again. */
async function reReadAfter(arm: (node: Node) => void) {
  const truth = new Pool(COUNT, new Map());
  const { node, src } = rig(truth);
  await src.sync();
  await src.fetchNotes(OWNED);
  expect(node.reads).toEqual([OWNED]);
  arm(node);
  const result = await src.sync();
  expect([result.leafCount, hex(result.root)]).toEqual([COUNT, hex(truth.root)]);
  const mark = node.reads.length;
  const records = await src.fetchNotes(OWNED);
  records.forEach((r, i) => expect(hex(r.commitmentPrefix)).toBe(prefixAt(truth, OWNED[i]!)));
  return { rewoundTo: result.rewoundTo, reread: node.reads.slice(mark) };
}

describe("the read after a rewind", () => {
  it("is the same whichever block boundary the node fakes a divergence at", async () => {
    const seen: { why: string; rewoundTo: number | undefined; reread: number[][] }[] = [];
    for (let k = 0; k <= 3; k++) {
      seen.push({ why: `root, block ${k}`, ...(await reReadAfter((node) => armRoot(node, k))) });
      seen.push({ why: `behind, block ${k}`, ...(await reReadAfter((node) => armBehind(node, k * BLOCK + 10))) });
    }
    seen.push({ why: "moved row", ...(await reReadAfter((node) => armMoved(node, 3_080))) });
    expect(seen.map((s) => s.rewoundTo)).toEqual([0, 0, 1_024, 1_024, 2_048, 2_048, 3_072, 3_072, 3_072]);
    for (const s of seen) expect(s.reread, s.why).toEqual([]);
  });

  it("covers every cell read before when any feed row or leaf changed", async () => {
    const truth = new Pool(COUNT, new Map());
    const cases: { at: Pool; rewoundTo: number }[] = [
      { at: new Pool(COUNT, new Map([[3_090, new Uint8Array(6).fill(9)]]), truth), rewoundTo: 3_072 },
      { at: withLeaf(truth, 2_000), rewoundTo: 1_024 },
      { at: withLeaf(truth, 3_075), rewoundTo: 3_072 },
    ];
    for (const c of cases) {
      const { node, src } = rig(truth);
      await src.sync();
      await src.fetchNotes(OWNED);
      node.at = c.at;
      expect((await src.sync()).rewoundTo).toBe(c.rewoundTo);
      const mark = node.reads.length;
      // a read of one cell covers them all, once
      await src.fetchNotes([OWNED[0]!]);
      expect(node.reads.slice(mark)).toEqual([OWNED]);
      const records = await src.fetchNotes(OWNED);
      expect(node.reads.length).toBe(mark + 1);
      records.forEach((r, i) => expect(hex(r.commitmentPrefix)).toBe(prefixAt(c.at, OWNED[i]!)));
    }
  });

  it("is the same whichever block holds the leaf or row a node changes, on the forged chain and after the true one", async () => {
    const truth = new Pool(COUNT, new Map());
    const changes: { why: string; at: Pool }[] = [];
    // a leaf that is not the wallet's in each block, and a row of the tail a sync reads again
    for (const p of [100, 1_500, 2_100, 3_080]) changes.push({ why: `leaf ${p}`, at: withLeaf(truth, p) });
    for (const p of [3_073, 3_099]) {
      changes.push({ why: `row ${p}`, at: new Pool(COUNT, new Map([[p, new Uint8Array(6).fill(9)]]), truth) });
    }
    for (const c of changes) {
      const { node, src } = rig(truth);
      await src.sync();
      await src.fetchNotes(OWNED);
      node.at = c.at;
      await src.sync();
      let mark = node.reads.length;
      const forged = await src.fetchNotes(OWNED);
      expect(node.reads.slice(mark), `${c.why}, forged`).toEqual([OWNED]);
      forged.forEach((r, i) => expect(hex(r.commitmentPrefix)).toBe(prefixAt(c.at, OWNED[i]!)));
      node.at = truth;
      await src.sync();
      mark = node.reads.length;
      const back = await src.fetchNotes(OWNED);
      expect(node.reads.slice(mark), `${c.why}, true chain`).toEqual([OWNED]);
      back.forEach((r, i) => expect(hex(r.commitmentPrefix)).toBe(prefixAt(truth, OWNED[i]!)));
    }
  });

  it("keeps its size while a shorter chain holds cells aside, whatever count the node claims", async () => {
    const truth = new Pool(COUNT, new Map());
    for (const c of [600, 1_500, 2_100, 3_080]) {
      const { node, src } = rig(truth);
      await src.sync();
      await src.fetchNotes(OWNED);
      // a chain of c leaves that agrees with the verified one up to there
      node.at = prefixOf(truth, c);
      await src.sync();
      const below = OWNED.filter((p) => p < c);
      let mark = node.reads.length;
      const short = await src.fetchNotes(below);
      expect(node.reads.slice(mark).map((r) => r.length), `count ${c}`).toEqual([OWNED.length]);
      expect(node.reads[mark]!.slice(0, below.length)).toEqual(below);
      short.forEach((r, i) => expect(hex(r.commitmentPrefix)).toBe(prefixAt(truth, below[i]!)));
      node.at = truth;
      await src.sync();
      mark = node.reads.length;
      const back = await src.fetchNotes(OWNED);
      expect(node.reads.slice(mark), `count ${c}, true chain`).toEqual([]);
      back.forEach((r, i) => expect(hex(r.commitmentPrefix)).toBe(prefixAt(truth, OWNED[i]!)));
    }
  });

  it("costs at most two full re-reads and one sync, however far ahead a forged count sat", async () => {
    const truth = new Pool(COUNT, new Map());
    const syncs = (node: Node) => node.paths.filter((p) => p.startsWith("/howl/v1/sync")).length;
    for (const claim of [3_200, 4_200, 9_000]) {
      const { node, src } = rig(truth);
      await src.sync();
      await src.fetchNotes(OWNED);
      node.at = new Pool(claim, new Map(), truth);
      await src.sync();
      node.at = truth;
      expect((await src.sync()).rewoundTo, `claim ${claim}`).toBe(3_072);
      let mark = node.reads.length;
      let synced = syncs(node);
      for (let i = 0; i < 10; i++) await src.fetchNotes([OWNED[0]!]);
      expect(node.reads.slice(mark), `claim ${claim}, true chain`).toEqual([OWNED]);
      expect(syncs(node) - synced, `claim ${claim}, true chain`).toBe(1);
      // the true chain passes the forged count with other rows: one more full read, then none
      const grown = new Pool(claim + 50, new Map(), truth);
      node.at = grown;
      await src.sync();
      mark = node.reads.length;
      synced = syncs(node);
      for (let i = 0; i < 10; i++) {
        const records = await src.fetchNotes(OWNED);
        records.forEach((r, k) => expect(hex(r.commitmentPrefix)).toBe(prefixAt(grown, OWNED[k]!)));
      }
      expect(node.reads.slice(mark), `claim ${claim}, grown chain`).toEqual([OWNED]);
      expect(syncs(node) - synced).toBe(0);
    }
  });

  it("answers a cell held aside past its full read as not held until a sync reaches the old count", async () => {
    const truth = new Pool(COUNT, new Map());
    const { node, src } = rig(truth);
    await src.sync();
    await src.fetchNotes(OWNED);
    node.at = new Pool(3_200, new Map(), truth);
    await src.sync();
    await src.fetchNotes([3_150]);
    node.at = truth;
    await src.sync();
    let mark = node.reads.length;
    await src.fetchNotes([OWNED[0]!]);
    // the cell past the count takes a filler slot
    expect(node.reads.slice(mark).map((r) => r.length)).toEqual([OWNED.length + 1]);
    const later = new Pool(3_250, new Map(), truth);
    node.at = prefixOf(later, 3_160);
    await src.sync();
    mark = node.reads.length;
    const [held] = await src.fetchNotes([3_150]);
    expect(node.reads.slice(mark)).toEqual([]);
    expect([held!.leafIndex, hex(held!.commitmentPrefix)]).toEqual([3_150, "00".repeat(16)]);
    node.at = later;
    await src.sync();
    mark = node.reads.length;
    const [read] = await src.fetchNotes([3_150]);
    expect(node.reads.slice(mark)).toEqual([[...OWNED, 3_150]]);
    expect(hex(read!.commitmentPrefix)).toBe(prefixAt(later, 3_150));
  });

  it("sends the same requests whether or not the asked positions sit past the count", async () => {
    const truth = new Pool(COUNT, new Map());
    const syncs = (node: Node) => node.paths.filter((p) => p.startsWith("/howl/v1/sync")).length;
    const seen: string[] = [];
    for (const c of [3_000, 3_080, 3_095, COUNT]) {
      const { node, src } = rig(truth);
      await src.sync();
      await src.fetchNotes(OWNED);
      node.at = prefixOf(truth, c);
      await src.sync();
      const pattern: unknown[] = [];
      for (const asked of [OWNED, [OWNED[0]!, 3_200], [OWNED[0]!, 6]]) {
        const mark = node.reads.length;
        const synced = syncs(node);
        const records = await src.fetchNotes(asked);
        pattern.push(syncs(node) - synced, node.reads.slice(mark).map((r) => r.length));
        records.forEach((r, i) => {
          const p = asked[i]!;
          expect(r.leafIndex).toBe(p);
          expect(hex(r.commitmentPrefix), `count ${c}, leaf ${p}`).toBe(p < c ? prefixAt(truth, p) : "00".repeat(16));
        });
      }
      // a shorter chain's first read syncs first and covers every cell, whatever was asked
      if (c < COUNT) expect(pattern.slice(0, 2), `count ${c}`).toEqual([1, [OWNED.length]]);
      seen.push(JSON.stringify(pattern.slice(2)));
    }
    // past the full read, a held cell and a new position cost the same whatever the count
    expect(new Set(seen).size, seen.join("\n")).toBe(1);
    expect(JSON.parse(seen[0]!)).toEqual([0, [1], 0, [1]]);
  });

  it("keeps the cells of the old newest block once it has filled, at every boundary", async () => {
    const truth = new Pool(COUNT, new Map());
    const grown = new Pool(4_200, new Map(), truth);
    for (let k = 0; k <= 3; k++) {
      const { node, src } = rig(truth);
      await src.sync();
      await src.fetchNotes(OWNED);
      node.at = grown;
      armRoot(node, k);
      const result = await src.sync();
      expect([result.leafCount, result.rewoundTo]).toEqual([4_200, k * BLOCK]);
      // the filled block is read, as a sync without a rewind reads it
      expect(node.paths).toContain("/howl/v1/block/3");
      const mark = node.reads.length;
      await src.fetchNotes(OWNED);
      expect(node.reads.slice(mark), `block ${k}`).toEqual([]);
    }
  });

  it("a sync that fails after a rewind leaves the set-aside cells to the next one, with no read before it", async () => {
    const truth = new Pool(COUNT, new Map());
    const { node, src } = rig(truth);
    await src.sync();
    await src.fetchNotes(OWNED);
    let stage = 0;
    node.lie = async (path) => {
      if (stage === 0 && path.startsWith("/howl/v1/sync")) {
        stage = 1;
        return prefixOf(truth, 10).sync(COUNT, 0);
      }
      if (stage === 1 && path.startsWith("/howl/v1/sync")) {
        stage = 2;
        return { status: 503, body: new Uint8Array(0) };
      }
      return null;
    };
    await expect(src.sync()).rejects.toMatchObject({ kind: "Busy" });
    expect(src.state.leafCount).toBe(0);
    const mark = node.reads.length;
    await src.fetchNotes([5]);
    await src.fetchNotes(OWNED);
    expect(node.reads.slice(mark)).toEqual([]);
  });

  it("a read below the count of a sync that stopped between feed segments waits for the sync to complete", async () => {
    const truth = new Pool(70_000, new Map());
    const owned = [5, 66_000, 69_000];
    const { node, src } = rig(truth);
    await src.sync();
    await src.fetchNotes(owned);
    armRoot(node, 1);
    const lie = node.lie!;
    let syncs = 0;
    node.lie = async (path) => {
      // the rewound sync's second segment is refused once
      if (path.startsWith("/howl/v1/sync") && ++syncs === 3) return { status: 503, body: new Uint8Array(0) };
      return lie(path);
    };
    await expect(src.sync()).rejects.toMatchObject({ kind: "Busy" });
    expect([src.state.leafCount, src.feed.length]).toEqual([70_000, 65_536]);
    const mark = node.reads.length;
    const records = await src.fetchNotes(owned);
    expect(node.reads.slice(mark)).toEqual([]);
    records.forEach((r, i) => expect(hex(r.commitmentPrefix)).toBe(prefixAt(truth, owned[i]!)));
  });
});
