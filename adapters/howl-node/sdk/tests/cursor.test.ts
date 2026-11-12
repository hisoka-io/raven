// The sync cursor: rounded to the granule at every count, at a bounded cost to an
// idle sync, with the reorganisation and lagging-node checks still in force.
import { describe, expect, it } from "vitest";
import { bigintField, RavenHowlSource, SYNC_CURSOR_GRANULE, type HowlTransport } from "../src/index.js";
import { hex, wasm } from "./helpers/fixture.js";
import { CHAIN_BLOCK, Pool, served } from "./helpers/pool.js";

describe("the sync cursor", () => {
  /** A source following whichever pool `at` names, recording paths and bytes down. */
  function following(start: Pool) {
    const state = { at: start, paths: [] as string[], down: [] as number[] };
    const transport: HowlTransport = {
      get: async (path) => {
        const ex = await served(state.at, new Set()).get(path);
        state.paths.push(path);
        state.down.push(ex.body.length);
        return ex;
      },
      post: async (path) => {
        throw new Error(`unexpected POST ${path}`);
      },
    };
    return { state, src: new RavenHowlSource({ transport, wasm, field: bigintField }) };
  }

  it("names a rounded count, and an idle sync costs at most the granule's rows and leaves", async () => {
    const counts = [1, 63, 64, 65, 1_023, 1_024, 1_025, 1_100, 2_047, 2_111, 3_000];
    const pools: Pool[] = [];
    for (const c of counts) pools.push(new Pool(c, new Map(), pools[pools.length - 1]));
    const { state, src } = following(pools[0]!);
    for (const pool of pools) {
      const held = src.state.leafCount;
      state.at = pool;
      const grown = await src.sync();
      expect([grown.leafCount, grown.rowsAdded, hex(grown.root)]).toEqual([pool.count, pool.count - held, hex(pool.root)]);
      const mark = state.paths.length;
      const idle = await src.sync();
      expect(idle.rowsAdded).toBe(0);
      for (const path of state.paths) {
        const m = /\/sync\?since=(\d+)&upper=\d+(?:&held=(\d+))?$/.exec(path);
        if (m === null) continue; // a block read
        expect(Number(m[1]) % SYNC_CURSOR_GRANULE, path).toBe(0);
        expect(Number(m[2] ?? 0) % SYNC_CURSOR_GRANULE, path).toBe(0);
      }
      const extra = state.down[mark]! - (56 + 16 + 16 + 8);
      expect(extra).toBe((pool.count % SYNC_CURSOR_GRANULE) * (6 + 32));
      expect(extra).toBeLessThanOrEqual(2_394);
      expect(hex(src.snapshot().rows)).toBe(hex(pool.rows));
    }
  });

  it("rows below the cursor that the node now serves otherwise are dropped and read again", async () => {
    const before = new Pool(1_100, new Map());
    const { state, src } = following(before);
    await src.sync();
    const tag = new Uint8Array(32).fill(5);
    // the same leaves and root, one feed row under the held count changed
    state.at = new Pool(1_100, new Map([[1_090, tag.slice(26)]]), before);
    const result = await src.sync();
    expect([result.rewoundTo, result.leafCount]).toEqual([1_024, 1_100]);
    expect(hex(src.snapshot().rows)).toBe(hex(state.at.rows));
    expect(src.matches([bigintField.fromBytes(tag)]).map((m) => m.position)).toEqual([1_090]);
  });

  it("a node behind the held count that the rounded cursor lets answer is refused as stale", async () => {
    const ahead = new Pool(1_100, new Map());
    const { state, src } = following(ahead);
    await src.sync();
    // a lagging replica: fewer leaves, an older chain block and the held tree's root at its count
    const lagging = new Pool(1_090, new Map());
    lagging.leaves.set(ahead.leaves.subarray(0, 1_090 * 32));
    const behind = new Pool(1_090, new Map(), lagging);
    const slow: HowlTransport = {
      get: async (path) => {
        const ex = await served(behind, new Set()).get(path);
        // older chain block in the header
        const body = ex.body.slice();
        new DataView(body.buffer).setBigUint64(16, BigInt(CHAIN_BLOCK - 1), false);
        state.paths.push(path);
        return { ...ex, body };
      },
      post: async (path) => {
        throw new Error(`unexpected POST ${path}`);
      },
    };
    const resumed = new RavenHowlSource({ transport: slow, wasm, field: bigintField, snapshot: src.snapshot() });
    await expect(resumed.sync()).rejects.toMatchObject({ kind: "Stale", state: { leafCount: 1_090 } });
    expect(resumed.state.leafCount).toBe(1_100);
  });
});
