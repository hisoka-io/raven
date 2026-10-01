// Covers fill free shards first, so k lookups in k shards padded to a ladder step touch as many
// shards as the step holds, up to the shard count.
// Every assertion here drives the shipped plan, and the wire half drives it through the interface.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  LEAVES_PER_PPOI_BLOCK,
  RavenPOINodeInterface,
  paddedBatchLength,
  type ClientPirContext,
} from "../src/index";
import { buildPaddedQueryPlan, recoverRealQueryResponses } from "../src/batch-cover";
import { forestConfig } from "./helpers/forest";
import { startMockServer, writeError, type MockServer } from "./helpers/mock_server";
import { PATH10_ROW_BYTES } from "./helpers/path10_row";
import { batchTargets, commitmentAt, targetNamingCtx } from "./helpers/prefix_channel";
import { shardConfigBincode } from "./helpers/shard_config";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "ab".repeat(32);
const PER_SHARD = 2_048;
const SHARDS = 64;
const ROWS = SHARDS * PER_SHARD;

/** `count` rows, each in its own shard, at a random place in it. */
function distinctShardRows(count: number, shards = SHARDS): number[] {
  const picked = new Set<number>();
  while (picked.size < count) picked.add(Math.floor(Math.random() * shards));
  return [...picked].map((shard) => shard * PER_SHARD + Math.floor(Math.random() * PER_SHARD));
}

function distinctShards(targets: readonly number[]): number {
  return new Set(targets.map((target) => Math.floor(target / PER_SHARD))).size;
}

describe("padded query cover", () => {
  it("touches a number of distinct shards fixed by the ladder step, whatever the real count", () => {
    const seen = new Map<number, Set<number>>();
    for (let k = 1; k <= 32; k += 1) {
      for (let trial = 0; trial < 8; trial += 1) {
        const plan = buildPaddedQueryPlan(distinctShardRows(k), PER_SHARD, ROWS);
        const padded = paddedBatchLength(k);
        expect(plan.wireTargets).toHaveLength(padded);
        const counts = seen.get(padded) ?? new Set<number>();
        counts.add(distinctShards(plan.wireTargets));
        seen.set(padded, counts);
      }
    }
    for (const [padded, counts] of seen) {
      expect([...counts], `ladder step ${padded}`).toEqual([padded]);
    }
  });

  it("covers every populated shard, and no more, when the table has fewer than the step", () => {
    const rows = 3 * PER_SHARD - 100;
    for (let k = 1; k <= 32; k += 1) {
      // Round-robin over the three shards: more than three reals must share one.
      const reals = Array.from({ length: k }, (_unused, i) => (i % 3) * PER_SHARD + Math.floor(i / 3));
      const plan = buildPaddedQueryPlan(reals, PER_SHARD, rows);
      expect(distinctShards(plan.wireTargets), `k=${k}`).toBe(Math.min(paddedBatchLength(k), 3));
      for (const target of plan.wireTargets) expect(target).toBeLessThan(rows);
    }
  });

  it("aims covers only at rows the instance holds", () => {
    for (let trial = 0; trial < 200; trial += 1) {
      const plan = buildPaddedQueryPlan([5], PER_SHARD, 10 * PER_SHARD + 7);
      for (const target of plan.wireTargets) expect(target).toBeLessThan(10 * PER_SHARD + 7);
    }
  });

  it("shuffles the real slots rather than leading with them", () => {
    let leading = 0;
    const TRIALS = 200;
    for (let trial = 0; trial < TRIALS; trial += 1) {
      const plan = buildPaddedQueryPlan(distinctShardRows(3), PER_SHARD, ROWS);
      if (plan.realSlots.every((slot, position) => slot === position)) leading += 1;
    }
    // A uniform shuffle of four slots leads with three given reals in order 1 time in 24.
    expect(leading).toBeLessThan(TRIALS / 4);
  });

  it("restores the caller's order from the wire order", () => {
    const reals = distinctShardRows(5);
    const plan = buildPaddedQueryPlan(reals, PER_SHARD, ROWS);
    expect(recoverRealQueryResponses(plan, plan.wireTargets)).toEqual(reals);
    expect(() => recoverRealQueryResponses(plan, plan.wireTargets.slice(1))).toThrow(
      /expected 8 responses/,
    );
  });

  it("sends a lone cover for an empty lookup, spread over the rows held", () => {
    const shards = new Set<number>();
    for (let trial = 0; trial < 200; trial += 1) {
      const plan = buildPaddedQueryPlan([], PER_SHARD, ROWS);
      expect(plan.wireTargets).toHaveLength(1);
      expect(plan.realSlots).toEqual([]);
      shards.add(Math.floor(plan.wireTargets[0] / PER_SHARD));
    }
    expect(shards.size).toBeGreaterThan(1);
  });

  it("refuses a target or geometry that is not a count", () => {
    expect(() => buildPaddedQueryPlan([-1], PER_SHARD, ROWS)).toThrow(/non-negative integer/);
    expect(() => buildPaddedQueryPlan([1], 0, ROWS)).toThrow(/entries per shard/);
    expect(() => buildPaddedQueryPlan([1], PER_SHARD, 0)).toThrow(/populated rows/);
  });
});

describe("padded query cover on the wire", () => {
  // One path instance holds one 65,536-leaf block: 32 shards, so up to 17 lookups can sit in
  // distinct shards and still leave the ladder step room for distinct covers.
  const BLOCK_SHARDS = LEAVES_PER_PPOI_BLOCK / PER_SHARD;
  let server: MockServer;
  beforeAll(async () => {
    server = await startMockServer();
    // The reply is refused; the batch that was sent is what the property is about.
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, _body, res) => {
        writeError(res, 500, "not answered");
        return true;
      },
    );
  });
  afterEach(() => {
    server.requests.length = 0;
  });
  afterAll(async () => {
    await server.close();
  });

  function pathCtx(): ClientPirContext {
    return {
      ...targetNamingCtx(),
      entrySize: PATH10_ROW_BYTES,
      shardConfigBincode: shardConfigBincode(LEAVES_PER_PPOI_BLOCK),
    };
  }

  for (const k of [1, 2, 3, 5, 9, 17]) {
    it(`k=${k} proofs in ${k} shards touch ${paddedBatchLength(k)} shards`, async () => {
      const rows = distinctShardRows(k, BLOCK_SHARDS);
      const bcs = rows.map((row) => commitmentAt(row));
      const sdk = new RavenPOINodeInterface({
        ...forestConfig({
          endpoint: server.url,
          listKeyHex: LIST_KEY_HEX,
          ctx: pathCtx(),
          placed: rows.map((row, at) => [bcs[at], row] as const),
          total: LEAVES_PER_PPOI_BLOCK,
        }),
        bearerToken: TOKEN,
      });
      await expect(sdk.getPOIMerkleProofs(LIST_KEY_HEX, bcs)).rejects.toThrow(/500/);
      const batches = server.requests.filter((request) => request.url.endsWith("/batch"));
      expect(batches).toHaveLength(1);
      const targets = batchTargets(batches[0].body);
      expect(targets).toHaveLength(paddedBatchLength(k));
      expect(distinctShards(targets)).toBe(paddedBatchLength(k));
      expect([...targets].sort((a, b) => a - b)).toEqual(
        expect.arrayContaining([...rows].sort((a, b) => a - b)),
      );
    });
  }
});
