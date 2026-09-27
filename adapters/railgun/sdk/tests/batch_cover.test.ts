// `SeededClientQuery.shard_id` is cleartext, so the node counts the distinct shards a batch
// touches. A pad that re-queries a real target touches no new shard, so that count would be the
// real count the ladder exists to hide: three lookups padded to four would read as three shards.
// Every assertion here drives the shipped plan, and the wire half drives it through the interface.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { RavenPOINodeInterface, paddedBatchLength, type ClientPirContext } from "../src/index";
import {
  authPathQueryLevels,
  buildPaddedQueryPlan,
  recoverRealQueryResponses,
} from "../src/batch-cover";
import { authPathOf, encodeBatchResponse, stubCtx } from "./helpers/auth_path_stub";
import { startMockServer, type MockServer } from "./helpers/mock_server";
import {
  batchTargets,
  commitmentAt,
  mountStatusRows,
  targetNamingCtx,
  type MockList,
} from "./helpers/prefix_channel";
import { namedBatchTargets } from "./helpers/private_wire";
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
  function statusCtx(): ClientPirContext {
    return { ...targetNamingCtx(), shardConfigBincode: shardConfigBincode(ROWS) };
  }

  describe("T1 status", () => {
    // One commitment at the start of every shard, so k lookups can sit in k distinct shards.
    const list: MockList = {
      commitments: Array.from({ length: ROWS }, (_unused, row) => commitmentAt(row)),
    };
    const rowOf = new Map(list.commitments.map((bc, row) => [bc, row]));
    let server: MockServer;
    beforeAll(async () => {
      server = await startMockServer();
      mountStatusRows(server, list, () => 0);
    });
    afterEach(() => {
      server.requests.length = 0;
    });
    afterAll(async () => {
      await server.close();
    });

    function sdk(): RavenPOINodeInterface {
      return new RavenPOINodeInterface({
        endpoint: server.url,
        bearerToken: TOKEN,
        useClientPir: true,
        clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, statusCtx()]]),
        bcToIdxMaps: new Map([[LIST_KEY_HEX, rowOf]]),
      });
    }

    for (const k of [1, 2, 3, 5, 9, 17]) {
      it(`k=${k} lookups in ${k} shards touch ${paddedBatchLength(k)} shards`, async () => {
        const rows = distinctShardRows(k);
        const got = await sdk().getPOIsPerList(
          [LIST_KEY_HEX],
          rows.map((row) => ({ blindedCommitment: list.commitments[row], type: "Shield" })),
        );
        for (const row of rows) expect(got[list.commitments[row]][LIST_KEY_HEX]).toBe("Valid");
        const [batch] = server.requests.filter((request) => request.url.endsWith("/batch"));
        expect(distinctShards(batchTargets(batch.body))).toBe(paddedBatchLength(k));
      });
    }

    it("an all-absent lookup sends a cover spread over the rows held, not row 0", async () => {
      const shards = new Set<number>();
      for (let trial = 0; trial < 40; trial += 1) {
        await sdk()
          .getPOIsPerList([LIST_KEY_HEX], [{ blindedCommitment: "77".repeat(32), type: "Shield" }])
          .catch(() => undefined);
        const batches = server.requests.filter((request) => request.url.endsWith("/batch"));
        const [target] = batchTargets(batches[batches.length - 1].body);
        shards.add(Math.floor(target / PER_SHARD));
      }
      expect(shards.size).toBeGreaterThan(1);
    });
  });

  describe("T3 auth path", () => {
    let server: MockServer;
    afterAll(async () => {
      await server.close();
    });
    beforeAll(async () => {
      server = await startMockServer();
      server.route(
        (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
        (_req, body, res) => {
          res.writeHead(200, {
            "content-type": "application/octet-stream",
            "x-raven-epoch": "1",
            "x-raven-schema-version": "8",
          });
          res.end(Buffer.from(encodeBatchResponse(1, body)));
          return true;
        },
      );
    });

    it("a cold path of sixteen levels still returns every level in order", async () => {
      const sdk = new RavenPOINodeInterface({
        endpoint: server.url,
        bearerToken: TOKEN,
        useClientPir: true,
        clientPirContexts: new Map([["t3CommitTree:0", stubCtx()]]),
      });
      const path = authPathOf(await sdk.getMerkleProof(0, 1234));
      expect(path.elements.map((element) => Number.parseInt(element.slice(62), 16))).toEqual(
        Array.from({ length: 16 }, (_unused, level) => level),
      );
      const [batch] = server.requests.filter((request) => request.url.endsWith("/batch"));
      expect(namedBatchTargets(batch.body)).toHaveLength(16);
    });

    /** Per-shard slot counts, sorted: the whole cleartext shard picture a batch gives away. */
    function shardProfile(targets: readonly number[]): number[] {
      const perShard = new Map<number, number>();
      for (const target of targets) {
        const shard = Math.floor(target / PER_SHARD);
        perShard.set(shard, (perShard.get(shard) ?? 0) + 1);
      }
      return [...perShard.values()].sort((a, b) => a - b);
    }

    // Levels 6 and up of a commit-tree path share one shard, so covers aimed away from the real
    // shards would leave the count of upper-level misses readable from the shard picture.
    it("a warm path's shard picture depends on the ladder step alone, not the miss count", async () => {
      const LEAF = 1234;
      const byStep = new Map<number, Set<string>>();
      for (let misses = 1; misses <= 16; misses += 1) {
        const sdk = new RavenPOINodeInterface({
          endpoint: server.url,
          bearerToken: TOKEN,
          useClientPir: true,
          clientPirContexts: new Map([["t3CommitTree:0", stubCtx()]]),
        });
        await sdk.getMerkleProof(0, LEAF);
        // Flipping bit `misses - 1` changes the sibling at exactly levels 0..misses-1.
        const other = LEAF ^ (1 << (misses - 1));
        const path = authPathOf(await sdk.getMerkleProof(0, other));
        expect(path.elements.map((element) => Number.parseInt(element.slice(62), 16))).toEqual(
          Array.from({ length: 16 }, (_unused, level) => level),
        );
        const batches = server.requests.filter((request) => request.url.endsWith("/batch"));
        const targets = namedBatchTargets(batches[batches.length - 1].body);
        const step = paddedBatchLength(misses);
        expect(targets).toHaveLength(step);
        const seen = byStep.get(step) ?? new Set<string>();
        seen.add(JSON.stringify(shardProfile(targets)));
        byStep.set(step, seen);
      }
      for (const [step, profiles] of byStep) {
        expect([...profiles], `ladder step ${step}`).toHaveLength(1);
      }
      expect(JSON.parse([...(byStep.get(16) ?? [])][0])).toContain(10);
    });
  });
});

describe("auth-path level selection", () => {
  it("fetches the bottom levels up to the step covering the highest miss", () => {
    expect(authPathQueryLevels([0, 1, 2], 16)).toEqual([0, 1, 2, 3]);
    expect(authPathQueryLevels([7], 16)).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
    expect(authPathQueryLevels([15], 16)).toHaveLength(16);
    expect(authPathQueryLevels([], 16)).toHaveLength(16);
  });

  it("refuses a level outside the path", () => {
    expect(() => authPathQueryLevels([16], 16)).toThrow(/not a level/);
    expect(() => authPathQueryLevels([-1], 16)).toThrow(/not a level/);
    expect(() => authPathQueryLevels([0], 0)).toThrow(/path depth/);
  });
});
