import { afterEach, describe, expect, it, vi } from "vitest";

import {
  buildPaddedQueryPlan,
  recoverRealQueryResponses,
} from "../src/batch-cover";

function shardConfig(shardBytes: bigint, entryBytes: bigint, totalEntries: bigint): Uint8Array {
  const bytes = new Uint8Array(24);
  const view = new DataView(bytes.buffer);
  view.setBigUint64(0, shardBytes, true);
  view.setBigUint64(8, entryBytes, true);
  view.setBigUint64(16, totalEntries, true);
  return bytes;
}

function installWords(words: readonly number[]): void {
  let next = 0;
  vi.stubGlobal("crypto", {
    getRandomValues: (target: Uint32Array): Uint32Array => {
      if (next >= words.length) throw new Error("test CSPRNG words exhausted");
      target[0] = words[next];
      next += 1;
      return target;
    },
  });
}

describe("padded query cover", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("uses distinct cover shards outside the real set and restores caller response order", () => {
    installWords([0, 0, 0, 0, 0, 0]);
    const plan = buildPaddedQueryPlan(
      [0, 2_048, 4_096],
      shardConfig(65_536n, 32n, 16_384n),
    );
    const wireShards = plan.wireTargets.map((target) => Math.floor(target / 2_048));

    expect(plan.wireTargets).toHaveLength(4);
    expect(new Set(wireShards).size).toBe(4);
    expect(wireShards).toEqual(expect.arrayContaining([0, 1, 2]));
    expect(recoverRealQueryResponses(plan, wireShards)).toEqual([0, 1, 2]);
  });

  it("refuses to claim padding when no distinct cover shard exists", () => {
    installWords([0]);
    expect(() => buildPaddedQueryPlan([0, 1, 2], shardConfig(1n, 1n, 3n))).toThrow(
      /insufficient distinct cover shards/,
    );
  });

  it("refuses a real target outside the validated shard geometry", () => {
    expect(() => buildPaddedQueryPlan([8], shardConfig(4n, 1n, 8n))).toThrow(/out of range/);
  });
});
