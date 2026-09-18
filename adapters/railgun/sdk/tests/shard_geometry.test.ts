import { describe, expect, it } from "vitest";

import { decodeShardGeometry } from "../src/client-pir";

function shardConfig(shardBytes: bigint, entryBytes: bigint, totalEntries: bigint): Uint8Array {
  const bytes = new Uint8Array(24);
  const view = new DataView(bytes.buffer);
  view.setBigUint64(0, shardBytes, true);
  view.setBigUint64(8, entryBytes, true);
  view.setBigUint64(16, totalEntries, true);
  return bytes;
}

describe("ShardConfig geometry", () => {
  it("decodes bincode fields and rounds a partial last shard up", () => {
    expect(decodeShardGeometry(shardConfig(65_536n, 32n, 4_097n))).toEqual({
      entriesPerShard: 2_048,
      shardCount: 3,
    });
  });

  it("refuses malformed, zero and unsafe geometry", () => {
    expect(() => decodeShardGeometry(new Uint8Array(23))).toThrow("24 bytes");
    expect(() => decodeShardGeometry(shardConfig(65_536n, 0n, 4_096n))).toThrow(
      "entry_size_bytes",
    );
    expect(() => decodeShardGeometry(shardConfig(65_537n, 32n, 4_096n))).toThrow(
      "not divisible",
    );
    expect(() =>
      decodeShardGeometry(shardConfig(65_536n, 32n, BigInt(Number.MAX_SAFE_INTEGER) + 1n)),
    ).toThrow("safe integer");
  });
});
