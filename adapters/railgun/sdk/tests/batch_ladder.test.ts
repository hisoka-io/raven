import { describe, expect, it } from "vitest";

import {
  BATCH_SIZE_LADDER,
  MAX_BATCH_SIZE,
  isOnLadder,
  paddedBatchLength,
} from "../src/batch-ladder";

describe("batch size ladder", () => {
  it("matches the Rust ladder the server enforces", () => {
    expect([...BATCH_SIZE_LADDER]).toEqual([1, 2, 4, 8, 16, 32]);
    expect(BATCH_SIZE_LADDER[BATCH_SIZE_LADDER.length - 1]).toBe(MAX_BATCH_SIZE);
  });

  it("pads every count in range onto a step without shrinking", () => {
    for (let n = 1; n <= MAX_BATCH_SIZE; n += 1) {
      const padded = paddedBatchLength(n);
      expect(isOnLadder(padded)).toBe(true);
      expect(padded).toBeGreaterThanOrEqual(n);
      expect(padded).toBeLessThan(n * 2);
    }
  });

  it("names the step an off-ladder count should have used", () => {
    expect(paddedBatchLength(3)).toBe(4);
    expect(paddedBatchLength(5)).toBe(8);
    expect(paddedBatchLength(9)).toBe(16);
    expect(paddedBatchLength(17)).toBe(32);
  });

  it("refuses an empty batch and anything past the top step", () => {
    expect(() => paddedBatchLength(0)).toThrow(RangeError);
    expect(() => paddedBatchLength(-1)).toThrow(RangeError);
    expect(() => paddedBatchLength(1.5)).toThrow(RangeError);
    expect(() => paddedBatchLength(MAX_BATCH_SIZE + 1)).toThrow(/split into several batches/);
  });
});
