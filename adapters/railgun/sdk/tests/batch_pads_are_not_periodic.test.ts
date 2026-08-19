// `SeededClientQuery.shard_id` travels in cleartext, so the batch's shard sequence is
// visible to the server. Cycling pads (`realSlots[slot % len]`) made slot j and slot j+len
// address the identical global index, so the repeat period IS the cache-miss count - the one
// quantity the dyadic ladder exists to hide. Pads must be drawn at random.
//
// Every assertion here drives the SHIPPED `drawPaddedSlots`. A test that defines its own draw
// asserts a property of the test, not of the code that ships.

import { describe, expect, it } from "vitest";

import { drawPaddedSlots, paddedBatchLength } from "../src/batch-ladder";

/** The cyclic draw, kept only so the detector below is a known-answer proof. */
function cyclicPads(realCount: number, padded: number): number[] {
  return Array.from({ length: padded }, (_u, slot) => slot % realCount);
}

/** Smallest p in 1..len-1 with seq[i] === seq[i+p] for every valid i, or null. */
function smallestPeriod(seq: number[]): number | null {
  for (let p = 1; p < seq.length; p += 1) {
    let holds = true;
    for (let i = 0; i + p < seq.length; i += 1) {
      if (seq[i] !== seq[i + p]) {
        holds = false;
        break;
      }
    }
    if (holds) return p;
  }
  return null;
}

/** Real levels 0..n-1, which is the shape the batch path passes in. */
function reals(realCount: number): number[] {
  return Array.from({ length: realCount }, (_u, i) => i);
}

describe("batch pad draw", () => {
  it("the cyclic draw publishes the miss count as its period", () => {
    // The DEFECT, asserted so the detector below is known to work.
    for (const realCount of [3, 5, 9]) {
      const padded = paddedBatchLength(realCount);
      if (padded <= realCount) continue;
      expect(smallestPeriod(cyclicPads(realCount, padded))).toBe(realCount);
    }
  });

  it("the shipped draw does not reproduce itself across calls", () => {
    // THE RED-PROOF. `realSlots[slot % len]` is a pure function of its input, so every call
    // returns the identical sequence; a random draw does not. Deterministic in the direction
    // that matters - a revert fails on the first comparison - and its false-failure
    // probability is 5^-3 per trial over 64 trials, which is nil.
    const input = reals(5);
    const first = drawPaddedSlots(input).join(",");
    let differs = false;
    for (let t = 0; t < 64 && !differs; t += 1) {
      if (drawPaddedSlots(input).join(",") !== first) differs = true;
    }
    expect(differs).toBe(true);
  });

  it("the shipped draw does not publish the miss count as a period", () => {
    // A distribution smoke check, not the gate: uniform pads can coincide by chance, so this
    // bounds how often rather than asserting on one draw. The reproducibility case above is
    // what actually catches a revert.
    for (const realCount of [5, 9]) {
      const padded = paddedBatchLength(realCount);
      if (padded <= realCount) continue;
      let periodic = 0;
      const TRIALS = 400;
      for (let t = 0; t < TRIALS; t += 1) {
        if (smallestPeriod(drawPaddedSlots(reals(realCount))) === realCount) periodic += 1;
      }
      // The cyclic draw is periodic in 400/400. Anything near that is the defect.
      expect(periodic).toBeLessThan(TRIALS / 4);
    }
  });

  it("the batch is exactly a ladder step long", () => {
    for (const realCount of [1, 2, 5, 9, 16]) {
      expect(drawPaddedSlots(reals(realCount))).toHaveLength(paddedBatchLength(realCount));
    }
  });

  it("pads only ever address a real level, so they cost the server a real pass", () => {
    for (const realCount of [1, 2, 5, 9, 16]) {
      for (const level of drawPaddedSlots(reals(realCount))) {
        expect(level).toBeGreaterThanOrEqual(0);
        expect(level).toBeLessThan(realCount);
      }
    }
  });

  it("the real slots keep their order, so the response mapping is unchanged", () => {
    for (const realCount of [1, 3, 9]) {
      const pads = drawPaddedSlots(reals(realCount));
      for (let slot = 0; slot < realCount; slot += 1) {
        expect(pads[slot]).toBe(slot);
      }
    }
  });
});
