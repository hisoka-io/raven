// Cycling pads (`realSlots[slot % len]`) made slot j and slot j+len address the identical
// global index, so the sequence repeated with the real count as its period. Pads must be drawn
// at random.
//
// Every assertion here drives the SHIPPED `buildPaddedQueryPlan`. A test that defines its own
// draw asserts a property of the test, not of the code that ships.

import { describe, expect, it } from "vitest";

import { paddedBatchLength } from "../src/batch-ladder";
import { buildPaddedQueryPlan } from "../src/batch-cover";

const PER_SHARD = 2_048;
const ROWS = 64 * PER_SHARD;

/** The cyclic draw, kept only so the detector below is a known-answer proof. */
function cyclicPads(realCount: number, padded: number): number[] {
  return Array.from({ length: padded }, (_u, slot) => slot % realCount);
}

/** Smallest p in 1..len-1 with seq[i] === seq[i+p] for every valid i, or null. */
function smallestPeriod(seq: readonly number[]): number | null {
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

/** Real rows 0..n-1 of one shard, the shape a cold auth path's lower levels take. */
function reals(realCount: number): number[] {
  return Array.from({ length: realCount }, (_u, i) => i);
}

function wire(realCount: number): readonly number[] {
  return buildPaddedQueryPlan(reals(realCount), PER_SHARD, ROWS).wireTargets;
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
    // `realSlots[slot % len]` is a pure function of its input, so every call returns the
    // identical sequence; a random draw does not. A revert fails on the first comparison.
    const first = wire(5).join(",");
    let differs = false;
    for (let t = 0; t < 64 && !differs; t += 1) {
      if (wire(5).join(",") !== first) differs = true;
    }
    expect(differs).toBe(true);
  });

  it("the shipped draw does not publish the miss count as a period", () => {
    // A distribution smoke check, not the gate: the reproducibility case above is.
    for (const realCount of [5, 9]) {
      const padded = paddedBatchLength(realCount);
      if (padded <= realCount) continue;
      let periodic = 0;
      const TRIALS = 400;
      for (let t = 0; t < TRIALS; t += 1) {
        if (smallestPeriod(wire(realCount)) === realCount) periodic += 1;
      }
      // The cyclic draw is periodic in 400/400. Anything near that is the defect.
      expect(periodic).toBeLessThan(TRIALS / 4);
    }
  });

  it("the batch is exactly a ladder step long", () => {
    for (const realCount of [1, 2, 5, 9, 16]) {
      expect(wire(realCount)).toHaveLength(paddedBatchLength(realCount));
    }
  });

  it("every real row is asked exactly where the plan says", () => {
    for (const realCount of [1, 3, 9]) {
      const plan = buildPaddedQueryPlan(reals(realCount), PER_SHARD, ROWS);
      expect(plan.realSlots.map((slot) => plan.wireTargets[slot])).toEqual(reals(realCount));
      expect(new Set(plan.realSlots).size).toBe(realCount);
    }
  });

  it("pads address rows the instance holds, so they cost the server a real pass", () => {
    for (const realCount of [1, 2, 5, 9, 16]) {
      for (const row of wire(realCount)) {
        expect(row).toBeGreaterThanOrEqual(0);
        expect(row).toBeLessThan(ROWS);
      }
    }
  });
});
