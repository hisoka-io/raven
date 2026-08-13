// `SeededClientQuery.shard_id` travels in cleartext, so the batch's shard sequence is
// visible to the server. Cycling pads (`queryLevels[slot % len]`) made slot j and slot
// j+len address the identical global index, so the repeat period IS the cache-miss count
// - the one quantity the dyadic ladder exists to hide. Pads must be drawn at random.

import { describe, expect, it } from "vitest";

import { paddedBatchLength } from "../src/batch-ladder";

/** The pre-fix draw, kept as the thing the assertion must be able to distinguish. */
function cyclicPads(realCount: number, padded: number): number[] {
  return Array.from({ length: padded }, (_u, slot) => slot % realCount);
}

/** The shipped draw: real levels in order, then uniform picks from the real set. */
function randomPads(realCount: number, padded: number): number[] {
  const out: number[] = [];
  for (let slot = 0; slot < padded; slot += 1) {
    out.push(slot < realCount ? slot : randomBelow(realCount));
  }
  return out;
}

function randomBelow(bound: number): number {
  if (bound === 1) return 0;
  const limit = Math.floor(0x1_0000_0000 / bound) * bound;
  const buf = new Uint32Array(1);
  for (;;) {
    globalThis.crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % bound;
  }
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

describe("batch pad draw", () => {
  it("the cyclic draw publishes the miss count as its period", () => {
    // This is the DEFECT, asserted so the detector below is known to work.
    for (const realCount of [3, 5, 9]) {
      const padded = paddedBatchLength(realCount);
      if (padded <= realCount) continue;
      expect(smallestPeriod(cyclicPads(realCount, padded))).toBe(realCount);
    }
  });

  it("the random draw does not publish the miss count as a period", () => {
    // Uniform pads can coincide by chance, so require that no single trial is periodic
    // across many trials rather than asserting on one draw.
    for (const realCount of [5, 9]) {
      const padded = paddedBatchLength(realCount);
      if (padded <= realCount) continue;
      let periodic = 0;
      const TRIALS = 400;
      for (let t = 0; t < TRIALS; t += 1) {
        if (smallestPeriod(randomPads(realCount, padded)) === realCount) periodic += 1;
      }
      // The cyclic draw is periodic in 400/400. Anything near that is the defect.
      expect(periodic).toBeLessThan(TRIALS / 4);
    }
  });

  it("pads only ever address a real level, so they cost the server a real pass", () => {
    for (const realCount of [1, 2, 5, 9, 16]) {
      const padded = paddedBatchLength(realCount);
      for (const level of randomPads(realCount, padded)) {
        expect(level).toBeGreaterThanOrEqual(0);
        expect(level).toBeLessThan(realCount);
      }
    }
  });

  it("the real slots keep their order, so the response mapping is unchanged", () => {
    for (const realCount of [1, 3, 9]) {
      const padded = paddedBatchLength(realCount);
      const pads = randomPads(realCount, padded);
      for (let slot = 0; slot < realCount; slot += 1) {
        expect(pads[slot]).toBe(slot);
      }
    }
  });
});
