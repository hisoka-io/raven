/**
 * Fixed-size ladder for batched PIR requests: an unpadded batch publishes the
 * wallet's exact cache-miss count. Must stay in step with the Rust ladder in
 * `raven_railgun_core::batch_ladder`; the server refuses off-ladder lengths.
 */

import { RavenError } from "./errors";

/** Permitted batch sizes, ascending. */
export const BATCH_SIZE_LADDER: readonly number[] = [1, 2, 4, 8, 16, 32];

/** Largest batch the ladder admits. */
export const MAX_BATCH_SIZE = 32;

/** Whether `len` is a ladder step. */
export function isOnLadder(len: number): boolean {
  return BATCH_SIZE_LADDER.includes(len);
}

/**
 * Smallest ladder step fitting `realCount`. Throws above {@link MAX_BATCH_SIZE};
 * callers with more queries split into independently-padded batches.
 */
export function paddedBatchLength(realCount: number): number {
  if (!Number.isInteger(realCount) || realCount < 1) {
    throw new RangeError(
      `batch length ${realCount} must be a positive integer; an empty batch has nothing to pad`,
    );
  }
  const step = BATCH_SIZE_LADDER.find((s) => s >= realCount);
  if (step === undefined) {
    throw new RangeError(
      `batch length ${realCount} exceeds the fixed-size ladder maximum ${MAX_BATCH_SIZE}; ` +
        `split into several batches and pad each`,
    );
  }
  return step;
}

/**
 * Uniform draw below `bound`, rejection-sampled so no residue is favoured.
 *
 * Throws rather than degrading: `SeededClientQuery.shard_id` is unencrypted on the wire,
 * so a pad drawn from a weak or absent CSPRNG is a leak, not a slow path.
 */
function randomBelow(bound: number): number {
  if (!Number.isInteger(bound) || bound <= 0) {
    throw RavenError.invalidQuery(`randomBelow: bound must be a positive integer, got ${bound}`);
  }
  if (bound === 1) return 0;
  const c = globalThis.crypto;
  if (!c || typeof c.getRandomValues !== "function") {
    throw RavenError.invalidQuery(
      "randomBelow: globalThis.crypto.getRandomValues is unavailable; batch padding " +
        "cannot be drawn without a CSPRNG and cycling pads leaks the cache-miss count",
    );
  }
  // Largest multiple of `bound` that fits a u32; draws at or above it are rejected.
  const limit = Math.floor(0x1_0000_0000 / bound) * bound;
  const buf = new Uint32Array(1);
  for (;;) {
    c.getRandomValues(buf);
    const v = buf[0];
    if (v < limit) return v % bound;
  }
}

/**
 * Slot plan for one padded batch: the real slots in order, then pad slots drawn at RANDOM
 * from the real ones.
 *
 * Pads are never cycled. `slot % realSlots.length` makes slot j and slot j+len address the
 * identical global index, so a server reading the cleartext `shard_id` sequence recovers the
 * repeat period and with it the exact cache-miss count - the one quantity the ladder exists
 * to hide. Lives here, exported, so the test exercises the shipped draw rather than a copy.
 */
export function drawPaddedSlots(realSlots: readonly number[]): number[] {
  const padded = paddedBatchLength(realSlots.length);
  return Array.from({ length: padded }, (_unused, slot) =>
    slot < realSlots.length ? realSlots[slot] : realSlots[randomBelow(realSlots.length)],
  );
}
