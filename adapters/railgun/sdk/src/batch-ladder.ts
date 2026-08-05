/**
 * Fixed-size ladder for batched PIR requests: an unpadded batch publishes the
 * wallet's exact cache-miss count. Must stay in step with the Rust ladder in
 * `raven_railgun_core::batch_ladder`; the server refuses off-ladder lengths.
 */

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
