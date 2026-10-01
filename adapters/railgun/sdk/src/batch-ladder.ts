/**
 * Fixed-size ladder for batched PIR requests. Railgun's default policy must stay in step
 * with `raven_railgun_core::batch_ladder`; Raven core owns the generic arithmetic.
 */

/** Permitted batch sizes, ascending. */
export const BATCH_SIZE_LADDER: readonly number[] = [1, 2, 4, 8, 16, 32];

/** Largest batch the ladder admits. */
export const MAX_BATCH_SIZE = 32;

function largestDyadicStep(maximum: number): number {
  let step = 1;
  while (step <= Math.floor(maximum / 2)) step *= 2;
  return step;
}

/** Whether `len` is a dyadic step beneath a slot ceiling. */
export function isOnLadder(len: number, maximum: number = MAX_BATCH_SIZE): boolean {
  if (
    !Number.isSafeInteger(len) ||
    len < 1 ||
    !Number.isSafeInteger(maximum) ||
    maximum < 1 ||
    len > maximum
  ) {
    return false;
  }
  const largestStep = largestDyadicStep(maximum);
  let step = 1;
  while (step < len && step < largestStep) step *= 2;
  return step === len;
}

/**
 * Smallest dyadic step fitting `realCount` beneath `maximum`.
 * The default remains Railgun's current {@link MAX_BATCH_SIZE} policy.
 */
export function paddedBatchLength(
  realCount: number,
  maximum: number = MAX_BATCH_SIZE,
): number {
  if (!Number.isInteger(realCount) || realCount < 1) {
    throw new RangeError(
      `batch length ${realCount} must be a positive integer; an empty batch has nothing to pad`,
    );
  }
  if (!Number.isSafeInteger(maximum) || maximum < 1) {
    throw new RangeError(`batch ladder maximum ${maximum} must admit at least one slot`);
  }
  const largestStep = largestDyadicStep(maximum);
  let step = 1;
  while (step < realCount && step < largestStep) step *= 2;
  if (step < realCount) {
    throw new RangeError(
      `batch length ${realCount} has no dyadic step under slot ceiling ${maximum}; ` +
        `largest step is ${largestStep}, so split into several batches and pad each independently`,
    );
  }
  return step;
}
