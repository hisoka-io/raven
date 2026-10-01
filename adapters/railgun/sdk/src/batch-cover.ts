import { paddedBatchLength } from "./batch-ladder";
import { uniformRandomBelow } from "./crypto-random";
import { RavenError } from "./errors";

/** One padded `/batch` request: every target in wire order, and where each caller target sits. */
export interface PaddedQueryPlan {
  /** Global row indices in wire order, real and cover alike. */
  readonly wireTargets: readonly number[];
  /** Wire slot answering each caller target, in caller order. */
  readonly realSlots: readonly number[];
}

function invalid(message: string): never {
  throw RavenError.invalidQuery(`batch cover: ${message}`);
}

function checkedCount(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    invalid(`${name} must be a positive integer, got ${value}`);
  }
  return value;
}

/** The `rank`-th shard below the populated count that `taken` (ascending) does not hold. */
function freeShardAtRank(rank: number, taken: readonly number[]): number {
  let shard = rank;
  for (const held of taken) {
    if (held > shard) break;
    shard += 1;
  }
  return shard;
}

function insertSorted(sorted: number[], value: number): void {
  let at = 0;
  while (at < sorted.length && sorted[at] < value) at += 1;
  sorted.splice(at, 0, value);
}

/**
 * Pad `realTargets` to a ladder step and shuffle the slots.
 *
 * Covers go to shards no real target occupies, up to min(padded length, populated shards)
 * distinct shards; a cover that fits no free shard goes to a uniform populated shard.
 *
 * Covers address rows below `populatedRows`, since a query into rows the instance never wrote
 * could only be a cover. An empty `realTargets` yields one cover query, so a request goes out
 * even when every lookup was answered locally.
 */
export function buildPaddedQueryPlan(
  realTargets: readonly number[],
  entriesPerShard: number,
  populatedRows: number,
): PaddedQueryPlan {
  checkedCount(entriesPerShard, "entries per shard");
  let rowBound = checkedCount(populatedRows, "populated rows");
  const realShards: number[] = [];
  for (const [position, target] of realTargets.entries()) {
    if (!Number.isSafeInteger(target) || target < 0) {
      invalid(`target at position ${position} must be a non-negative integer, got ${target}`);
    }
    // A target past the stated bound proves the row exists, so the bound was stale.
    rowBound = Math.max(rowBound, target + 1);
    const shard = Math.floor(target / entriesPerShard);
    if (!realShards.includes(shard)) insertSorted(realShards, shard);
  }
  const shardCount = Math.ceil(rowBound / entriesPerShard);
  const padded = realTargets.length === 0 ? 1 : paddedBatchLength(realTargets.length);
  const coverSlots = padded - realTargets.length;
  const distinctCovers = Math.min(coverSlots, Math.min(padded, shardCount) - realShards.length);

  const coverRow = (shard: number): number => {
    const first = shard * entriesPerShard;
    return first + uniformRandomBelow(Math.min(entriesPerShard, rowBound - first));
  };
  const slots: { target: number; realPosition: number | null }[] = realTargets.map(
    (target, realPosition) => ({ target, realPosition }),
  );
  const taken = [...realShards];
  for (let drawn = 0; drawn < distinctCovers; drawn += 1) {
    const shard = freeShardAtRank(uniformRandomBelow(shardCount - taken.length), taken);
    insertSorted(taken, shard);
    slots.push({ target: coverRow(shard), realPosition: null });
  }
  while (slots.length < padded) {
    slots.push({ target: coverRow(uniformRandomBelow(shardCount)), realPosition: null });
  }
  for (let right = slots.length - 1; right > 0; right -= 1) {
    const left = uniformRandomBelow(right + 1);
    [slots[left], slots[right]] = [slots[right], slots[left]];
  }

  const realSlots = new Array<number>(realTargets.length);
  const wireTargets = slots.map(({ target, realPosition }, wireSlot) => {
    if (realPosition !== null) realSlots[realPosition] = wireSlot;
    return target;
  });
  return Object.freeze({
    wireTargets: Object.freeze(wireTargets),
    realSlots: Object.freeze(realSlots),
  });
}

/** Responses for the caller's targets, in caller order. */
export function recoverRealQueryResponses<T>(
  plan: PaddedQueryPlan,
  wireResponses: readonly T[],
): T[] {
  if (wireResponses.length !== plan.wireTargets.length) {
    throw RavenError.batchMismatch(
      `batch cover: expected ${plan.wireTargets.length} responses, got ${wireResponses.length}`,
    );
  }
  return plan.realSlots.map((wireSlot) => wireResponses[wireSlot]);
}
