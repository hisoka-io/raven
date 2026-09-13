import { isOnLadder, MAX_BATCH_SIZE, paddedBatchLength } from "./batch-ladder";
import { uniformRandomBelow } from "./crypto-random";
import { RavenError } from "./errors";

const U32_MAX = 0xffff_ffff;
const U32_RANGE = 0x1_0000_0000;
const issuedPlans = new WeakSet<object>();

/** Padded fanout wire order and the map restoring real responses to caller order. */
export interface FanoutCoverPlan {
  readonly wireShardIds: readonly number[];
  readonly responseSlotByRealPosition: readonly number[];
  readonly nominalShardId: number;
}

interface FanoutSlot {
  readonly shardId: number;
  readonly realPosition: number | null;
}

function invalid(message: string): never {
  throw RavenError.invalidQuery(`fanout cover: ${message}`);
}

function validateShardId(shardId: number, position: number, shardCount: number): void {
  if (!Number.isSafeInteger(shardId) || shardId < 0) {
    invalid(`shard id at position ${position} must be a non-negative integer, got ${shardId}`);
  }
  if (shardId > U32_MAX || shardId >= shardCount) {
    invalid(
      `shard id ${shardId} at position ${position} is out of range for ${shardCount} shards`,
    );
  }
}

function validatePlan(plan: FanoutCoverPlan): void {
  if (!issuedPlans.has(plan)) invalid("plan must be issued by buildFanoutCoverPlan");
  if (plan.wireShardIds.length === 0) invalid("wire shard list must not be empty");
  if (!isOnLadder(plan.wireShardIds.length)) {
    invalid(`wire shard list length ${plan.wireShardIds.length} is not on the batch ladder`);
  }
  if (plan.wireShardIds.length > MAX_BATCH_SIZE) {
    invalid(
      `wire shard list length ${plan.wireShardIds.length} exceeds adapter cap ${MAX_BATCH_SIZE}`,
    );
  }
  if (plan.responseSlotByRealPosition.length === 0) {
    invalid("permutation map must contain at least one real response");
  }
  for (const [position, shardId] of plan.wireShardIds.entries()) {
    if (!Number.isSafeInteger(shardId) || shardId < 0 || shardId > U32_MAX) {
      invalid(`wire shard id at position ${position} is not a u32: ${shardId}`);
    }
  }
  const seen = new Set<number>();
  for (const [realPosition, wireSlot] of plan.responseSlotByRealPosition.entries()) {
    if (
      !Number.isSafeInteger(wireSlot) ||
      wireSlot < 0 ||
      wireSlot >= plan.wireShardIds.length ||
      seen.has(wireSlot)
    ) {
      invalid(`permutation map is invalid at real position ${realPosition}: wire slot ${wireSlot}`);
    }
    seen.add(wireSlot);
  }
  if (!plan.wireShardIds.includes(plan.nominalShardId)) {
    invalid(`nominal shard ${plan.nominalShardId} is absent from the wire shard list`);
  }
  const realSlots = new Set(plan.responseSlotByRealPosition);
  const slotsByShard = new Map<number, number[]>();
  for (const [wireSlot, shardId] of plan.wireShardIds.entries()) {
    const positions = slotsByShard.get(shardId) ?? [];
    positions.push(wireSlot);
    slotsByShard.set(shardId, positions);
  }
  for (const [shardId, positions] of slotsByShard) {
    if (positions.length > 1 && positions.some((wireSlot) => !realSlots.has(wireSlot))) {
      invalid(`duplicate cover shard ${shardId} appears outside caller-real positions`);
    }
  }
}

function availableShardAtRank(rank: number, excluded: ReadonlySet<number>): number {
  let shardId = rank;
  const orderedExcluded = Array.from(excluded).sort((left, right) => left - right);
  for (const excludedShard of orderedExcluded) {
    if (excludedShard > shardId) break;
    shardId += 1;
  }
  return shardId;
}

/** Pad and uniformly shuffle a fanout shard list without inspecting query or response bytes. */
export function buildFanoutCoverPlan(
  realShardIds: readonly number[],
  shardCount: number,
  maxFanoutShards: number,
): FanoutCoverPlan {
  if (realShardIds.length === 0) invalid("real shard list must not be empty");
  if (!Number.isSafeInteger(shardCount) || shardCount < 1 || shardCount > U32_RANGE) {
    invalid(`shard count must be an integer in [1, ${U32_RANGE}], got ${shardCount}`);
  }
  if (!Number.isSafeInteger(maxFanoutShards) || maxFanoutShards < 1) {
    invalid(`max fanout shards must be a positive integer, got ${maxFanoutShards}`);
  }
  if (maxFanoutShards > MAX_BATCH_SIZE) {
    invalid(`max fanout shards ${maxFanoutShards} exceeds adapter cap ${MAX_BATCH_SIZE}`);
  }
  if (realShardIds.length > maxFanoutShards) {
    invalid(
      `real shard list length ${realShardIds.length} exceeds max fanout shards ${maxFanoutShards}`,
    );
  }
  for (const [position, shardId] of realShardIds.entries()) {
    validateShardId(shardId, position, shardCount);
  }

  let paddedLength: number;
  try {
    paddedLength = paddedBatchLength(realShardIds.length);
  } catch (cause) {
    invalid(`cannot pad ${realShardIds.length} real shards: ${String(cause)}`);
  }
  if (paddedLength > maxFanoutShards) {
    invalid(
      `padded length ${paddedLength} exceeds max fanout shards ${maxFanoutShards}; ` +
        "cover is insufficient",
    );
  }

  const slots: FanoutSlot[] = realShardIds.map((shardId, realPosition) => ({
    shardId,
    realPosition,
  }));
  const excludedShards = new Set(realShardIds);
  const coversNeeded = paddedLength - slots.length;
  const availableCovers = shardCount - excludedShards.size;
  if (availableCovers < coversNeeded) {
    invalid(
      `insufficient distinct cover shards: need ${coversNeeded}, have ${availableCovers} ` +
        `outside ${excludedShards.size} real shards`,
    );
  }
  while (slots.length < paddedLength) {
    const available = shardCount - excludedShards.size;
    const rank = uniformRandomBelow(available);
    const shardId = availableShardAtRank(rank, excludedShards);
    excludedShards.add(shardId);
    slots.push({ shardId, realPosition: null });
  }
  for (let right = slots.length - 1; right > 0; right -= 1) {
    const left = uniformRandomBelow(right + 1);
    [slots[left], slots[right]] = [slots[right], slots[left]];
  }

  const responseSlotByRealPosition = new Array<number>(realShardIds.length);
  const wireShardIds = slots.map((slot, wireSlot) => {
    if (slot.realPosition !== null) responseSlotByRealPosition[slot.realPosition] = wireSlot;
    return slot.shardId;
  });
  const nominalShardId = wireShardIds[uniformRandomBelow(wireShardIds.length)];
  const plan: FanoutCoverPlan = {
    wireShardIds: Object.freeze(wireShardIds),
    responseSlotByRealPosition: Object.freeze(responseSlotByRealPosition),
    nominalShardId,
  };
  issuedPlans.add(plan);
  validatePlan(plan);
  return Object.freeze(plan);
}

/** Select real fanout responses and restore the caller's shard order. */
export function recoverRealFanoutResponses<T>(
  plan: FanoutCoverPlan,
  wireResponses: readonly T[],
): T[] {
  validatePlan(plan);
  if (wireResponses.length !== plan.wireShardIds.length) {
    throw RavenError.batchMismatch(
      `fanout cover: expected ${plan.wireShardIds.length} responses, got ${wireResponses.length}`,
    );
  }
  return plan.responseSlotByRealPosition.map((wireSlot) => wireResponses[wireSlot]);
}
