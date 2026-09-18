import { buildFanoutCoverPlan, recoverRealFanoutResponses, type FanoutCoverPlan } from "./fanout-cover";
import { decodeShardGeometry } from "./client-pir";
import { uniformRandomBelow } from "./crypto-random";
import { RavenError } from "./errors";

/** Padded global query targets plus the private map restoring caller order. */
export interface PaddedQueryPlan {
  readonly wireTargets: readonly number[];
}

const issuedPlans = new WeakMap<PaddedQueryPlan, FanoutCoverPlan>();

/** Build a dyadic, distinct-shard cover plan from validated shard geometry. */
export function buildPaddedQueryPlan(
  realTargets: readonly number[],
  shardConfigBincode: Uint8Array,
): PaddedQueryPlan {
  const geometry = decodeShardGeometry(shardConfigBincode);
  if (realTargets.length === 0) {
    throw RavenError.invalidQuery("batch cover: real target list must not be empty");
  }
  const realShardIds = realTargets.map((target, position) => {
    if (!Number.isSafeInteger(target) || target < 0) {
      throw RavenError.invalidQuery(
        `batch cover: target at position ${position} must be a non-negative integer`,
      );
    }
    const shardId = Math.floor(target / geometry.entriesPerShard);
    if (shardId >= geometry.shardCount) {
      throw RavenError.invalidQuery(
        `batch cover: target ${target} is out of range for ${geometry.shardCount} shards`,
      );
    }
    return shardId;
  });
  const fanout = buildFanoutCoverPlan(realShardIds, geometry.shardCount, 32);
  const realTargetBySlot = new Map(
    fanout.responseSlotByRealPosition.map((slot, position) => [slot, realTargets[position]]),
  );
  const wireTargets = fanout.wireShardIds.map((shardId, slot) => {
    const realTarget = realTargetBySlot.get(slot);
    if (realTarget !== undefined) return realTarget;
    return shardId * geometry.entriesPerShard + uniformRandomBelow(geometry.entriesPerShard);
  });
  const plan: PaddedQueryPlan = Object.freeze({ wireTargets: Object.freeze(wireTargets) });
  issuedPlans.set(plan, fanout);
  return plan;
}

/** Select real responses from a plan and restore the caller's target order. */
export function recoverRealQueryResponses<T>(
  plan: PaddedQueryPlan,
  wireResponses: readonly T[],
): T[] {
  const fanout = issuedPlans.get(plan);
  if (!fanout) {
    throw RavenError.invalidQuery("batch cover: plan was not issued by buildPaddedQueryPlan");
  }
  return recoverRealFanoutResponses(fanout, wireResponses);
}
