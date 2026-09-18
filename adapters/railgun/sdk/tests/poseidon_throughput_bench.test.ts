import { describe, expect, it } from "vitest";

import { hashLeftRight } from "../src/poseidon";

const RUN_BENCH = process.env.RAVEN_POSEIDON_THROUGHPUT_BENCH === "1";
const WARMUP_HASHES = 1_000;
const BATCHES = 20;
const HASHES_PER_BATCH = 1_000;

function word(value: number): string {
  return value.toString(16).padStart(64, "0");
}

function drive(count: number, start: number): string {
  let accumulator = word(start + 1);
  for (let index = 0; index < count; index += 1) {
    accumulator = hashLeftRight(accumulator, word(start + index + 2));
  }
  return accumulator;
}

function percentile(sorted: readonly number[], fraction: number): number {
  return sorted[Math.floor((sorted.length - 1) * fraction)] ?? 0;
}

describe.runIf(RUN_BENCH)("Poseidon-2 BN254 wasm throughput", () => {
  it("reports hashes per second with warmup and batch spread", () => {
    drive(WARMUP_HASHES, 0);
    const rates: number[] = [];
    let witness = "";
    for (let batch = 0; batch < BATCHES; batch += 1) {
      const started = performance.now();
      witness = drive(HASHES_PER_BATCH, (batch + 1) * HASHES_PER_BATCH);
      const elapsedSeconds = (performance.now() - started) / 1_000;
      rates.push(HASHES_PER_BATCH / elapsedSeconds);
    }
    rates.sort((left, right) => left - right);
    const mean = rates.reduce((sum, rate) => sum + rate, 0) / rates.length;
    const summary = {
      warmupHashes: WARMUP_HASHES,
      batches: BATCHES,
      hashesPerBatch: HASHES_PER_BATCH,
      totalMeasuredHashes: BATCHES * HASHES_PER_BATCH,
      min: rates[0],
      p05: percentile(rates, 0.05),
      median: percentile(rates, 0.5),
      p95: percentile(rates, 0.95),
      max: rates.at(-1),
      mean,
      witness,
    };
    console.info(JSON.stringify(summary));
    expect(witness).toBe("05b8340b1ba9680d0013801297f37852991ab4341f61a12c60d6405fb9b78812");
    expect(summary.median).toBeGreaterThan(0);
  });
});
