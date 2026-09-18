import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  BATCH_SIZE_LADDER,
  MAX_BATCH_SIZE,
  isOnLadder,
  paddedBatchLength,
} from "../src/batch-ladder";
import { RavenPOINodeInterface } from "../src/index";
import { encodeBatchResponse, encodedBatchCount, stubCtx, TOKEN } from "./helpers/auth_path_stub";
import { startMockServer } from "./helpers/mock_server";

const FIXTURES_DIR = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

interface BatchCapacityEvidence {
  readonly serializedQueryBytes: number;
  readonly batchFrameBytes: number;
  readonly defaultBodyCapBytes: number;
}

const capacityEvidence = JSON.parse(
  readFileSync(join(FIXTURES_DIR, "production_batch_capacity.json"), "utf8"),
) as BatchCapacityEvidence;

function productionHandledQuery(): Uint8Array {
  const encoded = readFileSync(join(FIXTURES_DIR, "production_handled_query.hex"), "utf8").trim();
  if (encoded.length % 2 !== 0 || !/^[0-9a-f]+$/.test(encoded)) {
    throw new Error("production handled-query fixture must be lowercase whole-byte hex");
  }
  return new Uint8Array(Buffer.from(encoded, "hex"));
}

describe("batch size ladder", () => {
  it("matches the Rust ladder the server enforces", () => {
    expect([...BATCH_SIZE_LADDER]).toEqual([1, 2, 4, 8, 16, 32]);
    expect(BATCH_SIZE_LADDER[BATCH_SIZE_LADDER.length - 1]).toBe(MAX_BATCH_SIZE);
  });

  it("pads every count in range onto a step without shrinking", () => {
    for (let n = 1; n <= MAX_BATCH_SIZE; n += 1) {
      const padded = paddedBatchLength(n);
      expect(isOnLadder(padded)).toBe(true);
      expect(padded).toBeGreaterThanOrEqual(n);
      expect(padded).toBeLessThan(n * 2);
    }
  });

  it("names the step an off-ladder count should have used", () => {
    expect(paddedBatchLength(3)).toBe(4);
    expect(paddedBatchLength(5)).toBe(8);
    expect(paddedBatchLength(9)).toBe(16);
    expect(paddedBatchLength(17)).toBe(32);
  });

  it("derives the dyadic boundary from the production query, frame, and body cap", async () => {
    const queryBytes = productionHandledQuery();
    const server = await startMockServer();
    server.route(
      (request) => /^\/v1\/instance\/[^/]+\/batch$/.test(request.url ?? ""),
      (_request, body, response) => {
        response.writeHead(200, {
          "content-type": "application/octet-stream",
          "x-raven-epoch": "1",
          "x-raven-schema-version": "6",
        });
        response.end(Buffer.from(encodeBatchResponse(1, encodedBatchCount(body))));
        return true;
      },
    );

    try {
      const sdk = new RavenPOINodeInterface({
        endpoint: server.url,
        bearerToken: TOKEN,
        useClientPir: true,
        clientPirContexts: new Map([["t3CommitTree:0", stubCtx(queryBytes)]]),
      });
      await sdk.getMerkleProof(0, 31_415);
      const [wire] = sdk.lastWireRequests();
      const queryCount = encodedBatchCount(wire.body);
      const frameBytes = wire.body.length - queryCount * queryBytes.length;
      const bodyCapBytes = capacityEvidence.defaultBodyCapBytes;
      const rawCapacity = Math.floor((bodyCapBytes - frameBytes) / queryBytes.length);

      expect(queryBytes.length).toBe(capacityEvidence.serializedQueryBytes);
      expect(frameBytes).toBe(capacityEvidence.batchFrameBytes);
      expect(queryBytes.length).toBe(15_491);
      expect(frameBytes).toBe(10);
      expect(rawCapacity).toBe(541);
      expect(frameBytes + rawCapacity * queryBytes.length).toBe(8_380_641);
      expect(frameBytes + (rawCapacity + 1) * queryBytes.length).toBe(8_396_132);
      expect(frameBytes + rawCapacity * queryBytes.length).toBeLessThanOrEqual(bodyCapBytes);
      expect(frameBytes + (rawCapacity + 1) * queryBytes.length).toBeGreaterThan(bodyCapBytes);
      expect(paddedBatchLength(257, rawCapacity)).toBe(512);
      expect(isOnLadder(512, rawCapacity)).toBe(true);
      expect(isOnLadder(rawCapacity, rawCapacity)).toBe(false);
      expect(() => paddedBatchLength(513, rawCapacity)).toThrow(/541.*512.*split/);
    } finally {
      await server.close();
    }
  });

  it("does not round large safe integers onto a power-of-two step", () => {
    expect(isOnLadder(2 ** 50, Number.MAX_SAFE_INTEGER)).toBe(true);
    expect(isOnLadder(2 ** 50 - 1, Number.MAX_SAFE_INTEGER)).toBe(false);
    expect(isOnLadder(2 ** 52 - 1, Number.MAX_SAFE_INTEGER)).toBe(false);
    expect(isOnLadder(2 ** 52 + 1, Number.MAX_SAFE_INTEGER)).toBe(false);
    expect(isOnLadder(Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER)).toBe(false);
  });

  it("refuses an empty batch and anything past the top step", () => {
    expect(() => paddedBatchLength(0)).toThrow(RangeError);
    expect(() => paddedBatchLength(-1)).toThrow(RangeError);
    expect(() => paddedBatchLength(1.5)).toThrow(RangeError);
    expect(() => paddedBatchLength(MAX_BATCH_SIZE + 1)).toThrow(/split into several batches/);
  });
});
