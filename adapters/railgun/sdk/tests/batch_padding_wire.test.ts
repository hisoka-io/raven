// The batch a warm cache produces is padded to a ladder step before it leaves
// the SDK, so the wire never publishes the exact cache-miss count. Without the
// padding the second call below sends 3 slots, which the server refuses.

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { RavenPOINodeInterface, isOnLadder } from "../src/index";

import { startMockServer, type MockServer } from "./helpers/mock_server";
import { encodeBatchResponse, encodedBatchCount, stubCtx } from "./helpers/auth_path_stub";

const TOKEN = "test-token-padded-long-enough-1234";



/** Batch route echoing exactly as many 32 B node hashes as the request asked for. */
function mountEchoingBatchRoute(server: MockServer): void {
  server.route(
    (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
    (_req, body, res) => {
      // Shared encoder, (epoch=0xab, slot) node convention; one writer for the wire shape.
      const out = encodeBatchResponse(0xab, encodedBatchCount(body));
      res.writeHead(200, {
        "content-type": "application/octet-stream",
        "x-raven-epoch": "1",
        "x-raven-schema-version": "3",
      });
      res.end(Buffer.from(out));
      return true;
    },
  );
}

describe("batch bodies leaving the SDK are padded to a ladder step", () => {
  let server: MockServer;
  beforeAll(async () => {
    server = await startMockServer();
    mountEchoingBatchRoute(server);
  });
  afterAll(async () => {
    await server.close();
  });

  it("pads a 3-miss warm-cache batch up to 4 slots", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([["t3CommitTree:0", stubCtx()]]),
    });

    await sdk.getMerkleProof(0, 1234);
    const cold = sdk.lastWireRequests();
    expect(cold).toHaveLength(1);
    expect(encodedBatchCount(cold[0].body)).toBe(16);

    // 1234 ^ 0b111 shares every sibling above level 2, so exactly 3 levels miss.
    sdk.resetWireCapture();
    await sdk.getMerkleProof(0, 1234 ^ 0b111);
    const warm = sdk.lastWireRequests();
    expect(warm).toHaveLength(1);
    const sent = encodedBatchCount(warm[0].body);
    expect(isOnLadder(sent)).toBe(true);
    expect(sent).toBe(4);
  });

  it("keeps every batch length on the ladder across a walk of nearby leaves", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([["t3CommitTree:0", stubCtx()]]),
    });
    for (const leaf of [4096, 4097, 4099, 4103, 4111, 4127, 4159, 4223]) {
      sdk.resetWireCapture();
      await sdk.getMerkleProof(0, leaf);
      for (const wire of sdk.lastWireRequests()) {
        const sent = encodedBatchCount(wire.body);
        expect(isOnLadder(sent)).toBe(true);
      }
    }
  });
});
