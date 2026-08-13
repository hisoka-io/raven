// A fully-cached auth path must leave the same trace as a cold one. Skipping the batch, or
// sending a shorter one, turns the request itself into an oracle for "this wallet already
// holds every node of that path" - the exact leak the ladder padding exists to prevent.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { ImtCache, RavenPOINodeInterface, isOnLadder } from "../src/index";

import { startMockServer, writeJson, type MockServer } from "./helpers/mock_server";
import {
  TOKEN,
  authPathOf,
  encodeBatchResponse,
  encodedBatchCount,
  stubCtx,
} from "./helpers/auth_path_stub";

const TREE_NUMBER = 0;
const INSTANCE_ID = `commit-tree-${TREE_NUMBER}`;
const LEAF = 1234;
const EPOCH = 7;

interface Adapter {
  batchHits: number;
  statusHits: number;
}

function mountAdapter(server: MockServer): Adapter {
  const adapter: Adapter = { batchHits: 0, statusHits: 0 };
  server.route(
    (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
    (_req, body, res) => {
      adapter.batchHits += 1;
      res.writeHead(200, {
        "content-type": "application/octet-stream",
        "x-raven-epoch": String(EPOCH),
        "x-raven-schema-version": "1",
      });
      res.end(Buffer.from(encodeBatchResponse(EPOCH, encodedBatchCount(body))));
      return true;
    },
  );
  server.route(
    (req) => req.url === "/v1/status",
    (_req, _body, res) => {
      adapter.statusHits += 1;
      writeJson(res, {
        scheme: "inspire",
        instances: [
          {
            id: INSTANCE_ID,
            epoch: EPOCH,
            role: "live",
            drain_state: "active",
            in_flight: 0,
            active_k_concurrency: 4,
          },
        ],
        consumer: null,
      });
      return true;
    },
  );
  return adapter;
}

function newSdk(server: MockServer): RavenPOINodeInterface {
  return new RavenPOINodeInterface({
    endpoint: server.url,
    bearerToken: TOKEN,
    useClientPir: true,
    clientPirContexts: new Map([[`t3CommitTree:${TREE_NUMBER}`, stubCtx()]]),
    imtCache: new ImtCache({ disableIndexedDb: true }),
  });
}

describe("a fully-cached auth path still crosses the wire", () => {
  let server: MockServer;
  let adapter: Adapter;

  beforeAll(async () => {
    server = await startMockServer();
  });
  afterAll(async () => {
    await server.close();
  });
  afterEach(() => {
    server.reset();
  });

  it("sends one batch POST and no status probe", async () => {
    adapter = mountAdapter(server);
    const sdk = newSdk(server);

    await sdk.getMerkleProof(TREE_NUMBER, LEAF);
    sdk.resetWireCapture();
    await sdk.getMerkleProof(TREE_NUMBER, LEAF);

    const warm = sdk.lastWireRequests();
    expect(warm).toHaveLength(1);
    expect(warm[0].method).toBe("POST");
    expect(warm[0].url.endsWith(`/v1/instance/${INSTANCE_ID}/batch`)).toBe(true);
    expect(adapter.batchHits).toBe(2);
    expect(adapter.statusHits).toBe(0);
  });

  it("sends the same slot count as the cold path, so the count does not publish the hit rate", async () => {
    adapter = mountAdapter(server);
    const sdk = newSdk(server);

    await sdk.getMerkleProof(TREE_NUMBER, LEAF);
    const coldSlots = encodedBatchCount(sdk.lastWireRequests()[0].body);
    sdk.resetWireCapture();
    await sdk.getMerkleProof(TREE_NUMBER, LEAF);
    const warmSlots = encodedBatchCount(sdk.lastWireRequests()[0].body);

    expect(coldSlots).toBe(16);
    expect(warmSlots).toBe(coldSlots);
    expect(isOnLadder(warmSlots)).toBe(true);
  });

  it("serves the same path it served cold", async () => {
    adapter = mountAdapter(server);
    const sdk = newSdk(server);

    const cold = authPathOf(await sdk.getMerkleProof(TREE_NUMBER, LEAF));
    const warm = authPathOf(await sdk.getMerkleProof(TREE_NUMBER, LEAF));
    expect(warm.elements).toEqual(cold.elements);
    expect(warm.indices).toBe(cold.indices);
  });

  it("still pads a partial hit to its own ladder step", async () => {
    adapter = mountAdapter(server);
    const sdk = newSdk(server);

    await sdk.getMerkleProof(TREE_NUMBER, LEAF);
    sdk.resetWireCapture();
    // LEAF ^ 0b111 shares every sibling above level 2, so exactly 3 levels miss.
    await sdk.getMerkleProof(TREE_NUMBER, LEAF ^ 0b111);
    expect(encodedBatchCount(sdk.lastWireRequests()[0].body)).toBe(4);
  });
});
