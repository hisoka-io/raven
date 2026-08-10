// A batch reply that does not name its snapshot epoch cannot certify the auth path it carries,
// so the SDK refuses it instead of caching and serving nodes tagged with a guessed epoch.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { ImtCache, RavenError, RavenPOINodeInterface } from "../src/index";

import { startMockServer, type MockServer } from "./helpers/mock_server";
import { TOKEN, encodeBatchResponse, encodedBatchCount, stubCtx } from "./helpers/auth_path_stub";

const TREE_NUMBER = 0;
const LEAF = 1234;
const SERVED_EPOCH = 7;

interface HeaderPolicy {
  epoch: string | null;
  schemaVersion: string | null;
}

function mountBatchRoute(server: MockServer, policy: HeaderPolicy): void {
  server.route(
    (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
    (_req, body, res) => {
      const headers: Record<string, string> = { "content-type": "application/octet-stream" };
      if (policy.epoch !== null) headers["x-raven-epoch"] = policy.epoch;
      if (policy.schemaVersion !== null) headers["x-raven-schema-version"] = policy.schemaVersion;
      res.writeHead(200, headers);
      res.end(Buffer.from(encodeBatchResponse(SERVED_EPOCH, encodedBatchCount(body))));
      return true;
    },
  );
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

async function captureThrow(sdk: RavenPOINodeInterface): Promise<unknown> {
  let thrown: unknown;
  let returned = false;
  try {
    await sdk.getMerkleProof(TREE_NUMBER, LEAF);
    returned = true;
  } catch (e) {
    thrown = e;
  }
  expect(returned).toBe(false);
  return thrown;
}

describe("X-Raven-Epoch is mandatory on a batch reply", () => {
  let server: MockServer;

  beforeAll(async () => {
    server = await startMockServer();
  });
  afterAll(async () => {
    await server.close();
  });
  afterEach(() => {
    server.reset();
  });

  it("rejects a 200 batch reply that omits the header", async () => {
    mountBatchRoute(server, { epoch: null, schemaVersion: "1" });
    const thrown = await captureThrow(newSdk(server));
    expect(RavenError.is(thrown, "StaleAdapter")).toBe(true);
    expect((thrown as RavenError).message).toContain("x-raven-epoch");
  });

  // Whitespace-only values reach the SDK as "" - both the Headers constructor and the HTTP
  // transport strip OWS - so an empty value is the only blank shape a reply can carry.
  it("rejects a header present but empty, which would alias the never-observed tag", async () => {
    mountBatchRoute(server, { epoch: "", schemaVersion: "1" });
    const thrown = await captureThrow(newSdk(server));
    expect(RavenError.is(thrown, "StaleAdapter")).toBe(true);
  });

  it("rejects an omitted header even when the schema-version header is also absent", async () => {
    mountBatchRoute(server, { epoch: null, schemaVersion: null });
    const thrown = await captureThrow(newSdk(server));
    expect(RavenError.is(thrown, "StaleAdapter")).toBe(true);
  });

  it("serves the path when the header is present", async () => {
    mountBatchRoute(server, { epoch: String(SERVED_EPOCH), schemaVersion: "1" });
    const proof = await newSdk(server).getMerkleProof(TREE_NUMBER, LEAF);
    expect(proof.elements).toHaveLength(16);
    expect(proof.elements.every((e) => e.startsWith("07"))).toBe(true);
  });
});
