// `X-Raven-Schema-Version` decides whether a scope's cached nodes survive, so an
// unparseable value cannot be handed to the cache as a number: `NaN !== NaN` makes the
// "same tuple, keep the cache" comparison unreachable and purges the scope on every reply.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { ImtCache, RavenError, RavenPOINodeInterface, imtCacheScopeKey } from "../src/index";

import { startMockServer, type MockServer } from "./helpers/mock_server";
import { NODE_BYTES, TOKEN, encodeBatchResponse, encodedBatchCount, stubCtx } from "./helpers/auth_path_stub";

const TREE_NUMBER = 0;
const LEAF = 1234;
const SERVED_EPOCH = "7";

function mountBatchRoute(server: MockServer, schemaVersion: string | null): void {
  server.route(
    (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
    (_req, body, res) => {
      const out = encodeBatchResponse(7, encodedBatchCount(body));
      const headers: Record<string, string> = {
        "content-type": "application/octet-stream",
        "x-raven-epoch": SERVED_EPOCH,
      };
      if (schemaVersion !== null) headers["x-raven-schema-version"] = schemaVersion;
      res.writeHead(200, headers);
      res.end(Buffer.from(out));
      return true;
    },
  );
}

function newSdk(server: MockServer, cache: ImtCache): RavenPOINodeInterface {
  return new RavenPOINodeInterface({
    endpoint: server.url,
    bearerToken: TOKEN,
    useClientPir: true,
    clientPirContexts: new Map([[`t3CommitTree:${TREE_NUMBER}`, stubCtx()]]),
    imtCache: cache,
  });
}

describe("batch schema-version header validation", () => {
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

  it("refuses a non-numeric schema-version header", async () => {
    mountBatchRoute(server, "v1");
    const sdk = newSdk(server, new ImtCache({ disableIndexedDb: true }));
    let thrown: unknown;
    try {
      await sdk.getMerkleProof(TREE_NUMBER, LEAF);
    } catch (e) {
      thrown = e;
    }
    expect(RavenError.is(thrown, "StaleAdapter")).toBe(true);
  });

  it("refuses a fractional or negative schema-version header", async () => {
    for (const raw of ["1.5", "-1", "0x2", "NaN"]) {
      mountBatchRoute(server, raw);
      const sdk = newSdk(server, new ImtCache({ disableIndexedDb: true }));
      await expect(sdk.getMerkleProof(TREE_NUMBER, LEAF)).rejects.toThrow(/schema/);
      server.reset();
    }
  });

  it("keeps a scope's cached nodes across replies carrying the same header", async () => {
    mountBatchRoute(server, "3");
    const cache = new ImtCache({ disableIndexedDb: true });
    const sdk = newSdk(server, cache);
    await sdk.getMerkleProof(TREE_NUMBER, LEAF);
    const afterFirst = cache.inMemorySize();
    expect(afterFirst).toBe(16);
    await sdk.getMerkleProof(TREE_NUMBER, LEAF);
    expect(cache.inMemorySize()).toBe(afterFirst);
  });

  it("still accepts a reply with no schema-version header", async () => {
    mountBatchRoute(server, null);
    const cache = new ImtCache({ disableIndexedDb: true });
    await newSdk(server, cache).getMerkleProof(TREE_NUMBER, LEAF);
    expect(cache.inMemorySize()).toBe(16);
  });

  // Matches the epoch header's rule that an empty value counts as absent.
  it("treats a whitespace-only schema-version header as absent", async () => {
    mountBatchRoute(server, " ");
    const cache = new ImtCache({ disableIndexedDb: true });
    await newSdk(server, cache).getMerkleProof(TREE_NUMBER, LEAF);
    expect(cache.inMemorySize()).toBe(16);
  });

  it("exports the scope-key builder the cache invalidation contract names", () => {
    expect(imtCacheScopeKey({ chainId: 1, scope: `tree-${TREE_NUMBER}` })).toBe("c=1|s=tree-0|");
    expect(NODE_BYTES).toBe(32);
  });
});
