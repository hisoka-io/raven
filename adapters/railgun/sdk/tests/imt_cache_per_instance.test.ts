// Instances advance their snapshots independently, so one instance's epoch says nothing about
// another's cached nodes. A cache that drops every layer on any epoch change makes two
// instances at different epochs evict each other on every alternating query.

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { ImtCache, RavenPOINodeInterface, imtCacheKey } from "../src/index";
// Not re-exported from the barrel yet; the barrel is outside this change's write set.
import { imtCacheScopeKey } from "../src/imt-cache";

import { startMockServer, type MockServer } from "./helpers/mock_server";
import { TOKEN, encodeBatchResponse, encodedBatchCount, stubCtx } from "./helpers/auth_path_stub";

const LIST_KEY_HEX = "ab".repeat(32);
const TREE_NUMBER = 0;
const TREE_EPOCH = 7;
const LIST_EPOCH = 9;
const LEAF = 1234;
const NEAR_LEAF = LEAF ^ 0b111;
const BC_AT_LEAF = "11".repeat(32);
const BC_AT_NEAR_LEAF = "22".repeat(32);

function epochFor(url: string): number {
  return url.includes("commit-tree-") ? TREE_EPOCH : LIST_EPOCH;
}

function mountBatchRoute(server: MockServer): void {
  server.route(
    (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
    (req, body, res) => {
      const epoch = epochFor(req.url ?? "");
      res.writeHead(200, {
        "content-type": "application/octet-stream",
        "x-raven-epoch": String(epoch),
        "x-raven-schema-version": "1",
      });
      res.end(Buffer.from(encodeBatchResponse(epoch, encodedBatchCount(body))));
      return true;
    },
  );
}

function newSdk(server: MockServer, cache: ImtCache): RavenPOINodeInterface {
  return new RavenPOINodeInterface({
    endpoint: server.url,
    bearerToken: TOKEN,
    useClientPir: true,
    clientPirContexts: new Map([
      [`t3CommitTree:${TREE_NUMBER}`, stubCtx()],
      [`t2Path:${LIST_KEY_HEX}`, stubCtx()],
    ]),
    bcToIdxMaps: new Map([
      [
        LIST_KEY_HEX,
        new Map([
          [BC_AT_LEAF, LEAF],
          [BC_AT_NEAR_LEAF, NEAR_LEAF],
        ]),
      ],
    ]),
    imtCache: cache,
  });
}

function slotsOf(sdk: RavenPOINodeInterface): number[] {
  return sdk.lastWireRequests().map((w) => encodedBatchCount(w.body));
}

describe("IMT cache freshness is scoped to one instance", () => {
  let server: MockServer;

  beforeAll(async () => {
    server = await startMockServer();
    mountBatchRoute(server);
  });
  afterAll(async () => {
    await server.close();
  });

  it("a list query at its own epoch does not evict the tree instance's nodes", async () => {
    const sdk = newSdk(server, new ImtCache({ disableIndexedDb: true }));

    await sdk.getMerkleProof(TREE_NUMBER, LEAF);
    await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_AT_LEAF]);

    sdk.resetWireCapture();
    await sdk.getMerkleProof(TREE_NUMBER, NEAR_LEAF);
    expect(slotsOf(sdk)).toEqual([4]);
  });

  it("a tree query at its own epoch does not evict the list instance's nodes", async () => {
    const sdk = newSdk(server, new ImtCache({ disableIndexedDb: true }));

    await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_AT_LEAF]);
    await sdk.getMerkleProof(TREE_NUMBER, LEAF);

    sdk.resetWireCapture();
    await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_AT_NEAR_LEAF]);
    expect(slotsOf(sdk)).toEqual([4]);
  });

  it("alternating queries stay warm across a full round", async () => {
    const sdk = newSdk(server, new ImtCache({ disableIndexedDb: true }));

    await sdk.getMerkleProof(TREE_NUMBER, LEAF);
    await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_AT_LEAF]);
    await sdk.getMerkleProof(TREE_NUMBER, LEAF);
    await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_AT_LEAF]);

    sdk.resetWireCapture();
    await sdk.getMerkleProof(TREE_NUMBER, NEAR_LEAF);
    await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_AT_NEAR_LEAF]);
    expect(slotsOf(sdk)).toEqual([4, 4]);
  });
});

describe("ImtCache.noteFreshness evicts one scope", () => {
  const node = (tag: number): Uint8Array => new Uint8Array([tag]);
  const treeScope = imtCacheScopeKey({ chainId: 1, scope: "tree-0" });
  const listScope = imtCacheScopeKey({ chainId: 1, scope: `list-${LIST_KEY_HEX}` });
  const otherChainScope = imtCacheScopeKey({ chainId: 11_155_111, scope: "tree-0" });
  const treeKey = imtCacheKey({
    chainId: 1,
    scope: "tree-0",
    level: 0,
    idxAtLevel: 5,
    epochTag: "7",
    schemaVersion: 1,
  });
  const listKey = imtCacheKey({
    chainId: 1,
    scope: `list-${LIST_KEY_HEX}`,
    level: 0,
    idxAtLevel: 5,
    epochTag: "9",
    schemaVersion: 1,
  });
  const otherChainKey = imtCacheKey({
    chainId: 11_155_111,
    scope: "tree-0",
    level: 0,
    idxAtLevel: 5,
    epochTag: "7",
    schemaVersion: 1,
  });

  // Every scope is recorded before its nodes go in, so any later eviction is caused by the
  // tuple moving, not by the scope being seen for the first time.
  function seeded(): ImtCache {
    const cache = new ImtCache({ disableIndexedDb: true });
    cache.noteFreshness(treeScope, "7", 1);
    cache.noteFreshness(listScope, "9", 1);
    cache.noteFreshness(otherChainScope, "7", 1);
    cache.set(treeKey, node(1));
    cache.set(listKey, node(2));
    cache.set(otherChainKey, node(3));
    return cache;
  }

  it("drops the advancing scope and leaves the others", () => {
    const cache = seeded();
    cache.noteFreshness(treeScope, "8", 1);
    expect(cache.getSync(treeKey)).toBeUndefined();
    expect(cache.getSync(listKey)).toEqual(node(2));
    expect(cache.getSync(otherChainKey)).toEqual(node(3));
    expect(cache.inMemorySize()).toBe(2);
  });

  it("keeps one chain's scope distinct from the same scope on another chain", () => {
    const cache = seeded();
    cache.noteFreshness(otherChainScope, "8", 1);
    expect(cache.getSync(otherChainKey)).toBeUndefined();
    expect(cache.getSync(treeKey)).toEqual(node(1));
  });

  it("is a no-op when the scope reports the tuple it already holds", () => {
    const cache = seeded();
    cache.noteFreshness(treeScope, "7", 1);
    expect(cache.getSync(treeKey)).toEqual(node(1));
    expect(cache.inMemorySize()).toBe(3);
  });

  it("drops the scope on a schema-version advance at an unchanged epoch", () => {
    const cache = seeded();
    cache.noteFreshness(treeScope, "7", 2);
    expect(cache.getSync(treeKey)).toBeUndefined();
    expect(cache.getSync(listKey)).toEqual(node(2));
  });

  // A reload resets the freshness map while an IndexedDB L2 survives, so nothing is known
  // about what an unrecorded scope holds and it is dropped rather than trusted.
  it("drops a scope it has no recorded tuple for", () => {
    const cache = new ImtCache({ disableIndexedDb: true });
    cache.set(treeKey, node(1));
    cache.noteFreshness(treeScope, "7", 1);
    expect(cache.getSync(treeKey)).toBeUndefined();
  });

  it("clearAll drops every scope", async () => {
    const cache = seeded();
    await cache.clearAll();
    expect(cache.inMemorySize()).toBe(0);
  });
});
