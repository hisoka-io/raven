// A wallet restarts far more often than the list turns over, and walking the whole prefix channel
// again on every start is the cost the index exists to avoid. So the index, its row count and the
// cursor it resumes from outlive the process: a restarted client resolves an index from the store
// with no request, and its next call re-reads only the tail. A record is also an input the SDK
// answers absences from, so one that is damaged, foreign, or from another node is not believed.

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import {
  LEAVES_PER_PPOI_BLOCK,
  RavenError,
  RavenPOINodeInterface,
  indexedDbPoiListIndexStore,
  type PoiListIndexStore,
} from "../src/index";
import {
  commitmentAt,
  mountPrefixChannel,
  prefixIndexOf,
  targetNamingCtx,
  type MockList,
} from "./helpers/prefix_channel";
import { startMockServer, type MockServer } from "./helpers/mock_server";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "ab".repeat(32);

class MemoryStore implements PoiListIndexStore {
  readonly records = new Map<string, Uint8Array>();
  failSaves = false;

  async load(key: string): Promise<Uint8Array | undefined> {
    return this.records.get(key);
  }

  async save(key: string, record: Uint8Array): Promise<void> {
    if (this.failSaves) throw new Error("disk full");
    this.records.set(key, new Uint8Array(record));
  }
}

function listOf(rows: number): MockList {
  return { commitments: Array.from({ length: rows }, (_unused, row) => commitmentAt(row)) };
}

/** Counts every request and refuses all of them: a client that must not touch the network. */
function offline(): { fetchImpl: typeof fetch; calls: () => number } {
  let calls = 0;
  return {
    fetchImpl: async () => {
      calls += 1;
      throw new TypeError("offline");
    },
    calls: () => calls,
  };
}

describe("a list index survives a restart", () => {
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

  function client(store: PoiListIndexStore | false, fetchImpl?: typeof fetch): RavenPOINodeInterface {
    return new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      clientPirContexts: new Map([[`t2Path:1:${LIST_KEY_HEX}`, targetNamingCtx()]]),
      poiListIndexStore: store,
      fetchImpl,
    });
  }

  it("lets a cold client resolve an index with no request at all", async () => {
    const list = listOf(5);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    const store = new MemoryStore();
    await client(store).syncPoiListIndex(LIST_KEY_HEX);
    expect(store.records.size).toBe(1);

    const network = offline();
    const restarted = client(store, network.fetchImpl);
    const resolved = await restarted.poiListIndexCandidates(LIST_KEY_HEX, commitmentAt(3));

    expect(resolved).toStrictEqual({ rows: 5, candidates: [3] });
    expect(network.calls()).toBe(0);
  });

  // A wallet's first calls after a start arrive together, one per txid version.
  it("lets every call that arrives while the store is being read resolve from it", async () => {
    const list = listOf(5);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    const store = new MemoryStore();
    await client(store).syncPoiListIndex(LIST_KEY_HEX);

    const network = offline();
    const restarted = client(store, network.fetchImpl);
    const resolved = await Promise.allSettled([
      restarted.poiListIndexCandidates(LIST_KEY_HEX, commitmentAt(3)),
      restarted.poiListIndexCandidates(LIST_KEY_HEX, commitmentAt(1)),
    ]);

    expect(resolved).toStrictEqual([
      { status: "fulfilled", value: { rows: 5, candidates: [3] } },
      { status: "fulfilled", value: { rows: 5, candidates: [1] } },
    ]);
    expect(network.calls()).toBe(0);
  });

  it("answers concurrent status calls on a restarted client from the stored index's tail", async () => {
    const list = listOf(2_050);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    const store = new MemoryStore();
    await client(store).syncPoiListIndex(LIST_KEY_HEX);
    server.requests.length = 0;

    const restarted = client(store);
    const ask = (bc: string) =>
      restarted.getPOIsPerList([LIST_KEY_HEX], [{ blindedCommitment: bc, type: "Shield" }]);
    const settled = await Promise.allSettled([ask(commitmentAt(1)), ask(commitmentAt(2_049))]);

    expect(settled.map((r) => r.status)).toStrictEqual(["fulfilled", "fulfilled"]);
    const [first, second] = settled.map((r) => (r.status === "fulfilled" ? r.value : {}));
    expect(first[commitmentAt(1)]?.[LIST_KEY_HEX]).toBe("Valid");
    expect(second[commitmentAt(2_049)]?.[LIST_KEY_HEX]).toBe("Valid");
    expect(
      server.requests.filter((r) => r.url.includes("/bc-prefixes")).map((r) => r.url),
    ).toStrictEqual([
      `/v1/poi/${LIST_KEY_HEX}/bc-prefixes?since=2048`,
      `/v1/poi/${LIST_KEY_HEX}/bc-prefixes?since=2048`,
    ]);
  });

  it("resumes from the persisted cursor and catches what was appended while it was down", async () => {
    const list = listOf(2_050);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    const store = new MemoryStore();
    await client(store).syncPoiListIndex(LIST_KEY_HEX);
    const appended = commitmentAt(2_050);
    list.commitments.push(appended);
    server.requests.length = 0;

    const restarted = client(store);
    const got = await restarted.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: appended, type: "Shield" }],
    );

    expect(got[appended][LIST_KEY_HEX]).toBe("Valid");
    expect(restarted.indexCounters().staleIndexesCaught).toBe(1);
    expect(
      server.requests.filter((r) => r.url.includes("/bc-prefixes")).map((r) => r.url),
    ).toStrictEqual([`/v1/poi/${LIST_KEY_HEX}/bc-prefixes?since=2048`]);
    const again = client(store, offline().fetchImpl);
    expect((await again.poiListIndexCandidates(LIST_KEY_HEX, appended)).rows).toBe(2_051);
  });

  it("checks a preloaded index in full once, then persists it so a restart resumes its tail", async () => {
    const list = listOf(2_050);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    const store = new MemoryStore();
    const preloaded = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      poiListIndexes: new Map([[`1:${LIST_KEY_HEX}`, prefixIndexOf(list.commitments)]]),
      poiListIndexStore: store,
    });
    await preloaded.syncPoiListIndex(LIST_KEY_HEX);
    expect(store.records.size).toBe(1);

    await client(store).syncPoiListIndex(LIST_KEY_HEX);

    expect(
      server.requests.filter((r) => r.url.includes("/bc-prefixes")).map((r) => r.url),
    ).toStrictEqual([
      `/v1/poi/${LIST_KEY_HEX}/bc-prefixes?since=0`,
      `/v1/poi/${LIST_KEY_HEX}/bc-prefixes?since=2048`,
    ]);
  });

  it("does not believe a damaged, truncated or foreign record", async () => {
    const list = listOf(4);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    const store = new MemoryStore();
    await client(store).syncPoiListIndex(LIST_KEY_HEX);
    const [key, record] = [...store.records][0];

    const damage = async (bytes: Uint8Array): Promise<void> => {
      store.records.set(key, bytes);
      await expect(
        client(store, offline().fetchImpl).poiListIndexCandidates(LIST_KEY_HEX, commitmentAt(1)),
      ).rejects.toThrow(/no index is held/);
    };
    const flipped = new Uint8Array(record);
    flipped[48 + 6] ^= 0x01;
    await damage(flipped);
    await damage(record.subarray(0, record.length - 7));
    const foreign = new Uint8Array(record);
    foreign[4] ^= 0xff;
    await damage(foreign);
  });

  it("keeps one node's index away from another node", async () => {
    mountPrefixChannel(server, LIST_KEY_HEX, listOf(4));
    const store = new MemoryStore();
    await client(store).syncPoiListIndex(LIST_KEY_HEX);

    const elsewhere = new RavenPOINodeInterface({
      endpoint: "http://127.0.0.1:1",
      bearerToken: TOKEN,
      poiListIndexStore: store,
    });
    await expect(elsewhere.poiListIndexCandidates(LIST_KEY_HEX, commitmentAt(1))).rejects.toThrow(
      /no index is held/,
    );
  });

  it("treats a failed save as a longer walk next time, not a failed sync", async () => {
    mountPrefixChannel(server, LIST_KEY_HEX, listOf(4));
    const store = new MemoryStore();
    store.failSaves = true;

    await expect(client(store).syncPoiListIndex(LIST_KEY_HEX)).resolves.toMatchObject({ total: 4 });
    expect(store.records.size).toBe(0);
  });

  it("keeps the lowest occurrence of a recurring commitment, as the adapter resolves it", async () => {
    const recurring = commitmentAt(0x100_0000);
    const list = listOf(LEAVES_PER_PPOI_BLOCK + 4);
    list.commitments[3] = recurring;
    list.commitments[LEAVES_PER_PPOI_BLOCK + 3] = recurring;
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, _body, res) => {
        // Garbage on purpose: the assertion is WHICH instance was asked.
        res.writeHead(200, { "content-type": "application/octet-stream" });
        res.end(Buffer.alloc(16));
        return true;
      },
    );
    const store = new MemoryStore();
    await client(store).syncPoiListIndex(LIST_KEY_HEX);

    const restarted = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      clientPirContexts: new Map([[`t2Path:1:${LIST_KEY_HEX}`, targetNamingCtx()]]),
      clientPirInstanceLabels: new Map([
        [`t2Path:1:${LIST_KEY_HEX}:0`, "block0"],
        [`t2Path:1:${LIST_KEY_HEX}:1`, "block1"],
      ]),
      poiListIndexStore: store,
    });
    await expect(restarted.getPOIMerkleProofs(LIST_KEY_HEX, [recurring])).rejects.toThrow();

    const batched = server.requests.filter((r) => /\/batch$/.test(r.url)).map((r) => r.url);
    expect(batched).toStrictEqual(["/v1/instance/block0/batch"]);
  });
});

/** Enough of IndexedDB for one object store: requests complete on a microtask, like the real one. */
function fakeIndexedDb(): { factory: IDBFactory; records: Map<string, unknown> } {
  const records = new Map<string, unknown>();
  let created = false;
  const request = <T>(run: () => T): IDBRequest<T> => {
    const req = {} as { result: T; onsuccess?: () => void; onerror?: () => void };
    queueMicrotask(() => {
      req.result = run();
      req.onsuccess?.();
    });
    return req as unknown as IDBRequest<T>;
  };
  const db = {
    objectStoreNames: { contains: (): boolean => created },
    createObjectStore: (): void => {
      created = true;
    },
    transaction: () => ({
      objectStore: () => ({
        get: (key: string) => request(() => records.get(key)),
        put: (value: unknown, key: string) =>
          request(() => {
            records.set(key, value);
            return key;
          }),
      }),
    }),
  };
  const factory = {
    open: () => {
      const req = {} as {
        result: typeof db;
        onupgradeneeded?: () => void;
        onsuccess?: () => void;
      };
      queueMicrotask(() => {
        req.result = db;
        req.onupgradeneeded?.();
        req.onsuccess?.();
      });
      return req;
    },
  };
  return { factory: factory as unknown as IDBFactory, records };
}

describe("the browser store", () => {
  let server: MockServer;
  beforeAll(async () => {
    server = await startMockServer();
  });
  afterAll(async () => {
    await server.close();
  });
  afterEach(() => {
    server.reset();
    vi.unstubAllGlobals();
  });

  it("is absent where the runtime has no IndexedDB", () => {
    expect(indexedDbPoiListIndexStore()).toBeUndefined();
  });

  it("round-trips a record", async () => {
    const { factory } = fakeIndexedDb();
    const store = indexedDbPoiListIndexStore({ indexedDB: factory });
    expect(store).toBeDefined();
    const record = new Uint8Array([1, 2, 3, 4]);
    await store?.save("k", record);
    expect(await store?.load("k")).toStrictEqual(record);
    expect(await store?.load("absent")).toBeUndefined();
  });

  it("is the default wherever IndexedDB exists, so a restart in a browser resumes", async () => {
    const { factory, records } = fakeIndexedDb();
    vi.stubGlobal("indexedDB", factory);
    const list = listOf(3);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    await new RavenPOINodeInterface({ endpoint: server.url, bearerToken: TOKEN }).syncPoiListIndex(
      LIST_KEY_HEX,
    );
    expect(records.size).toBe(1);

    const restarted = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      fetchImpl: offline().fetchImpl,
    });
    expect(await restarted.poiListIndexCandidates(LIST_KEY_HEX, commitmentAt(2))).toStrictEqual({
      rows: 3,
      candidates: [2],
    });
  });
});

describe("an index the node no longer vouches for", () => {
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

  function client(store: PoiListIndexStore): RavenPOINodeInterface {
    return new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      clientPirContexts: new Map([[`t2Path:1:${LIST_KEY_HEX}`, targetNamingCtx()]]),
      poiListIndexStore: store,
    });
  }

  const prefixRequests = (): string[] =>
    server.requests.filter((r) => r.url.includes("/bc-prefixes")).map((r) => r.url);
  const since = (row: number): string => `/v1/poi/${LIST_KEY_HEX}/bc-prefixes?since=${row}`;

  it("resetPoiListIndex clears the held and stored index, so the next sync reads the whole list", async () => {
    const list = listOf(2_050);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    const store = new MemoryStore();
    const sdk = client(store);
    await sdk.syncPoiListIndex(LIST_KEY_HEX);
    server.requests.length = 0;

    await sdk.resetPoiListIndex(LIST_KEY_HEX);
    await expect(sdk.poiListIndexCandidates(LIST_KEY_HEX, commitmentAt(1))).rejects.toThrow(
      /no index is held/,
    );
    await expect(client(store).poiListIndexCandidates(LIST_KEY_HEX, commitmentAt(1))).rejects.toThrow(
      /no index is held/,
    );
    expect((await sdk.syncPoiListIndex(LIST_KEY_HEX)).total).toBe(2_050);
    expect(prefixRequests()).toStrictEqual([since(0)]);
  });

  it("resetPoiListIndex also drops an index the caller preloaded", async () => {
    const list = listOf(3);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      poiListIndexes: new Map([[`1:${LIST_KEY_HEX}`, prefixIndexOf(list.commitments)]]),
      poiListIndexStore: false,
    });
    await sdk.resetPoiListIndex(LIST_KEY_HEX);
    await expect(sdk.poiListIndexCandidates(LIST_KEY_HEX, commitmentAt(1))).rejects.toThrow(
      /no index is held/,
    );
  });

  it("discards a stored index stamped with another epoch and reads the node's list again", async () => {
    const list: MockList = { ...listOf(2_050), epoch: 5 };
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    const store = new MemoryStore();
    await client(store).syncPoiListIndex(LIST_KEY_HEX);
    // Another list under the same key: a row below the resume cursor differs as well.
    list.commitments[7] = commitmentAt(90_000);
    list.epoch = 6;
    server.requests.length = 0;

    const synced = await client(store).syncPoiListIndex(LIST_KEY_HEX);

    expect(synced.epoch).toBe(6);
    expect(prefixRequests()).toStrictEqual([since(2_048), since(0)]);
    const again = client(store);
    expect(await again.poiListIndexCandidates(LIST_KEY_HEX, commitmentAt(90_000))).toStrictEqual({
      rows: 2_050,
      candidates: [7],
    });
  });

  it("resumes a 416 from the total the node reports, and re-reads a re-bootstrapped list", async () => {
    const list: MockList = listOf(4_100);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    const store = new MemoryStore();
    await client(store).syncPoiListIndex(LIST_KEY_HEX);
    list.commitments.length = 3_000;
    list.epoch = 1;
    server.requests.length = 0;

    const synced = await client(store).syncPoiListIndex(LIST_KEY_HEX);

    expect(synced).toMatchObject({ epoch: 1, total: 3_000 });
    expect(prefixRequests()).toStrictEqual([since(4_096), since(2_048), since(0)]);
  });

  it("resumes a 416 from the node's total and still refuses a shorter list under the same epoch", async () => {
    const list = listOf(4_100);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    const store = new MemoryStore();
    await client(store).syncPoiListIndex(LIST_KEY_HEX);
    list.commitments.length = 3_000;
    server.requests.length = 0;

    await expect(client(store).syncPoiListIndex(LIST_KEY_HEX)).rejects.toSatisfy(
      (e: unknown) =>
        RavenError.is(e, "StaleAdapter") && /serves 3000 rows of a list this index holds 4100/.test(e.message),
    );
    expect(prefixRequests()).toStrictEqual([since(4_096), since(2_048)]);
  });
});
