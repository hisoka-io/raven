// "Missing" is the verdict a wallet acts on, and an index answers it with no query: the commitment
// has no row, so no row's commitment check ever runs. An index one append behind the list therefore
// reads a real member as "Missing". For a mirrored PPOI list the served epoch is 0 whatever the list
// holds, so it cannot tell the two apart; the row count is the quantity that moves, so that is what
// an index is bound to, and each call brings the index up to the node's count before it answers.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  BC_INDEX_RESUME_ALIGN_ROWS,
  RavenError,
  RavenPOINodeInterface,
  hexToBytes,
  indexCandidatesFor,
  indexCandidatesForEach,
  resumeBcPrefixIndex,
  type BcPrefixIndex,
  type RavenConfig,
} from "../src/index";
import { bcPrefixIndexFromRows } from "../src/bc-prefix-index";
import { encodeBatchResponseNodes } from "./helpers/auth_path_stub";
import {
  batchTargets,
  commitmentAt,
  mountJsonIndex,
  mountPrefixChannel,
  mountStatusRows,
  prefixIndexOf,
  prefixTwinOf,
  statusRow,
  targetNamingCtx,
  type MockList,
} from "./helpers/prefix_channel";
import { startMockServer, writeJson, type MockServer } from "./helpers/mock_server";
import { path10Slot } from "./helpers/path10_row";
import { ppoiTree } from "./helpers/ppoi_tree";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "ab".repeat(32);
const SHIELD_BLOCKED = 1;

function listOf(rows: number): MockList {
  return { commitments: Array.from({ length: rows }, (_unused, row) => commitmentAt(row)) };
}

function prefixRequests(server: MockServer): string[] {
  return server.requests.filter((r) => r.url.includes("/bc-prefixes")).map((r) => r.url);
}

function batchRequests(server: MockServer): number {
  return server.requests.filter((r) => /\/batch$/.test(r.url)).length;
}

describe("an index answers an absence only at the row count the node serves", () => {
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

  function sdk(
    extra: Pick<RavenConfig, "bcToIdxMaps" | "indexStalenessPolicy" | "poiListIndexes"> = {},
  ): RavenPOINodeInterface {
    return new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, targetNamingCtx()]]),
      poiListIndexStore: false,
      ...extra,
    });
  }

  it("catches a map fetched before an append instead of reading the new member as Missing", async () => {
    const list = listOf(3);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    mountStatusRows(server, list, () => SHIELD_BLOCKED);
    const client = sdk();
    expect((await client.syncPoiListIndex(LIST_KEY_HEX)).total).toBe(3);

    const appended = commitmentAt(3);
    list.commitments.push(appended);
    const got = await client.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: appended, type: "Shield" }],
    );

    expect(got[appended][LIST_KEY_HEX]).toBe("ShieldBlocked");
    expect(client.indexCounters()).toStrictEqual({
      absent: 0,
      absentFromStaleIndex: 0,
      absentFromBareMap: 0,
      refused: 0,
      staleIndexesCaught: 1,
    });
  });

  it("answers a commitment absent from every served row as Missing, and counts it", async () => {
    const list = listOf(3);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    mountStatusRows(server, list, () => SHIELD_BLOCKED);
    const client = sdk();
    await client.syncPoiListIndex(LIST_KEY_HEX);
    server.requests.length = 0;

    const stranger = commitmentAt(99);
    const got = await client.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: stranger, type: "Shield" }],
    );

    expect(got[stranger][LIST_KEY_HEX]).toBe("Missing");
    expect(client.indexCounters().absent).toBe(1);
    expect(client.indexCounters().staleIndexesCaught).toBe(0);
    expect(prefixRequests(server)).toStrictEqual([
      `/v1/poi/${LIST_KEY_HEX}/bc-prefixes?since=0`,
    ]);
  });

  it("refuses by default when the index cannot be brought up to the node's list", async () => {
    const list = listOf(3);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    mountStatusRows(server, list, () => SHIELD_BLOCKED);
    const client = sdk();
    await client.syncPoiListIndex(LIST_KEY_HEX);
    list.failStatus = 503;
    server.requests.length = 0;

    const call = client.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: commitmentAt(99), type: "Shield" }],
    );

    await expect(call).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "ServerError") && /holds 3 rows/.test(e.message),
    );
    expect(client.indexCounters().refused).toBe(1);
    expect(client.indexCounters().absent).toBe(0);
    // Raised after the list's query, as a bare map's refusal is, so membership shapes nothing.
    expect(batchRequests(server)).toBe(1);
  });

  it("answers from the rows held only on the caller's decision, and counts that apart", async () => {
    const list = listOf(3);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    mountStatusRows(server, list, () => SHIELD_BLOCKED);
    const client = sdk({ indexStalenessPolicy: "answer-at-index-rows" });
    await client.syncPoiListIndex(LIST_KEY_HEX);
    list.failStatus = 503;

    const stranger = commitmentAt(99);
    const got = await client.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: stranger, type: "Shield" }],
    );

    expect(got[stranger][LIST_KEY_HEX]).toBe("MissingStale");
    expect(client.indexCounters().absentFromStaleIndex).toBe(1);
    expect(client.indexCounters().absent).toBe(0);
  });

  it("refuses a bare map's absence by default and counts it apart when the caller decides", async () => {
    const list = listOf(1);
    mountStatusRows(server, list, () => SHIELD_BLOCKED);
    const bare = new Map([[commitmentAt(0), 0]]);
    const stranger = commitmentAt(99);
    const query = [{ blindedCommitment: stranger, type: "Shield" as const }];

    const refusing = sdk({ bcToIdxMaps: new Map([[LIST_KEY_HEX, bare]]) });
    await expect(refusing.getPOIsPerList([LIST_KEY_HEX], query)).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "InvalidQuery") && /carries no row count/.test(e.message),
    );
    expect(refusing.indexCounters().refused).toBe(1);

    const deciding = sdk({
      bcToIdxMaps: new Map([[LIST_KEY_HEX, bare]]),
      indexStalenessPolicy: "answer-at-index-rows",
    });
    const got = await deciding.getPOIsPerList([LIST_KEY_HEX], query);
    expect(got[stranger][LIST_KEY_HEX]).toBe("MissingStale");
    expect(deciding.indexCounters().absentFromBareMap).toBe(1);
    expect(deciding.indexCounters().absent).toBe(0);
  });

  it("refuses a bare map's absence only after every list's query has gone out", async () => {
    const list = listOf(1);
    mountStatusRows(server, list, () => SHIELD_BLOCKED);
    const other = "cd".repeat(32);
    const client = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([
        [`t1Status:${LIST_KEY_HEX}`, targetNamingCtx()],
        [`t1Status:${other}`, targetNamingCtx()],
      ]),
      bcToIdxMaps: new Map([
        [LIST_KEY_HEX, new Map()],
        [other, new Map([[commitmentAt(0), 0]])],
      ]),
      poiListIndexStore: false,
    });

    await expect(
      client.getPOIsPerList([LIST_KEY_HEX, other], [{ blindedCommitment: commitmentAt(0), type: "Shield" }]),
    ).rejects.toSatisfy((e: unknown) => RavenError.is(e, "InvalidQuery"));
    expect(batchRequests(server)).toBe(2);
  });

  it("refuses a node that serves fewer rows than the index already holds", async () => {
    const list = listOf(3);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    mountStatusRows(server, list, () => SHIELD_BLOCKED);
    const held = prefixIndexOf(listOf(5).commitments);
    const client = sdk({ poiListIndexes: new Map([[LIST_KEY_HEX, held]]) });

    await expect(
      client.getPOIsPerList([LIST_KEY_HEX], [{ blindedCommitment: commitmentAt(99), type: "Shield" }]),
    ).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "StaleAdapter") && /serves 3 rows/.test(e.message),
    );
    expect(client.indexCounters().absent).toBe(0);
  });

  it("refuses a node whose re-read rows differ from the rows the index holds", async () => {
    const list = listOf(3);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    const held = prefixIndexOf([commitmentAt(0), commitmentAt(7), commitmentAt(2)]);

    await expect(
      resumeBcPrefixIndex(fetch, server.url, LIST_KEY_HEX, {}, held),
    ).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "DecodeError") && /row 1 differs/.test(e.message),
    );
  });

  it("re-reads only from the aligned window below the rows held", async () => {
    const held = BC_INDEX_RESUME_ALIGN_ROWS + 2;
    const list = listOf(held);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    const client = sdk();
    await client.syncPoiListIndex(LIST_KEY_HEX);
    server.requests.length = 0;
    list.commitments.push(commitmentAt(held));

    const synced: BcPrefixIndex = await client.syncPoiListIndex(LIST_KEY_HEX);

    expect(synced.total).toBe(held + 1);
    expect(prefixRequests(server)).toStrictEqual([
      `/v1/poi/${LIST_KEY_HEX}/bc-prefixes?since=${BC_INDEX_RESUME_ALIGN_ROWS}`,
    ]);
  });

  // Batch SIZE still follows the real-target count, as the ladder always has; what an index adds
  // is the sync, and it must not depend on membership.
  it("sends the same requests whether or not the commitments are on the list", async () => {
    const list = listOf(4);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    mountStatusRows(server, list, () => SHIELD_BLOCKED);
    const shape = async (bcs: string[]): Promise<string[]> => {
      const client = sdk();
      await client.syncPoiListIndex(LIST_KEY_HEX);
      server.requests.length = 0;
      await client.getPOIsPerList(
        [LIST_KEY_HEX],
        bcs.map((blindedCommitment) => ({ blindedCommitment, type: "Shield" as const })),
      );
      return server.requests
        .filter((r) => !r.url.endsWith("/session"))
        .map((r) => `${r.method} ${r.url.replace(/\/instance\/[^/]+\//, "/instance/*/")}`);
    };

    const members = await shape([commitmentAt(0), commitmentAt(1)]);
    const strangers = await shape([commitmentAt(98), commitmentAt(99)]);

    expect(strangers).toStrictEqual(members);
  });
});

describe("a prefix shared by two commitments is resolved by the row, never by guessing", () => {
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

  function sdk(): RavenPOINodeInterface {
    return new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, targetNamingCtx()]]),
      poiListIndexStore: false,
    });
  }

  it("moves past a colliding row to the commitment's own", async () => {
    const list: MockList = {
      commitments: [commitmentAt(0), prefixTwinOf(5), commitmentAt(2), commitmentAt(5)],
    };
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    mountStatusRows(server, list, (row) => (row === 3 ? 0 : SHIELD_BLOCKED));
    const client = sdk();
    await client.syncPoiListIndex(LIST_KEY_HEX);

    const own = commitmentAt(5);
    const got = await client.getPOIsPerList([LIST_KEY_HEX], [{ blindedCommitment: own, type: "Shield" }]);

    expect(got[own][LIST_KEY_HEX]).toBe("Valid");
    expect(batchRequests(server)).toBe(2);
  });

  it("finds every candidate in one pass, as one lookup per commitment would", () => {
    const index = prefixIndexOf([commitmentAt(0), prefixTwinOf(5), commitmentAt(0), commitmentAt(5)]);
    const asked = [commitmentAt(5), `0x${commitmentAt(0)}`, commitmentAt(9)];

    const together = indexCandidatesForEach(index, asked);

    expect(together).toStrictEqual(asked.map((bc) => indexCandidatesFor(index, bc)));
    expect(together).toStrictEqual([[1, 3], [0, 2], []]);
  });

  it("reads a commitment whose only prefix match is another commitment as absent", async () => {
    const list: MockList = { commitments: [commitmentAt(0), prefixTwinOf(5)] };
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    mountStatusRows(server, list, () => SHIELD_BLOCKED);
    const client = sdk();
    await client.syncPoiListIndex(LIST_KEY_HEX);

    const own = commitmentAt(5);
    const got = await client.getPOIsPerList([LIST_KEY_HEX], [{ blindedCommitment: own, type: "Shield" }]);

    expect(got[own][LIST_KEY_HEX]).toBe("Missing");
    expect(client.indexCounters().absent).toBe(1);
  });

  it("refuses a row that does not even carry the indexed prefix rather than calling it absent", async () => {
    const list = listOf(3);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    mountStatusRows(server, list, () => 0, () => new Uint8Array(32));
    const client = sdk();
    await client.syncPoiListIndex(LIST_KEY_HEX);

    await expect(
      client.getPOIsPerList([LIST_KEY_HEX], [{ blindedCommitment: commitmentAt(1), type: "Shield" }]),
    ).rejects.toSatisfy((e: unknown) => RavenError.is(e, "DecodeError"));
    expect(client.indexCounters().absent).toBe(0);
  });
});

describe("the JSON index channel is parsed, never cast", () => {
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

  // The prefix channel of the two-row list `row(0, 0), row(1, 1)` names, read before any body.
  function serve(body: unknown): void {
    mountPrefixChannel(server, LIST_KEY_HEX, listOf(2));
    server.route(
      (req) => req.url === `/v1/poi/${LIST_KEY_HEX}/bc-to-idx-map`,
      (_req, _body, res) => {
        if (typeof body === "string") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(body);
        } else {
          writeJson(res, body);
        }
        return true;
      },
    );
  }

  const client = (): RavenPOINodeInterface =>
    new RavenPOINodeInterface({ endpoint: server.url, bearerToken: TOKEN, poiListIndexStore: false });
  const row = (seed: number, idx: number) => ({ bc: commitmentAt(seed), idx });

  it("returns the rows it checked, with the count they cover", async () => {
    serve({ epoch: 0, listKey: LIST_KEY_HEX.toUpperCase(), entries: [row(0, 0), row(1, 1)] });
    const body = await client().fetchBcToIdxMap(LIST_KEY_HEX);
    expect(body).toStrictEqual({
      epoch: 0,
      listKey: LIST_KEY_HEX,
      rows: 2,
      entries: [row(0, 0), row(1, 1)],
    });
  });

  it.each([
    ["a truncated body", `{"epoch":0,"listKey":"${LIST_KEY_HEX}","entries":[{"bc":"`],
    ["a non-object body", [row(0, 0)]],
    ["an epoch that is not an integer", { epoch: "0", listKey: LIST_KEY_HEX, entries: [] }],
    ["another list's map", { epoch: 0, listKey: "cd".repeat(32), entries: [] }],
    ["entries that are not an array", { epoch: 0, listKey: LIST_KEY_HEX, entries: {} }],
    ["a row with no commitment", { epoch: 0, listKey: LIST_KEY_HEX, entries: [{ idx: 0 }] }],
    ["a row omitted mid-map", { epoch: 0, listKey: LIST_KEY_HEX, entries: [row(0, 0), row(2, 2)] }],
    ["a repeated index", { epoch: 0, listKey: LIST_KEY_HEX, entries: [row(0, 0), row(1, 0)] }],
    ["rows out of order", { epoch: 0, listKey: LIST_KEY_HEX, entries: [row(1, 1), row(0, 0)] }],
  ])("refuses %s", async (_name, body) => {
    serve(body);
    await expect(client().fetchBcToIdxMap(LIST_KEY_HEX)).rejects.toSatisfy((e: unknown) =>
      RavenError.is(e, "DecodeError"),
    );
  });

  it("refuses a body whose tail was dropped, against the prefix channel's count", async () => {
    const list = listOf(4);
    mountJsonIndex(server, LIST_KEY_HEX, list, () => list.commitments.slice(0, 3));
    mountPrefixChannel(server, LIST_KEY_HEX, list);

    await expect(client().fetchBcToIdxMap(LIST_KEY_HEX)).rejects.toSatisfy(
      (e: unknown) =>
        RavenError.is(e, "DecodeError") && /carries 3 rows .* serves 4/.test(e.message),
    );
  });

  it("refuses a body with rows the prefix channel does not serve", async () => {
    const list = listOf(3);
    mountJsonIndex(server, LIST_KEY_HEX, list, () => [...list.commitments, commitmentAt(3)]);
    mountPrefixChannel(server, LIST_KEY_HEX, list);

    await expect(client().fetchBcToIdxMap(LIST_KEY_HEX)).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "DecodeError") && /carries 4 rows, more/.test(e.message),
    );
  });

  it("refuses a body whose last rows name other commitments than the prefix channel's", async () => {
    const list = listOf(3);
    mountJsonIndex(server, LIST_KEY_HEX, list, () => [
      list.commitments[0],
      list.commitments[1],
      commitmentAt(42),
    ]);
    mountPrefixChannel(server, LIST_KEY_HEX, list);

    await expect(client().fetchBcToIdxMap(LIST_KEY_HEX)).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "DecodeError") && /row 2 differs/.test(e.message),
    );
  });

  it("reads the whole prefix channel before the body and compares every row", async () => {
    const list = listOf(BC_INDEX_RESUME_ALIGN_ROWS + 3);
    mountJsonIndex(server, LIST_KEY_HEX, list);
    mountPrefixChannel(server, LIST_KEY_HEX, list);

    const body = await client().fetchBcToIdxMap(LIST_KEY_HEX);

    expect(body.rows).toBe(BC_INDEX_RESUME_ALIGN_ROWS + 3);
    expect(server.requests.map((r) => r.url)).toStrictEqual([
      `/v1/poi/${LIST_KEY_HEX}/bc-prefixes?since=0`,
      `/v1/poi/${LIST_KEY_HEX}/bc-to-idx-map`,
    ]);
  });

  // A row count on a multiple of the resume window left a tail comparison with no rows in it.
  it("refuses a last row that differs when the body ends on a resume boundary", async () => {
    const list = listOf(2 * BC_INDEX_RESUME_ALIGN_ROWS);
    const last = list.commitments.length - 1;
    mountJsonIndex(server, LIST_KEY_HEX, list, () =>
      list.commitments.map((bc, idx) => (idx === last ? commitmentAt(0x7777) : bc)),
    );
    mountPrefixChannel(server, LIST_KEY_HEX, list);

    await expect(client().fetchBcToIdxMap(LIST_KEY_HEX)).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "DecodeError") && new RegExp(`row ${last} differs`).test(e.message),
    );
  });

  it.each([
    ["at the end", 2 * BC_INDEX_RESUME_ALIGN_ROWS - 1],
    ["far below the last resume window", 1_000],
  ])("refuses a row omitted and hidden by relabelling, with a forged row %s", async (_where, at) => {
    const list = listOf(2 * BC_INDEX_RESUME_ALIGN_ROWS);
    mountJsonIndex(server, LIST_KEY_HEX, list, () => {
      const forged = list.commitments.filter((_bc, idx) => idx !== 100);
      forged.splice(at, 0, commitmentAt(0x7777));
      return forged;
    });
    mountPrefixChannel(server, LIST_KEY_HEX, list);

    await expect(client().fetchBcToIdxMap(LIST_KEY_HEX)).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "DecodeError") && /row 100 differs/.test(e.message),
    );
  });

  it("accepts a body an append overtook between the two reads, after reading the new tail", async () => {
    const list = listOf(BC_INDEX_RESUME_ALIGN_ROWS + 3);
    mountJsonIndex(server, LIST_KEY_HEX, list, () => {
      list.commitments.push(commitmentAt(list.commitments.length));
      return list.commitments;
    });
    mountPrefixChannel(server, LIST_KEY_HEX, list);

    const body = await client().fetchBcToIdxMap(LIST_KEY_HEX);

    expect(body.rows).toBe(BC_INDEX_RESUME_ALIGN_ROWS + 4);
    expect(prefixRequests(server)).toStrictEqual([
      `/v1/poi/${LIST_KEY_HEX}/bc-prefixes?since=0`,
      `/v1/poi/${LIST_KEY_HEX}/bc-prefixes?since=${BC_INDEX_RESUME_ALIGN_ROWS}`,
    ]);
  });

  it("refuses a preloaded index whose rows disagree with the prefix channel's", async () => {
    const list = listOf(3);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    mountStatusRows(server, list, () => SHIELD_BLOCKED);
    const forged = [list.commitments[0], commitmentAt(42), list.commitments[2]];
    const bound = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, targetNamingCtx()]]),
      poiListIndexes: new Map([[LIST_KEY_HEX, prefixIndexOf(forged)]]),
      poiListIndexStore: false,
    });

    await expect(
      bound.getPOIsPerList([LIST_KEY_HEX], [{ blindedCommitment: commitmentAt(99), type: "Shield" }]),
    ).rejects.toSatisfy((e: unknown) => RavenError.is(e, "DecodeError"));
  });

  it("refuses rows that are not a gap-free prefix when turning them into an index", () => {
    expect(() => bcPrefixIndexFromRows(0, [row(0, 1)])).toThrow(/gap-free prefix/);
    expect(() => bcPrefixIndexFromRows(0, [{ bc: "ff", idx: 0 }])).toThrow(/gap-free prefix/);
  });

  it("keeps the status row's commitment check on a bound index", async () => {
    const list = listOf(2);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    mountStatusRows(server, list, () => 0, () => statusRow(0, commitmentAt(1)));
    const bound = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, targetNamingCtx()]]),
      poiListIndexStore: false,
    });
    await bound.syncPoiListIndex(LIST_KEY_HEX);

    await expect(
      bound.getPOIsPerList([LIST_KEY_HEX], [{ blindedCommitment: commitmentAt(0), type: "Shield" }]),
    ).rejects.toSatisfy((e: unknown) => RavenError.is(e, "DecodeError"));
  });
});

describe("an index this node did not produce is checked row by row before it answers", () => {
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

  function preloaded(
    index: BcPrefixIndex,
    policy?: RavenConfig["indexStalenessPolicy"],
  ): RavenPOINodeInterface {
    return new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, targetNamingCtx()]]),
      poiListIndexes: new Map([[LIST_KEY_HEX, index]]),
      indexStalenessPolicy: policy,
      poiListIndexStore: false,
    });
  }

  it("refuses a substituted row below the resume window instead of reading its member as Missing", async () => {
    const list = listOf(BC_INDEX_RESUME_ALIGN_ROWS + 5);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    mountStatusRows(server, list, () => SHIELD_BLOCKED);
    const forged = [...list.commitments];
    forged[10] = commitmentAt(0x7777);
    const member = [{ blindedCommitment: list.commitments[10], type: "Shield" as const }];

    const refusing = preloaded(prefixIndexOf(forged));
    await expect(refusing.getPOIsPerList([LIST_KEY_HEX], member)).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "DecodeError") && /row 10 differs/.test(e.message),
    );
    expect(refusing.indexCounters().absent).toBe(0);
    expect(prefixRequests(server)[0]).toBe(`/v1/poi/${LIST_KEY_HEX}/bc-prefixes?since=0`);

    const deciding = preloaded(prefixIndexOf(forged), "answer-at-index-rows");
    const got = await deciding.getPOIsPerList([LIST_KEY_HEX], member);
    expect(got[list.commitments[10]][LIST_KEY_HEX]).toBe("MissingStale");
    expect(deciding.indexCounters().absent).toBe(0);
  });

  it("re-reads every held row of an index resumed with no rows named as confirmed", async () => {
    const list = listOf(BC_INDEX_RESUME_ALIGN_ROWS + 5);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    const forged = [...list.commitments];
    forged[10] = commitmentAt(0x7777);

    await expect(
      resumeBcPrefixIndex(fetch, server.url, LIST_KEY_HEX, {}, prefixIndexOf(forged)),
    ).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "DecodeError") && /row 10 differs/.test(e.message),
    );
    expect(prefixRequests(server)).toStrictEqual([`/v1/poi/${LIST_KEY_HEX}/bc-prefixes?since=0`]);
  });

  it("reads a preloaded index in full once, then only its tail", async () => {
    const list = listOf(BC_INDEX_RESUME_ALIGN_ROWS + 5);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    mountStatusRows(server, list, () => SHIELD_BLOCKED);
    const client = preloaded(prefixIndexOf(list.commitments));
    const stranger = [{ blindedCommitment: commitmentAt(0x99999), type: "Shield" as const }];

    const first = await client.getPOIsPerList([LIST_KEY_HEX], stranger);
    await client.getPOIsPerList([LIST_KEY_HEX], stranger);

    expect(first[commitmentAt(0x99999)][LIST_KEY_HEX]).toBe("Missing");
    expect(prefixRequests(server)).toStrictEqual([
      `/v1/poi/${LIST_KEY_HEX}/bc-prefixes?since=0`,
      `/v1/poi/${LIST_KEY_HEX}/bc-prefixes?since=${BC_INDEX_RESUME_ALIGN_ROWS}`,
    ]);
  });
});

describe("a sync reads the node, never a cache in front of it", () => {
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

  it("asks for every prefix segment and the JSON map with the HTTP cache bypassed", async () => {
    const list = listOf(3);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    mountStatusRows(server, list, () => SHIELD_BLOCKED);
    const inits: (RequestInit | undefined)[] = [];
    const recording: typeof fetch = async (input, init) => {
      if (/\/bc-(prefixes|to-idx-map)/.test(String(input))) inits.push(init);
      return fetch(input, init);
    };
    const client = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, targetNamingCtx()]]),
      poiListIndexStore: false,
      fetchImpl: recording,
    });
    mountJsonIndex(server, LIST_KEY_HEX, list);

    await client.syncPoiListIndex(LIST_KEY_HEX);
    await client.getPOIsPerList([LIST_KEY_HEX], [{ blindedCommitment: commitmentAt(9), type: "Shield" }]);
    await client.fetchBcToIdxMap(LIST_KEY_HEX);

    expect(inits).toHaveLength(4);
    for (const init of inits) expect(init?.cache).toBe("no-cache");
  });
});

describe("a stale absence is told apart in the verdict itself", () => {
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

  it("answers MissingStale on the list whose index is stale and Missing on the current one", async () => {
    const other = "cd".repeat(32);
    const current = listOf(3);
    const stale = listOf(3);
    mountPrefixChannel(server, LIST_KEY_HEX, current);
    mountPrefixChannel(server, other, stale);
    mountStatusRows(server, current, () => SHIELD_BLOCKED);
    const client = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([
        [`t1Status:${LIST_KEY_HEX}`, targetNamingCtx()],
        [`t1Status:${other}`, targetNamingCtx()],
      ]),
      indexStalenessPolicy: "answer-at-index-rows",
      poiListIndexStore: false,
    });
    await client.syncPoiListIndex(LIST_KEY_HEX);
    await client.syncPoiListIndex(other);
    stale.failStatus = 503;

    const stranger = commitmentAt(99);
    const got = await client.getPOIsPerList(
      [LIST_KEY_HEX, other],
      [{ blindedCommitment: stranger, type: "Shield" }],
    );

    expect(got[stranger]).toStrictEqual({ [LIST_KEY_HEX]: "Missing", [other]: "MissingStale" });
    expect(client.indexCounters()).toStrictEqual({
      absent: 1,
      absentFromStaleIndex: 1,
      absentFromBareMap: 0,
      refused: 0,
      staleIndexesCaught: 0,
    });
  });
});

describe("a failed sync costs only the absences it cannot vouch for", () => {
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

  function statusClient(fetchImpl?: typeof fetch): RavenPOINodeInterface {
    return new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, targetNamingCtx()]]),
      poiListIndexStore: false,
      fetchImpl,
    });
  }

  it("answers a member from the rows held and refuses only an absence", async () => {
    const list = listOf(3);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    mountStatusRows(server, list, () => SHIELD_BLOCKED);
    const client = statusClient();
    await client.syncPoiListIndex(LIST_KEY_HEX);
    list.failStatus = 503;
    const member = { blindedCommitment: list.commitments[1], type: "Shield" as const };

    const got = await client.getPOIsPerList([LIST_KEY_HEX], [member]);
    expect(got[list.commitments[1]][LIST_KEY_HEX]).toBe("ShieldBlocked");

    await expect(
      client.getPOIsPerList(
        [LIST_KEY_HEX],
        [member, { blindedCommitment: commitmentAt(99), type: "Shield" }],
      ),
    ).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "ServerError") && /holds 3 rows/.test(e.message),
    );
    expect(client.indexCounters()).toMatchObject({ absent: 0, refused: 1 });
  });

  it("reads an absence as Unreachable when the sync fails on the network", async () => {
    const list = listOf(3);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    mountStatusRows(server, list, () => SHIELD_BLOCKED);
    let down = false;
    const client = statusClient(async (input, init) => {
      if (down && String(input).includes("/bc-prefixes")) throw new TypeError("fetch failed");
      return fetch(input, init);
    });
    await client.syncPoiListIndex(LIST_KEY_HEX);
    down = true;

    const stranger = commitmentAt(99);
    const got = await client.getPOIsPerList(
      [LIST_KEY_HEX],
      [
        { blindedCommitment: list.commitments[1], type: "Shield" },
        { blindedCommitment: stranger, type: "Shield" },
      ],
    );

    expect(got[list.commitments[1]][LIST_KEY_HEX]).toBe("ShieldBlocked");
    expect(got[stranger][LIST_KEY_HEX]).toBe("Unreachable");
    expect(client.indexCounters()).toMatchObject({ absent: 0, refused: 1 });
  });

  it("proves a member when the sync fails, and refuses an absent one before any query", async () => {
    const list = listOf(3);
    const tree = ppoiTree(list.commitments);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, body, res) => {
        const slots = batchTargets(body).map((target) =>
          path10Slot({
            bcHex: list.commitments[target],
            nodes: tree.proofs[target].elements.map((node) => hexToBytes(node)),
          }),
        );
        res.writeHead(200, {
          "content-type": "application/octet-stream",
          "x-raven-freshness": "lag_blocks=0 applied_height=0 epoch=1 confidence=1",
        });
        res.end(Buffer.from(encodeBatchResponseNodes(slots)));
        return true;
      },
    );
    const client = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t2Path:${LIST_KEY_HEX}`, targetNamingCtx(512)]]),
      ppoiPinnedRoots: new Map([[`${LIST_KEY_HEX}:0`, tree.root]]),
      poiListIndexStore: false,
    });
    await client.syncPoiListIndex(LIST_KEY_HEX);
    list.failStatus = 503;

    const proofs = await client.getPOIMerkleProofs(LIST_KEY_HEX, [list.commitments[1]]);
    expect(proofs.map((proof) => proof.root)).toStrictEqual([tree.root]);

    const sent = batchRequests(server);
    await expect(
      client.getPOIMerkleProofs(LIST_KEY_HEX, [commitmentAt(99)]),
    ).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "ServerError") && /holds 3 rows/.test(e.message),
    );
    expect(batchRequests(server)).toBe(sent);
    expect(client.indexCounters().refused).toBe(1);
  });
});

describe("syncs of one index run one at a time", () => {
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

  it("never lets a slower sync land an older list over a newer one", async () => {
    const list = listOf(3);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    let hold: { reached: () => void; released: Promise<void> } | undefined;
    const client = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      poiListIndexStore: false,
      fetchImpl: async (input, init) => {
        const res = await fetch(input, init);
        const gate = hold;
        if (gate !== undefined && String(input).includes("/bc-prefixes")) {
          hold = undefined;
          gate.reached();
          await gate.released;
        }
        return res;
      },
    });
    await client.syncPoiListIndex(LIST_KEY_HEX);
    let reached = (): void => undefined;
    let release = (): void => undefined;
    const answered = new Promise<void>((resolve) => (reached = resolve));
    hold = { reached, released: new Promise<void>((resolve) => (release = resolve)) };

    const slow = client.syncPoiListIndex(LIST_KEY_HEX);
    await answered;
    list.commitments.push(commitmentAt(3));
    const fast = client.syncPoiListIndex(LIST_KEY_HEX);
    await new Promise((resolve) => setTimeout(resolve, 50));
    release();
    await Promise.all([slow, fast]);

    expect((await client.poiListIndexCandidates(LIST_KEY_HEX, commitmentAt(3))).rows).toBe(4);
    expect(client.indexCounters().staleIndexesCaught).toBe(1);
  });
});

describe("a proof has no answer for an absence, so each kind is refused and counted apart", () => {
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

  function prover(
    extra: Pick<RavenConfig, "bcToIdxMaps" | "indexStalenessPolicy"> = {},
  ): RavenPOINodeInterface {
    return new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t2Path:${LIST_KEY_HEX}`, targetNamingCtx(512)]]),
      poiListIndexStore: false,
      ...extra,
    });
  }
  const strangers = [commitmentAt(98), commitmentAt(99)];

  it("counts an absence from an index synced in the call as a current one", async () => {
    mountPrefixChannel(server, LIST_KEY_HEX, listOf(3));
    const client = prover();
    await client.syncPoiListIndex(LIST_KEY_HEX);

    await expect(client.getPOIMerkleProofs(LIST_KEY_HEX, strangers)).rejects.toSatisfy(
      (e: unknown) =>
        RavenError.is(e, "InvalidQuery") && /holds the 3 rows the node serves/.test(e.message),
    );
    expect(client.indexCounters()).toMatchObject({ absent: 2, absentFromStaleIndex: 0, refused: 0 });
    expect(batchRequests(server)).toBe(0);
  });

  it("says a stale index's absence cannot be shown current, and counts it apart", async () => {
    const list = listOf(3);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    const client = prover({ indexStalenessPolicy: "answer-at-index-rows" });
    await client.syncPoiListIndex(LIST_KEY_HEX);
    list.failStatus = 503;

    await expect(client.getPOIMerkleProofs(LIST_KEY_HEX, strangers)).rejects.toSatisfy(
      (e: unknown) =>
        RavenError.is(e, "InvalidQuery") && /cannot be shown current/.test(e.message),
    );
    expect(client.indexCounters()).toMatchObject({ absent: 0, absentFromStaleIndex: 2, refused: 0 });
    expect(batchRequests(server)).toBe(0);
  });

  it("refuses a bare map's absence by default and counts it apart when the caller decides", async () => {
    const bcToIdxMaps = new Map([[LIST_KEY_HEX, new Map([[commitmentAt(0), 0]])]]);

    const refusing = prover({ bcToIdxMaps });
    await expect(refusing.getPOIMerkleProofs(LIST_KEY_HEX, strangers)).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "InvalidQuery") && /carries no row count/.test(e.message),
    );
    expect(refusing.indexCounters()).toMatchObject({ absent: 0, absentFromBareMap: 0, refused: 1 });

    const deciding = prover({ bcToIdxMaps, indexStalenessPolicy: "answer-at-index-rows" });
    await expect(deciding.getPOIMerkleProofs(LIST_KEY_HEX, strangers)).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "InvalidQuery") && /carries no row count/.test(e.message),
    );
    expect(deciding.indexCounters()).toMatchObject({ absent: 0, absentFromBareMap: 2, refused: 0 });
    expect(batchRequests(server)).toBe(0);
  });
});
