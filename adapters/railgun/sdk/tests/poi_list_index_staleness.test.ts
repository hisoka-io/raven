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
import { encodeBatchResponseNodes } from "./helpers/auth_path_stub";
import { blockLabel, forestConfig } from "./helpers/forest";
import {
  batchTargets,
  commitmentAt,
  mountPrefixChannel,
  prefixIndexOf,
  prefixTwinOf,
  targetNamingCtx,
  type MockList,
} from "./helpers/prefix_channel";
import { startMockServer, type MockServer } from "./helpers/mock_server";
import { PATH10_ROW_BYTES, path10Slot } from "./helpers/path10_row";
import { ppoiTree } from "./helpers/ppoi_tree";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "ab".repeat(32);

function listOf(rows: number): MockList {
  return { commitments: Array.from({ length: rows }, (_unused, row) => commitmentAt(row)) };
}

function prefixRequests(server: MockServer): string[] {
  return server.requests.filter((r) => r.url.includes("/bc-prefixes")).map((r) => r.url);
}

function batchRequests(server: MockServer): number {
  return server.requests.filter((r) => /\/batch$/.test(r.url)).length;
}

/** A client serving LIST_KEY_HEX on chain 1, with whatever else the test sets. */
function client(
  server: MockServer,
  extra: Partial<RavenConfig> = {},
  entrySize = 32,
): RavenPOINodeInterface {
  return new RavenPOINodeInterface({
    ...forestConfig({
      endpoint: server.url,
      listKeyHex: LIST_KEY_HEX,
      ctx: targetNamingCtx(entrySize),
    }),
    bearerToken: TOKEN,
    ...extra,
  });
}

const stranger = (tag = 99) => [{ blindedCommitment: commitmentAt(tag), type: "Shield" as const }];

/** Serves a real depth-16 tree's rows for the list's commitments, so a proof folds. */
function mountTreeRows(server: MockServer, commitments: readonly string[]): string {
  const tree = ppoiTree(commitments);
  server.route(
    (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
    (_req, body, res) => {
      const slots = batchTargets(body).map((target) =>
        path10Slot({
          bcHex: commitments[target],
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
  return tree.root;
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

  it("catches an index read before an append instead of reading the new member as Missing", async () => {
    const list = listOf(3);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    const sdk = client(server);
    expect((await sdk.syncPoiListIndex(LIST_KEY_HEX)).total).toBe(3);

    const appended = commitmentAt(3);
    list.commitments.push(appended);
    const got = await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: appended, type: "Shield" }],
    );

    expect(got[appended][LIST_KEY_HEX]).toBe("Valid");
    expect(sdk.indexCounters()).toStrictEqual({ absent: 0, staleIndexesCaught: 1 });
  });

  it("answers a commitment absent from every served row as Missing, and counts it", async () => {
    mountPrefixChannel(server, LIST_KEY_HEX, listOf(3));
    const sdk = client(server);
    await sdk.syncPoiListIndex(LIST_KEY_HEX);
    server.requests.length = 0;

    const got = await sdk.getPOIsPerList([LIST_KEY_HEX], stranger());

    expect(got[commitmentAt(99)][LIST_KEY_HEX]).toBe("Missing");
    expect(sdk.indexCounters()).toStrictEqual({ absent: 1, staleIndexesCaught: 0 });
    expect(prefixRequests(server)).toStrictEqual([`/v1/poi/${LIST_KEY_HEX}/bc-prefixes?since=0`]);
  });

  it("refuses when the index cannot be brought up to the node's list, answering nothing", async () => {
    const list = listOf(3);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    const sdk = client(server);
    await sdk.syncPoiListIndex(LIST_KEY_HEX);
    list.failStatus = 503;
    server.requests.length = 0;

    await expect(sdk.getPOIsPerList([LIST_KEY_HEX], stranger())).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "ServerError") && /could not be brought up/.test(e.message),
    );
    await expect(
      sdk.getPOIsPerList("V2_PoseidonMerkle", { type: 0, id: 1 }, [LIST_KEY_HEX], stranger()),
    ).resolves.toStrictEqual({});
    expect(sdk.indexCounters().absent).toBe(0);
    expect(batchRequests(server)).toBe(0);
  });

  it("refuses a node that serves fewer rows than the index already holds", async () => {
    mountPrefixChannel(server, LIST_KEY_HEX, listOf(3));
    const held = prefixIndexOf(listOf(5).commitments);
    const sdk = client(server, { poiListIndexes: new Map([[`1:${LIST_KEY_HEX}`, held]]) });

    await expect(sdk.getPOIsPerList([LIST_KEY_HEX], stranger())).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "StaleAdapter") && /serves 3 rows/.test(e.message),
    );
    expect(sdk.indexCounters().absent).toBe(0);
  });

  it("refuses a node whose re-read rows differ from the rows the index holds", async () => {
    mountPrefixChannel(server, LIST_KEY_HEX, listOf(3));
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
    const sdk = client(server);
    await sdk.syncPoiListIndex(LIST_KEY_HEX);
    server.requests.length = 0;
    list.commitments.push(commitmentAt(held));

    const synced: BcPrefixIndex = await sdk.syncPoiListIndex(LIST_KEY_HEX);

    expect(synced.total).toBe(held + 1);
    expect(prefixRequests(server)).toStrictEqual([
      `/v1/poi/${LIST_KEY_HEX}/bc-prefixes?since=${BC_INDEX_RESUME_ALIGN_ROWS}`,
    ]);
  });

  it("sends the same requests whether or not the commitments are on the list", async () => {
    mountPrefixChannel(server, LIST_KEY_HEX, listOf(4));
    const shape = async (bcs: string[]): Promise<string[]> => {
      const sdk = client(server);
      await sdk.syncPoiListIndex(LIST_KEY_HEX);
      server.requests.length = 0;
      await sdk.getPOIsPerList(
        [LIST_KEY_HEX],
        bcs.map((blindedCommitment) => ({ blindedCommitment, type: "Shield" as const })),
      );
      return server.requests.map((r) => `${r.method} ${r.url}`);
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

  it("moves a proof past a colliding row to the commitment's own", async () => {
    const list: MockList = {
      commitments: [commitmentAt(0), prefixTwinOf(5), commitmentAt(2), commitmentAt(5)],
    };
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    const root = mountTreeRows(server, list.commitments);
    const sdk = client(server, { ppoiPinnedRoots: new Map([[`1:${LIST_KEY_HEX}:0`, root]]) }, PATH10_ROW_BYTES);

    const [proof] = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [commitmentAt(5)]);

    expect(proof.leaf).toBe(commitmentAt(5));
    expect(BigInt(`0x${proof.indices}`)).toBe(3n);
    expect(batchRequests(server)).toBe(2);
  });

  it("finds every candidate in one pass, as one lookup per commitment would", () => {
    const index = prefixIndexOf([commitmentAt(0), prefixTwinOf(5), commitmentAt(0), commitmentAt(5)]);
    const asked = [commitmentAt(5), `0x${commitmentAt(0)}`, commitmentAt(9)];

    const together = indexCandidatesForEach(index, asked);

    expect(together).toStrictEqual(asked.map((bc) => indexCandidatesFor(index, bc)));
    expect(together).toStrictEqual([[1, 3], [0, 2], []]);
  });

  it("refuses a proof whose only prefix match is another commitment, as absent", async () => {
    const list: MockList = { commitments: [commitmentAt(0), prefixTwinOf(5)] };
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    const root = mountTreeRows(server, list.commitments);
    const sdk = client(server, { ppoiPinnedRoots: new Map([[`1:${LIST_KEY_HEX}:0`, root]]) }, PATH10_ROW_BYTES);

    await expect(sdk.getPOIMerkleProofs(LIST_KEY_HEX, [commitmentAt(5)])).rejects.toThrow(
      /not present in list/,
    );
    expect(sdk.indexCounters().absent).toBe(1);
  });

  it("refuses a row that does not even carry the indexed prefix rather than calling it absent", async () => {
    const list = listOf(3);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    // Every row the node serves names a commitment that is not the list's.
    mountTreeRows(server, [commitmentAt(0x70), commitmentAt(0x71), commitmentAt(0x72)]);
    const sdk = client(server, {}, PATH10_ROW_BYTES);

    await expect(sdk.getPOIMerkleProofs(LIST_KEY_HEX, [commitmentAt(1)])).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "DecodeError"),
    );
    expect(sdk.indexCounters().absent).toBe(0);
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

  function preloaded(index: BcPrefixIndex): RavenPOINodeInterface {
    return client(server, { poiListIndexes: new Map([[`1:${LIST_KEY_HEX}`, index]]) });
  }

  it("refuses a preloaded index whose rows disagree with the prefix channel's", async () => {
    const list = listOf(3);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    const forged = [list.commitments[0], commitmentAt(42), list.commitments[2]];

    await expect(preloaded(prefixIndexOf(forged)).getPOIsPerList([LIST_KEY_HEX], stranger())).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "DecodeError"),
    );
  });

  it("refuses a substituted row below the resume window instead of reading its member as Missing", async () => {
    const list = listOf(BC_INDEX_RESUME_ALIGN_ROWS + 5);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    const forged = [...list.commitments];
    forged[10] = commitmentAt(0x7777);
    const member = [{ blindedCommitment: list.commitments[10], type: "Shield" as const }];

    const refusing = preloaded(prefixIndexOf(forged));
    await expect(refusing.getPOIsPerList([LIST_KEY_HEX], member)).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "DecodeError") && /row 10 differs/.test(e.message),
    );
    expect(refusing.indexCounters().absent).toBe(0);
    expect(prefixRequests(server)[0]).toBe(`/v1/poi/${LIST_KEY_HEX}/bc-prefixes?since=0`);

    const engine = preloaded(prefixIndexOf(forged));
    await expect(
      engine.getPOIsPerList("V2_PoseidonMerkle", { type: 0, id: 1 }, [LIST_KEY_HEX], member),
    ).resolves.toStrictEqual({});
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
    const sdk = preloaded(prefixIndexOf(list.commitments));

    const first = await sdk.getPOIsPerList([LIST_KEY_HEX], stranger(0x99999));
    await sdk.getPOIsPerList([LIST_KEY_HEX], stranger(0x99999));

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

  it("asks for every prefix segment with the HTTP cache bypassed", async () => {
    mountPrefixChannel(server, LIST_KEY_HEX, listOf(3));
    const inits: (RequestInit | undefined)[] = [];
    const recording: typeof fetch = async (input, init) => {
      if (/\/bc-prefixes/.test(String(input))) inits.push(init);
      return fetch(input, init);
    };
    const sdk = client(server, { fetchImpl: recording });

    await sdk.syncPoiListIndex(LIST_KEY_HEX);
    await sdk.getPOIsPerList([LIST_KEY_HEX], stranger(9));

    expect(inits).toHaveLength(2);
    for (const init of inits) expect(init?.cache).toBe("no-cache");
  });
});

describe("a failed sync costs a proof only the absences it cannot vouch for", () => {
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

  it("proves a member when the sync fails, and refuses an absent one before any query", async () => {
    const list = listOf(3);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    const root = mountTreeRows(server, list.commitments);
    const sdk = client(server, { ppoiPinnedRoots: new Map([[`1:${LIST_KEY_HEX}:0`, root]]) }, PATH10_ROW_BYTES);
    await sdk.syncPoiListIndex(LIST_KEY_HEX);
    list.failStatus = 503;

    const proofs = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [list.commitments[1]]);
    expect(proofs.map((proof) => proof.root)).toStrictEqual([root]);

    const sent = batchRequests(server);
    await expect(sdk.getPOIMerkleProofs(LIST_KEY_HEX, [commitmentAt(99)])).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "ServerError") && /could not be brought up/.test(e.message),
    );
    expect(batchRequests(server)).toBe(sent);
    expect(sdk.indexCounters().absent).toBe(0);
    expect(server.requests.some((r) => r.url.endsWith(`/${blockLabel(LIST_KEY_HEX, 0)}/batch`))).toBe(true);
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

  const strangers = [commitmentAt(98), commitmentAt(99)];

  it("counts an absence from an index synced in the call as a current one", async () => {
    mountPrefixChannel(server, LIST_KEY_HEX, listOf(3));
    const sdk = client(server, {}, PATH10_ROW_BYTES);
    await sdk.syncPoiListIndex(LIST_KEY_HEX);

    await expect(sdk.getPOIMerkleProofs(LIST_KEY_HEX, strangers)).rejects.toSatisfy(
      (e: unknown) =>
        RavenError.is(e, "InvalidQuery") && /holds the 3 rows the node serves/.test(e.message),
    );
    expect(sdk.indexCounters()).toMatchObject({ absent: 2 });
    expect(batchRequests(server)).toBe(0);
  });

  it("says a stale index's absence cannot be shown current, with the sync's own kind", async () => {
    const list = listOf(3);
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    const sdk = client(server, {}, PATH10_ROW_BYTES);
    await sdk.syncPoiListIndex(LIST_KEY_HEX);
    list.failStatus = 503;

    await expect(sdk.getPOIMerkleProofs(LIST_KEY_HEX, strangers)).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "ServerError") && /cannot be shown current/.test(e.message),
    );
    expect(sdk.indexCounters()).toMatchObject({ absent: 0 });
    expect(batchRequests(server)).toBe(0);
  });
});
