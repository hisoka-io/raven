// An instance holds the rows its shard config declares and no more. A list index past them has
// no row, so any answer to it describes something that was never written: it is refused by name,
// before it is asked. One derivation places an index for both routes. A block-labelled instance is
// asked at the leaf's place in its block; any other holds the list from index 0 and is asked at
// the list index itself, because localizing there would read block 1's leaf 0 from block 0's row.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  LEAVES_PER_PPOI_BLOCK,
  RavenError,
  RavenPOINodeInterface,
  type ClientPirContext,
} from "../src/index";
import { encodeBatchResponseNodes } from "./helpers/auth_path_stub";
import { startMockServer, type MockServer } from "./helpers/mock_server";
import {
  PATH10_ROW_BYTES,
  path10Root,
  path10Siblings,
  path10Slot,
} from "./helpers/path10_row";
import { batchTargets, statusRow, targetNamingCtx } from "./helpers/prefix_channel";
import { TREE_ROWS, shardConfigBincode } from "./helpers/shard_config";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_A = "ab".repeat(32);
const LIST_B = "cd".repeat(32);
const BC_HEX = "9f3c17aa04e1b28d6605c9713fe82b40d1a7c35e96280bf4517ade0c2b6d8391";
const VALID = 0;

function ctxHolding(rows: number, entrySize = 32): ClientPirContext {
  return { ...targetNamingCtx(entrySize), shardConfigBincode: shardConfigBincode(rows) };
}

function batches(server: MockServer): { url: string; targets: number[] }[] {
  return server.requests
    .filter((request) => request.url.endsWith("/batch"))
    .map((request) => ({ url: request.url, targets: batchTargets(request.body) }));
}

/** One batch per list, each a single cover query at a row that list's instance holds. */
function expectLoneCover(
  asked: { url: string; targets: number[] }[],
  lists: [string, number][],
): void {
  expect(asked.map(({ url }) => url)).toEqual(
    lists.map(([lk]) => `/v1/instance/t1Status-${lk}/batch`),
  );
  asked.forEach(({ targets }, position) => {
    expect(targets).toHaveLength(1);
    expect(targets[0]).toBeLessThan(lists[position][1]);
  });
}

async function refusalOf(call: Promise<unknown>): Promise<Error> {
  let answered: unknown;
  try {
    answered = await call;
  } catch (thrown) {
    expect(RavenError.is(thrown, "InvalidQuery"), `got ${String(thrown)}`).toBe(true);
    return thrown as Error;
  }
  throw new Error(`expected a refusal, got an answer: ${JSON.stringify(answered)}`);
}

describe("a status index the whole-list instance does not hold", () => {
  let server: MockServer;

  beforeAll(async () => {
    server = await startMockServer();
    // Answers every row it is asked for as a Valid row bound to the commitment: the worst case,
    // where only the client stands between an unwritten row and a spend-authorizing verdict.
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, body, res) => {
        res.writeHead(200, {
          "content-type": "application/octet-stream",
          "x-raven-freshness": "lag_blocks=0 applied_height=0 epoch=1 confidence=1",
        });
        const rows = batchTargets(body).map(() => statusRow(VALID, BC_HEX));
        res.end(Buffer.from(encodeBatchResponseNodes(rows)));
        return true;
      },
    );
  });
  afterAll(async () => {
    await server.close();
  });
  afterEach(() => {
    server.requests.length = 0;
  });

  function statusSdk(lists: [string, number, number][]): RavenPOINodeInterface {
    return new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map(lists.map(([lk, rows]) => [`t1Status:${lk}`, ctxHolding(rows)])),
      bcToIdxMaps: new Map(lists.map(([lk, , idx]) => [lk, new Map([[BC_HEX, idx]])])),
    });
  }

  it("refuses index 65,536 of a 65,536-row instance by name and never asks for it", async () => {
    const sdk = statusSdk([[LIST_A, TREE_ROWS, TREE_ROWS]]);

    const refusal = await refusalOf(
      sdk.getPOIsPerList([LIST_A], [{ blindedCommitment: BC_HEX, type: "Shield" }]),
    );

    expect(refusal.message).toMatch(/list index 65536 is past/);
    expect(refusal.message).toMatch(/capacity of 65536 rows/);
    expect(refusal.message).toContain(`t1Status-${LIST_A}`);
    // The list is still asked, exactly as for an absent commitment, so what the node sees does
    // not depend on where the commitment sits: one cover at a row the instance holds.
    expectLoneCover(batches(server), [[LIST_A, TREE_ROWS]]);
  });

  it("names an index and a capacity that differ", async () => {
    const sdk = statusSdk([[LIST_A, 4_096, 4_100]]);

    const refusal = await refusalOf(
      sdk.getPOIsPerList([LIST_A], [{ blindedCommitment: BC_HEX, type: "Shield" }]),
    );

    expect(refusal.message).toMatch(/list index 4100 is past/);
    expect(refusal.message).toMatch(/capacity of 4096 rows/);
    expect(batches(server).flatMap(({ targets }) => targets)).not.toContain(4_100);
  });

  it("asks a whole-list instance at the list index, never a block-local row", async () => {
    const idx = LEAVES_PER_PPOI_BLOCK + 7;
    const sdk = statusSdk([[LIST_A, 2 * TREE_ROWS, idx]]);

    const verdicts = await sdk.getPOIsPerList(
      [LIST_A],
      [{ blindedCommitment: BC_HEX, type: "Shield" }],
    );

    expect(verdicts[BC_HEX][LIST_A]).toBe("Valid");
    expect(batches(server)).toEqual([
      { url: `/v1/instance/t1Status-${LIST_A}/batch`, targets: [idx] },
    ]);
  });

  it("raises the refusal only once every list has been asked", async () => {
    const sdk = statusSdk([
      [LIST_A, TREE_ROWS, TREE_ROWS],
      [LIST_B, TREE_ROWS, 3],
    ]);

    const refusal = await refusalOf(
      sdk.getPOIsPerList([LIST_A, LIST_B], [{ blindedCommitment: BC_HEX, type: "Shield" }]),
    );

    expect(refusal.message).toMatch(/list index 65536 is past the instance's capacity of 65536/);
    const [coverA, realB] = batches(server);
    expectLoneCover([coverA], [[LIST_A, TREE_ROWS]]);
    expect(realB).toEqual({ url: `/v1/instance/t1Status-${LIST_B}/batch`, targets: [3] });
  });
});

describe("a path index the target instance does not hold", () => {
  const nodes = path10Siblings(0x5c);
  let server: MockServer;

  beforeAll(async () => {
    server = await startMockServer();
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, body, res) => {
        res.writeHead(200, {
          "content-type": "application/octet-stream",
          "x-raven-epoch": "1",
          "x-raven-schema-version": "8",
          "x-raven-freshness": "lag_blocks=0 applied_height=0 epoch=1 confidence=1",
        });
        const slots = batchTargets(body).map(() => path10Slot({ bcHex: BC_HEX, nodes }));
        res.end(Buffer.from(encodeBatchResponseNodes(slots)));
        return true;
      },
    );
  });
  afterAll(async () => {
    await server.close();
  });
  afterEach(() => {
    server.requests.length = 0;
  });

  function pathSdk(
    rows: number,
    idx: number,
    labels: [string, string][] = [],
  ): RavenPOINodeInterface {
    const block = Math.floor(idx / LEAVES_PER_PPOI_BLOCK);
    return new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t2Path:${LIST_A}`, ctxHolding(rows, PATH10_ROW_BYTES)]]),
      clientPirInstanceLabels: new Map(labels),
      ppoiPinnedRoots: new Map([
        [`${LIST_A}:${block}`, path10Root(BC_HEX, nodes, idx % LEAVES_PER_PPOI_BLOCK)],
      ]),
      bcToIdxMaps: new Map([[LIST_A, new Map([[BC_HEX, idx]])]]),
    });
  }

  it("asks a labelled block's instance at the leaf's row in that block", async () => {
    const idx = LEAVES_PER_PPOI_BLOCK + 7;
    const sdk = pathSdk(TREE_ROWS, idx, [[`t2Path:${LIST_A}:1`, "ppoi-paths-1"]]);

    const [proof] = await sdk.getPOIMerkleProofs(LIST_A, [BC_HEX]);

    expect(proof.leaf).toBe(BC_HEX);
    expect(batches(server)).toEqual([{ url: "/v1/instance/ppoi-paths-1/batch", targets: [7] }]);
  });

  it("asks an unlabelled list's one instance at the list index", async () => {
    const idx = LEAVES_PER_PPOI_BLOCK + 7;
    const sdk = pathSdk(2 * TREE_ROWS, idx);

    const [proof] = await sdk.getPOIMerkleProofs(LIST_A, [BC_HEX]);

    expect(batches(server)).toEqual([
      { url: `/v1/instance/t2Path-${LIST_A}/batch`, targets: [idx] },
    ]);
    // The row is the list index; the fold still takes the leaf's place in block 1's tree.
    expect(BigInt(`0x${proof.indices}`)).toBe(7n);
  });

  it("refuses a block-1 index on an unlabelled list of one tree, before any request", async () => {
    const idx = LEAVES_PER_PPOI_BLOCK + 7;
    const sdk = pathSdk(TREE_ROWS, idx);

    const refusal = await refusalOf(sdk.getPOIMerkleProofs(LIST_A, [BC_HEX]));

    expect(refusal.message).toMatch(/list index 65543 is past/);
    expect(refusal.message).toMatch(/capacity of 65536 rows/);
    expect(server.requests).toHaveLength(0);
  });

  it("refuses a row past a block instance's capacity, naming index, row and capacity", async () => {
    const idx = LEAVES_PER_PPOI_BLOCK + 5_000;
    const sdk = pathSdk(4_096, idx, [[`t2Path:${LIST_A}:1`, "ppoi-paths-1"]]);

    const refusal = await refusalOf(sdk.getPOIMerkleProofs(LIST_A, [BC_HEX]));

    expect(refusal.message).toContain("ppoi-paths-1");
    expect(refusal.message).toMatch(/list index 70536 \(row 5000 of block 1\) is past/);
    expect(refusal.message).toMatch(/capacity of 4096 rows/);
    expect(server.requests).toHaveLength(0);
  });

  it("refuses a context whose shard config declares no row count", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([
        [
          `t2Path:${LIST_A}`,
          { ...targetNamingCtx(PATH10_ROW_BYTES), shardConfigBincode: new Uint8Array(0) },
        ],
      ]),
      bcToIdxMaps: new Map([[LIST_A, new Map([[BC_HEX, 7]])]]),
    });

    const refusal = await refusalOf(sdk.getPOIMerkleProofs(LIST_A, [BC_HEX]));

    expect(refusal.message).toMatch(/shard config gives no row count/);
    expect(server.requests).toHaveLength(0);
  });
});
