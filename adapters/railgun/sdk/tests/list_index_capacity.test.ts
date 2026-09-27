// A path instance holds one PPOI block, as many rows as its shard config declares and no more. A
// list index is asked at the leaf's place in its block's instance; an index whose block has no
// instance, or whose row the instance does not hold, has no row to answer it, so it is refused by
// name before any query is sent.

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
import { batchTargets, indexHolding, targetNamingCtx } from "./helpers/prefix_channel";
import { TREE_ROWS, shardConfigBincode } from "./helpers/shard_config";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_A = "ab".repeat(32);
const BC_HEX = "9f3c17aa04e1b28d6605c9713fe82b40d1a7c35e96280bf4517ade0c2b6d8391";

function ctxHolding(rows: number, entrySize = PATH10_ROW_BYTES): ClientPirContext {
  return { ...targetNamingCtx(entrySize), shardConfigBincode: shardConfigBincode(rows) };
}

function batches(server: MockServer): { url: string; targets: number[] }[] {
  return server.requests
    .filter((request) => request.url.endsWith("/batch"))
    .map((request) => ({ url: request.url, targets: batchTargets(request.body) }));
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
    ctx: ClientPirContext,
    idx: number,
    labels: [string, string][] = [],
  ): RavenPOINodeInterface {
    const block = Math.floor(idx / LEAVES_PER_PPOI_BLOCK);
    return new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      clientPirContexts: new Map([[`t2Path:1:${LIST_A}`, ctx]]),
      clientPirInstanceLabels: new Map(labels),
      ppoiPinnedRoots: new Map([
        [`1:${LIST_A}:${block}`, path10Root(BC_HEX, nodes, idx % LEAVES_PER_PPOI_BLOCK)],
      ]),
      poiListIndexes: new Map([[`1:${LIST_A}`, indexHolding([[BC_HEX, idx]])]]),
      poiListIndexStore: false,
    });
  }

  it("asks a labelled block's instance at the leaf's row in that block", async () => {
    const idx = LEAVES_PER_PPOI_BLOCK + 7;
    const sdk = pathSdk(ctxHolding(TREE_ROWS), idx, [[`t2Path:1:${LIST_A}:1`, "ppoi-paths-1"]]);

    const [proof] = await sdk.getPOIMerkleProofs(LIST_A, [BC_HEX]);

    expect(proof.leaf).toBe(BC_HEX);
    expect(BigInt(`0x${proof.indices}`)).toBe(7n);
    expect(batches(server)).toEqual([{ url: "/v1/instance/ppoi-paths-1/batch", targets: [7] }]);
  });

  // No whole-list instance exists in a forest, so an unlabelled block is never asked of some
  // other instance at its list index, however many rows that instance's config declares.
  it("refuses a block with no label, naming the label, before any query", async () => {
    const idx = LEAVES_PER_PPOI_BLOCK + 7;
    const sdk = pathSdk(ctxHolding(2 * TREE_ROWS), idx, [[`t2Path:1:${LIST_A}:0`, "ppoi-paths-0"]]);

    const refusal = await refusalOf(sdk.getPOIMerkleProofs(LIST_A, [BC_HEX]));

    expect(refusal.message).toContain(`PPOI block 1, which has no path instance label`);
    expect(refusal.message).toContain(`t2Path:1:${LIST_A}:1`);
    expect(batches(server)).toEqual([]);
  });

  it("refuses a row past a block instance's capacity, naming index, row and capacity", async () => {
    const idx = LEAVES_PER_PPOI_BLOCK + 5_000;
    const sdk = pathSdk(ctxHolding(4_096), idx, [[`t2Path:1:${LIST_A}:1`, "ppoi-paths-1"]]);

    const refusal = await refusalOf(sdk.getPOIMerkleProofs(LIST_A, [BC_HEX]));

    expect(refusal.message).toContain("ppoi-paths-1");
    expect(refusal.message).toMatch(/list index 70536 \(row 5000 of block 1\) is past/);
    expect(refusal.message).toMatch(/capacity of 4096 rows/);
    expect(batches(server)).toEqual([]);
  });

  it("refuses a context whose shard config declares no row count", async () => {
    const sdk = pathSdk(
      { ...targetNamingCtx(PATH10_ROW_BYTES), shardConfigBincode: new Uint8Array(0) },
      7,
      [[`t2Path:1:${LIST_A}:0`, "ppoi-paths-0"]],
    );

    const refusal = await refusalOf(sdk.getPOIMerkleProofs(LIST_A, [BC_HEX]));

    expect(refusal.message).toMatch(/shard config gives no row count/);
    expect(batches(server)).toEqual([]);
  });
});
