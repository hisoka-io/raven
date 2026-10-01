/**
 * Multi-input spend over the private path. N=1/2/4/13 (the upstream circuitConfigs.js input
 * cap) in one block, a spend whose inputs sit in three blocks, and the status of several
 * commitments on several lists answered without cross-contamination.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { LEAVES_PER_PPOI_BLOCK, RavenPOINodeInterface, hexToBytes } from "../src/index";
import { TOKEN, encodeBatchResponseNodes, stubCtx } from "./helpers/auth_path_stub";
import { blockLabel, forestConfig } from "./helpers/forest";
import { startMockServer, writeJsonRpcResult, type MockServer } from "./helpers/mock_server";
import { PATH10_ROW_BYTES, path10Slot } from "./helpers/path10_row";
import { ppoiTree } from "./helpers/ppoi_tree";
import { commitmentAt, mountPrefixChannel, targetNamingCtx } from "./helpers/prefix_channel";
import { namedBatchTargets } from "./helpers/private_wire";

const LIST_KEY_HEX = "abababababababababababababababababababababababababababababababab";

interface Note {
  readonly bc: string;
  readonly index: number;
  readonly elements: readonly string[];
}

/** Serves each block's notes at their rows, one instance label per block. */
function mountForest(server: MockServer, notes: readonly Note[]): void {
  server.route(
    (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
    (req, body, res) => {
      const label = decodeURIComponent(/^\/v1\/instance\/([^/]+)\/batch$/.exec(req.url ?? "")![1]);
      const inBlock = notes.filter(
        (note) => blockLabel(LIST_KEY_HEX, Math.floor(note.index / LEAVES_PER_PPOI_BLOCK)) === label,
      );
      const slots = namedBatchTargets(body).map((row) => {
        const note =
          inBlock.find((candidate) => candidate.index % LEAVES_PER_PPOI_BLOCK === row) ?? inBlock[0];
        return path10Slot({ bcHex: note.bc, nodes: note.elements.map((e) => hexToBytes(e)) });
      });
      res.writeHead(200, {
        "content-type": "application/octet-stream",
        "x-raven-freshness": "lag_blocks=0 applied_height=0 epoch=1 confidence=1",
      });
      res.end(Buffer.from(encodeBatchResponseNodes(slots)));
      return true;
    },
  );
}

function forestSdk(server: MockServer, notes: readonly Note[], pins: Map<number, string>) {
  return new RavenPOINodeInterface({
    ...forestConfig({
      endpoint: server.url,
      listKeyHex: LIST_KEY_HEX,
      ctx: { ...stubCtx(), entrySize: PATH10_ROW_BYTES },
      placed: notes.map((note) => [note.bc, note.index] as const),
      pins,
    }),
    bearerToken: TOKEN,
  });
}

describe("multi-input spend support", () => {
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

  for (const n of [1, 2, 4, 13]) {
    it(`N=${n}: SDK fetches ${n} PPOI proofs in one call`, async () => {
      const bcs = Array.from({ length: n }, (_, i) => commitmentAt(i + 1));
      const tree = ppoiTree(bcs);
      const notes = bcs.map((bc, index) => ({ bc, index, elements: tree.proofs[index].elements }));
      mountForest(server, notes);

      const proofs = await forestSdk(server, notes, new Map([[0, tree.root]])).getPOIMerkleProofs(
        LIST_KEY_HEX,
        bcs,
      );
      expect(proofs).toHaveLength(n);
      proofs.forEach((p, i) => {
        expect(p.leaf).toBe(bcs[i]);
        expect(p.root).toBe(tree.root);
      });
      // The 13-input cap is the circuit's; the SDK round-trips it in one padded batch.
      expect(server.requests.filter((r) => r.url.endsWith("/batch"))).toHaveLength(1);
    });
  }

  it("a spend whose inputs sit in three blocks asks each block's own instance", async () => {
    const notes: Note[] = [0, 2, 3].map((block, i) => {
      const bc = commitmentAt(0x100 + i);
      return { bc, index: block * LEAVES_PER_PPOI_BLOCK, elements: ppoiTree([bc]).proofs[0].elements };
    });
    const pins = new Map(
      notes.map((note) => [Math.floor(note.index / LEAVES_PER_PPOI_BLOCK), ppoiTree([note.bc]).root]),
    );
    mountForest(server, notes);

    const proofs = await forestSdk(server, notes, pins).getPOIMerkleProofs(
      LIST_KEY_HEX,
      notes.map((note) => note.bc),
    );

    expect(proofs.map((p) => p.leaf)).toEqual(notes.map((note) => note.bc));
    const asked = server.requests.filter((r) => r.url.endsWith("/batch")).map((r) => r.url);
    expect(asked.sort()).toEqual(
      [0, 2, 3].map((block) => `/v1/instance/${blockLabel(LIST_KEY_HEX, block)}/batch`).sort(),
    );
  });

  it("getPOIsPerList answers every (BC, list) cell for several lists and commitments", async () => {
    const lkA = "11".repeat(32);
    const lkB = "22".repeat(32);
    const bcOne = commitmentAt(1);
    const bcTwo = commitmentAt(2);
    mountPrefixChannel(server, lkA, { commitments: [bcOne] });
    mountPrefixChannel(server, lkB, { commitments: [commitmentAt(9)] });
    server.route(
      (req) => req.url === "/",
      (_req, body, res) => {
        writeJsonRpcResult(body, res, null);
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      upstreamFallbackEndpoint: `${server.url}/`,
      clientPirContexts: new Map([
        [`t2Path:1:${lkA}`, targetNamingCtx()],
        [`t2Path:1:${lkB}`, targetNamingCtx()],
      ]),
      poiListIndexStore: false,
    });
    await sdk.submitLegacyTransactProofs(
      [lkB],
      [{ txidIndex: "1", npk: "2", value: "3", tokenHash: "4", blindedCommitment: bcTwo }],
    );

    const got = await sdk.getPOIsPerList(
      [lkA, lkB],
      [
        { blindedCommitment: bcOne, type: "Shield" },
        { blindedCommitment: bcTwo, type: "Transact" },
      ],
    );
    expect(got).toStrictEqual({
      [bcOne]: { [lkA]: "Valid", [lkB]: "Missing" },
      [bcTwo]: { [lkA]: "Missing", [lkB]: "ProofSubmitted" },
    });
  });
});
