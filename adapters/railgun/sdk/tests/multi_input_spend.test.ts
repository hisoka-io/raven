/**
 * Multi-input spend tests over the legacy passthrough path. N=1/2/4/13 (the
 * upstream circuitConfigs.js input cap) plus a cross-tree spend lock that the
 * SDK fans out per BC and per instance without state cross-contamination.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { RavenPOINodeInterface } from "../src/index";
import { startMockServer, writeJson, type MockServer } from "./helpers/mock_server";
import { ppoiTree } from "./helpers/ppoi_tree";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "abababababababababababababababababababababababababababababababab";

function bcAt(idx: number): string {
  return idx.toString(16).padStart(2, "0").repeat(32);
}

/** The plaintext route does not say which block a proof is in, so its root must be pinned. */
function pinnedSdk(endpoint: string, root: string): RavenPOINodeInterface {
  return new RavenPOINodeInterface({
    endpoint,
    bearerToken: TOKEN,
    useClientPir: false,
    ppoiPinnedRoots: new Map([[`${LIST_KEY_HEX}:0`, root]]),
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
      const bcs = Array.from({ length: n }, (_, i) => bcAt(i + 1));
      const tree = ppoiTree(bcs);
      server.route(
        (req) => req.url === "/v1/poi/merkle-proofs",
        (_req, body, res) => {
          const decoded = JSON.parse(new TextDecoder().decode(body));
          expect(decoded.blindedCommitments).toHaveLength(n);
          writeJson(res, tree.proofs);
          return true;
        },
      );
      const sdk = pinnedSdk(server.url, tree.root);
      const proofs = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, bcs);
      expect(proofs).toHaveLength(n);
      proofs.forEach((p, i) => expect(p.leaf).toBe(bcs[i]));
    });
  }

  it("13-input spend stays at the circuit cap", async () => {
    // 13 = upstream circuitConfigs.js cap; the SDK does not enforce it, only round-trips it
    const n = 13;
    const bcs = Array.from({ length: n }, (_, i) => bcAt(i + 1));
    const tree = ppoiTree(bcs);
    server.route(
      (req) => req.url === "/v1/poi/merkle-proofs",
      (_req, _body, res) => {
        writeJson(res, tree.proofs);
        return true;
      },
    );
    const sdk = pinnedSdk(server.url, tree.root);
    const proofs = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, bcs);
    expect(proofs).toHaveLength(13);
  });

  it("cross-tree spend: 3 commit-tree proofs each from a different tree", async () => {
    // one proof per UTXO, each dispatched to its tree-specific commit-tree route
    const inputs = [
      { tree: 0, leafIndex: 100, sibling: "aa".repeat(32) },
      { tree: 2, leafIndex: 5_000, sibling: "bb".repeat(32) },
      { tree: 3, leafIndex: 75, sibling: "cc".repeat(32) },
    ];
    for (const inp of inputs) {
      server.route(
        (req) => req.url === `/v1/commit-tree/${inp.tree}/merkle-proof`,
        (_req, _body, res) => {
          writeJson(res, {
            leaf: bcAt(inp.tree + 1),
            elements: Array.from({ length: 16 }, () => inp.sibling),
            indices: `0x${inp.leafIndex.toString(16)}`,
            root: "dd".repeat(32),
          });
          return true;
        },
      );
    }
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: false,
    });
    const proofs = await Promise.all(
      inputs.map((inp) => sdk.getMerkleProof(inp.tree, inp.leafIndex)),
    );
    expect(proofs).toHaveLength(3);
    proofs.forEach((p, i) => {
      expect(p.elements).toStrictEqual(Array.from({ length: 16 }, () => inputs[i].sibling));
      expect(p.indices).toBe(inputs[i].leafIndex.toString(16).padStart(64, "0"));
    });
    const wires = sdk.lastWireRequests();
    expect(wires.length).toBe(3);
    const urls = wires.map((w) => w.url);
    expect(urls).toContain(`${server.url}/v1/commit-tree/0/merkle-proof`);
    expect(urls).toContain(`${server.url}/v1/commit-tree/2/merkle-proof`);
    expect(urls).toContain(`${server.url}/v1/commit-tree/3/merkle-proof`);
  });

  it("getPOIsPerList multi-list multi-BC fans out per (list, BC)", async () => {
    const lkA = "11".repeat(32);
    const lkB = "22".repeat(32);
    const bcOne = bcAt(1);
    const bcTwo = bcAt(2);
    server.route(
      (req) => req.url === "/v1/poi/pois-per-list",
      (_req, body, res) => {
        const decoded = JSON.parse(new TextDecoder().decode(body));
        expect(decoded.listKeys).toEqual([lkA, lkB]);
        expect(decoded.blindedCommitmentDatas).toHaveLength(2);
        // BC outer, list key inner — `PoisPerListResponse` and upstream's POIsPerListMap.
        writeJson(res, {
          [bcOne]: { [lkA]: "Valid", [lkB]: "ShieldBlocked" },
          [bcTwo]: { [lkA]: "Missing", [lkB]: "ProofSubmitted" },
        });
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: false,
    });
    const got = await sdk.getPOIsPerList(
      [lkA, lkB],
      [
        { blindedCommitment: bcOne, type: "Shield" },
        { blindedCommitment: bcTwo, type: "Transact" },
      ],
    );
    expect(got[bcOne][lkA]).toBe("Valid");
    expect(got[bcTwo][lkB]).toBe("ProofSubmitted");
  });
});
