/**
 * Multi-input spend tests.
 *
 * Railgun's `circuits-v2/lib/circuitConfigs.js:4-11` caps inputs per
 * spend at 13. We exercise N=1 / N=2 / N=4 / N=13 to lock that the
 * SDK can issue N parallel PIR queries per spend without state
 * cross-contamination, plus a cross-tree spend (UTXOs split across
 * trees 0+2+3) to lock the per-instance routing.
 *
 * Each test uses the legacy passthrough path because that route is
 * tractable to assert against without running real WASM PIR per
 * spend; the encrypted-PIR equivalent is covered by the
 * privacy_all_paths tests at smaller N (the network-shape behavior
 * is the same — the SDK loops BC-by-BC).
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { RavenPOINodeInterface } from "../src/index";
import { startMockServer, writeJson, type MockServer } from "./helpers/mock_server";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "abababababababababababababababababababababababababababababababab";

function bcAt(idx: number): string {
  return idx.toString(16).padStart(2, "0").repeat(32);
}

function leafProof(leaf: string) {
  return {
    leaf,
    elements: Array.from({ length: 16 }, (_, j) => j.toString(16).padStart(2, "0").repeat(32)),
    indices: "0x00",
    root: "ff".repeat(32),
  };
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
      server.route(
        (req) => req.url === "/v1/poi/merkle-proofs",
        (_req, body, res) => {
          const decoded = JSON.parse(new TextDecoder().decode(body));
          expect(decoded.blindedCommitments).toHaveLength(n);
          writeJson(res, bcs.map(leafProof));
          return true;
        },
      );
      const sdk = new RavenPOINodeInterface({
        endpoint: server.url,
        bearerToken: TOKEN,
        useClientPir: false,
      });
      const proofs = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, bcs);
      expect(proofs).toHaveLength(n);
      proofs.forEach((p, i) => expect(p.leaf).toBe(bcs[i]));
    });
  }

  it("13-input spend stays at the circuit cap", async () => {
    // Locks the upstream MAX_OUTPUT cap from
    // circuits-v2/lib/circuitConfigs.js:4-11. Wallet integrators
    // assemble a SpendInfo with at most 13 outputs per
    // transaction-batch; we don't enforce that in the SDK (the
    // wallet does), but we lock that 13 parallel proofs round-trip
    // cleanly through the SDK.
    const n = 13;
    const bcs = Array.from({ length: n }, (_, i) => bcAt(i + 1));
    server.route(
      (req) => req.url === "/v1/poi/merkle-proofs",
      (_req, _body, res) => {
        writeJson(res, bcs.map(leafProof));
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: false,
    });
    const proofs = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, bcs);
    expect(proofs).toHaveLength(13);
  });

  it("cross-tree spend: 3 commit-tree proofs each from a different tree", async () => {
    // Wallet has UTXOs in trees 0, 2, 3 (per the mainnet topology
    // at boot: trees 0/1/2 are closed-static, tree 3 is live). The SDK fetches one
    // commit-tree proof per UTXO; each proof is dispatched to the
    // tree-specific commit-tree-merkle-proof route.
    const inputs = [
      { tree: 0, leafIndex: 100, expectedRoot: "aa".repeat(32) },
      { tree: 2, leafIndex: 5_000, expectedRoot: "bb".repeat(32) },
      { tree: 3, leafIndex: 75, expectedRoot: "cc".repeat(32) },
    ];
    for (const inp of inputs) {
      server.route(
        (req) => req.url === `/v1/commit-tree/${inp.tree}/merkle-proof`,
        (_req, _body, res) => {
          writeJson(res, {
            leaf: bcAt(inp.tree + 1),
            elements: Array.from({ length: 16 }, () => "00".repeat(32)),
            indices: `0x${inp.leafIndex.toString(16)}`,
            root: inp.expectedRoot,
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
    proofs.forEach((p, i) => expect(p.root).toBe(inputs[i].expectedRoot));
    const wires = sdk.lastWireRequests();
    expect(wires.length).toBe(3);
    // Each request hits its own tree URL.
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
        writeJson(res, {
          [lkA]: { [bcOne]: "Valid", [bcTwo]: "Missing" },
          [lkB]: { [bcOne]: "ShieldBlocked", [bcTwo]: "ProofSubmitted" },
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
    expect(got[lkA][bcOne]).toBe("Valid");
    expect(got[lkB][bcTwo]).toBe("ProofSubmitted");
  });
});
