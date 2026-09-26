/**
 * Legacy plaintext-BC fallback tests. With `useClientPir: false` the SDK hits
 * the wallet-shim routes with BCs serialized into the JSON body; these lock
 * that wire shape.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { RavenError, RavenPOINodeInterface, foldMerkleRoot } from "../src/index";

import {
  readJsonRpcRequest,
  startMockServer,
  writeJson,
  writeJsonRpcResult,
  type MockServer,
} from "./helpers/mock_server";
import { ppoiTree } from "./helpers/ppoi_tree";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX =
  "abababababababababababababababababababababababababababababababab";
const BC_VALID = "0000000000000000000000000000000000000000000000000000000000000001";
const BC_BLOCKED = "0000000000000000000000000000000000000000000000000000000000000002";
const BC_SUBMITTED = "0000000000000000000000000000000000000000000000000000000000000003";
const BC_MISSING = "0000000000000000000000000000000000000000000000000000000000000004";

describe("legacy plaintext fallback paths", () => {
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

  // Shield/Transact/Unshield; Nullified is not a BlindedCommitmentType, so Shield repeats to round out 4
  for (const [name, type, bc] of [
    ["Shield", "Shield", BC_VALID],
    ["Transact", "Transact", BC_BLOCKED],
    ["Unshield", "Unshield", BC_SUBMITTED],
    ["Shield-second-instance", "Shield", BC_MISSING],
  ] as const) {
    it(`getPOIsPerList legacy mode handles ${name}`, async () => {
      const expected = { [bc]: { [LIST_KEY_HEX]: "Valid" } };
      server.route(
        (req) => req.url === "/v1/poi/pois-per-list",
        (_req, _body, res) => {
          writeJson(res, expected, {
            "x-raven-freshness": "lag_blocks=1 applied_height=10 epoch=1 confidence=0.99",
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
        [LIST_KEY_HEX],
        [{ blindedCommitment: bc, type }],
      );
      expect(got).toEqual(expected);
      const wires = sdk.lastWireRequests();
      expect(wires.length).toBe(1);
      const decoded = JSON.parse(new TextDecoder().decode(wires[0].body));
      expect(decoded.txidVersion).toBe("V2_PoseidonMerkle");
      expect(decoded.listKeys).toEqual([LIST_KEY_HEX]);
      expect(decoded.blindedCommitmentDatas[0].type).toBe(type);
      expect(decoded.blindedCommitmentDatas[0].blindedCommitment).toBe(bc);
    });
  }

  // PPOI status enum round-trips; outer key BC, inner listKey (upstream POIsPerListMap shape)
  for (const [status, bc] of [
    ["Valid", BC_VALID],
    ["ShieldBlocked", BC_BLOCKED],
    ["ProofSubmitted", BC_SUBMITTED],
    ["Missing", BC_MISSING],
  ] as const) {
    it(`getPOIsPerList legacy mode round-trips POIStatus=${status}`, async () => {
      const expected = { [bc]: { [LIST_KEY_HEX]: status } };
      server.route(
        (req) => req.url === "/v1/poi/pois-per-list",
        (_req, _body, res) => {
          writeJson(res, expected, {
            "x-raven-freshness": "lag_blocks=1 applied_height=10 epoch=1 confidence=0.99",
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
        [LIST_KEY_HEX],
        [{ blindedCommitment: bc, type: "Shield" }],
      );
      expect(got[bc][LIST_KEY_HEX]).toBe(status);
    });
  }

  for (const n of [1, 2, 4, 13]) {
    it(`getPOIMerkleProofs legacy mode N=${n} fetches N proofs`, async () => {
      const bcs = Array.from({ length: n }, (_, i) =>
        i.toString(16).padStart(2, "0").repeat(32),
      );
      const { root, proofs } = ppoiTree(bcs);
      server.route(
        (req) => req.url === "/v1/poi/merkle-proofs",
        (_req, _body, res) => {
          writeJson(res, proofs, {
            "x-raven-freshness": "lag_blocks=1 applied_height=10 epoch=1 confidence=0.99",
          });
          return true;
        },
      );
      const sdk = new RavenPOINodeInterface({
        endpoint: server.url,
        bearerToken: TOKEN,
        useClientPir: false,
        ppoiPinnedRoots: new Map([[`${LIST_KEY_HEX}:0`, root]]),
      });
      const got = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, bcs);
      expect(got).toHaveLength(n);
      expect(got[0].leaf).toBe(bcs[0]);
      expect(got[n - 1].leaf).toBe(bcs[n - 1]);
      const wires = sdk.lastWireRequests();
      const decoded = JSON.parse(new TextDecoder().decode(wires[0].body));
      expect(decoded.blindedCommitments).toEqual(bcs);
      expect(decoded.listKey).toBe(LIST_KEY_HEX);
    });
  }

  it("getMerkleProof legacy mode hits commit-tree route with leafIndex body", async () => {
    const proof = {
      leaf: "00".repeat(32),
      elements: Array.from({ length: 16 }, () => "11".repeat(32)),
      indices: (42).toString(16).padStart(64, "0"),
      root: "ff".repeat(32),
    };
    server.route(
      (req) => req.url === "/v1/commit-tree/2/merkle-proof",
      (_req, _body, res) => {
        writeJson(res, proof);
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: false,
    });
    const got = await sdk.getMerkleProof(2, 42);
    expect(got).toStrictEqual({
      kind: "authPath",
      elements: proof.elements,
      indices: proof.indices,
    });
    const wires = sdk.lastWireRequests();
    expect(wires.length).toBe(1);
    const decoded = JSON.parse(new TextDecoder().decode(wires[0].body));
    expect(decoded.leafIndex).toBe(42);
    // Tree number is encoded into the URL, NOT the body.
    expect(wires[0].url).toMatch(/\/v1\/commit-tree\/2\/merkle-proof$/);
  });

  it("legacy mode getPOIsPerList raises on non-200 status", async () => {
    server.route(
      (req) => req.url === "/v1/poi/pois-per-list",
      (_req, _body, res) => {
        res.writeHead(503, { "content-type": "text/plain" });
        res.end("instance not ready");
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: false,
    });
    await expect(
      sdk.getPOIsPerList(
        [LIST_KEY_HEX],
        [{ blindedCommitment: BC_VALID, type: "Shield" }],
      ),
    ).rejects.toThrow(/503/);
  });

  it("legacy mode propagates upstream fallback URL when freshness is below floor", async () => {
    // low-confidence freshness header forces the upstream passthrough
    server.route(
      (req) => req.url === "/v1/poi/pois-per-list",
      (_req, _body, res) => {
        writeJson(
          res,
          {},
          {
            "x-raven-freshness": "lag_blocks=10 applied_height=5 epoch=1 confidence=0.10",
          },
        );
        return true;
      },
    );
    server.route(
      (req) => req.url === "/",
      (_req, body, res) => {
        const request = writeJsonRpcResult(
          body,
          res,
          { [BC_VALID]: { [LIST_KEY_HEX]: "Valid" } },
        );
        expect(request.method).toBe("ppoi_pois_per_list");
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      upstreamFallbackEndpoint: server.url,
      useClientPir: false,
      freshnessConfidenceFloor: 0.5,
    });
    const got = await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_VALID, type: "Shield" }],
    );
    expect(got[BC_VALID][LIST_KEY_HEX]).toBe("Valid");
    expect(sdk.lastWireRequests().length).toBe(2);
  });

  it("legacy mode does NOT trigger fallback when freshness is missing", async () => {
    server.route(
      (req) => req.url === "/v1/poi/pois-per-list",
      (_req, _body, res) => {
        writeJson(res, { [BC_VALID]: { [LIST_KEY_HEX]: "Valid" } });
        return true;
      },
    );
    server.route(
      (req) => req.url === "/",
      (_req, body, _res) => {
        expect(readJsonRpcRequest(body).method).toBe("ppoi_pois_per_list");
        throw new Error("upstream passthrough unexpectedly invoked");
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      upstreamFallbackEndpoint: server.url,
      useClientPir: false,
    });
    const got = await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_VALID, type: "Shield" }],
    );
    expect(got[BC_VALID][LIST_KEY_HEX]).toBe("Valid");
    expect(sdk.lastWireRequests().length).toBe(1);
  });

  // The stale upstream fallback, and the route's own answer, reach the wallet only once the proof
  // folds to a root the caller pinned: neither route says which block a proof is in.
  const PLAINTEXT_TREE = ppoiTree([BC_VALID, BC_BLOCKED]);

  function staleProofsRoute(upstreamProof: unknown = PLAINTEXT_TREE.proofs[0]): void {
    server.route(
      (req) => req.url === "/v1/poi/merkle-proofs",
      (_req, _body, res) => {
        writeJson(res, [], {
          "x-raven-freshness": "lag_blocks=10 applied_height=5 epoch=1 confidence=0.10",
        });
        return true;
      },
    );
    server.route(
      (req) => req.url === "/",
      (_req, body, res) => {
        const request = writeJsonRpcResult(body, res, [upstreamProof]);
        expect(request.method).toBe("ppoi_merkle_proofs");
        return true;
      },
    );
  }

  function servedProofsRoute(proofs: unknown[]): void {
    server.route(
      (req) => req.url === "/v1/poi/merkle-proofs",
      (_req, _body, res) => {
        writeJson(res, proofs, {
          "x-raven-freshness": "lag_blocks=1 applied_height=10 epoch=1 confidence=0.99",
        });
        return true;
      },
    );
  }

  function plaintextSdk(pins?: Map<string, string>, upstream = false): RavenPOINodeInterface {
    return new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: false,
      freshnessConfidenceFloor: 0.5,
      ...(upstream ? { upstreamFallbackEndpoint: server.url } : {}),
      ...(pins ? { ppoiPinnedRoots: pins } : {}),
    });
  }

  async function refusal(run: () => Promise<unknown>): Promise<unknown> {
    try {
      await run();
    } catch (error) {
      return error;
    }
    return undefined;
  }

  it("getPOIMerkleProofs legacy mode falls back when freshness is below floor", async () => {
    staleProofsRoute();
    const sdk = plaintextSdk(new Map([[`${LIST_KEY_HEX}:0`, PLAINTEXT_TREE.root]]), true);
    const got = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_VALID]);
    expect(got).toEqual([PLAINTEXT_TREE.proofs[0]]);
  });

  // Upstream's answer is checked exactly as the route's own is.
  it.each([
    {
      label: "whose fold is none of the pinned roots",
      proof: PLAINTEXT_TREE.proofs[0],
      pin: "33".repeat(32),
      reason: /not among the 1 root\(s\) pinned/,
    },
    {
      label: "that does not fold to the root it claims, even a pinned one",
      proof: { ...PLAINTEXT_TREE.proofs[0], root: "33".repeat(32) },
      pin: "33".repeat(32),
      reason: /does not fold to the root it claims/,
    },
  ])("refuses an upstream fallback proof $label", async ({ proof, pin, reason }) => {
    staleProofsRoute(proof);
    const thrown = await refusal(() =>
      plaintextSdk(new Map([[`${LIST_KEY_HEX}:0`, pin]]), true).getPOIMerkleProofs(
        LIST_KEY_HEX,
        [BC_VALID],
      ),
    );
    expect(RavenError.is(thrown, "DecodeError"), String(thrown)).toBe(true);
    expect(String((thrown as Error).message)).toMatch(/^upstream ppoi_merkle_proofs: /);
    expect(String((thrown as Error).message)).toMatch(reason);
    expect(server.requests.filter((request) => request.url === "/")).toHaveLength(1);
  });

  // Such a call could only refuse, so it refuses before sending the commitments anywhere.
  it("refuses before any request when no root is pinned for the list", async () => {
    staleProofsRoute();
    const thrown = await refusal(() =>
      plaintextSdk(undefined, true).getPOIMerkleProofs(LIST_KEY_HEX, [BC_VALID, BC_BLOCKED]),
    );
    expect(RavenError.is(thrown, "InvalidQuery"), String(thrown)).toBe(true);
    expect(String((thrown as Error).message)).toMatch(/no root pinned for the list/);
    expect(server.requests).toHaveLength(0);
  });

  it("refuses the route's proof when its fold is none of the pinned roots", async () => {
    servedProofsRoute(PLAINTEXT_TREE.proofs);
    const pins = new Map([[`${LIST_KEY_HEX}:0`, "33".repeat(32)]]);
    const thrown = await refusal(() =>
      plaintextSdk(pins).getPOIMerkleProofs(LIST_KEY_HEX, [BC_VALID]),
    );
    expect(RavenError.is(thrown, "DecodeError"), String(thrown)).toBe(true);
  });

  // A forged root that the caller happens to have pinned still has to be the fold.
  it("refuses a proof that does not fold to the root it claims, even a pinned one", async () => {
    const forged = { ...PLAINTEXT_TREE.proofs[0], root: "33".repeat(32) };
    servedProofsRoute([forged]);
    const pins = new Map([[`${LIST_KEY_HEX}:0`, forged.root]]);
    const thrown = await refusal(() =>
      plaintextSdk(pins).getPOIMerkleProofs(LIST_KEY_HEX, [BC_VALID]),
    );
    expect(RavenError.is(thrown, "DecodeError"), String(thrown)).toBe(true);
    expect(String((thrown as Error).message)).toMatch(/does not fold to the root it claims/);
  });

  // The fold only reads the low sixteen index bits and the elements it is given, so a proof of
  // another depth or position could fold to a pinned root and still be unusable to the circuit.
  it.each([
    {
      label: "fifteen elements",
      proof: (() => {
        const short = { ...PLAINTEXT_TREE.proofs[0], elements: PLAINTEXT_TREE.proofs[0].elements.slice(0, 15) };
        return { ...short, root: foldMerkleRoot(BC_VALID, short.elements, 0n) };
      })(),
    },
    {
      label: "indices past a depth-16 tree",
      proof: { ...PLAINTEXT_TREE.proofs[0], indices: (1n << 16n).toString(16).padStart(64, "0") },
    },
  ])("refuses a proof with $label even when its fold is pinned", async ({ proof }) => {
    servedProofsRoute([proof]);
    const pins = new Map([[`${LIST_KEY_HEX}:0`, proof.root]]);
    const thrown = await refusal(() =>
      plaintextSdk(pins).getPOIMerkleProofs(LIST_KEY_HEX, [BC_VALID]),
    );
    expect(RavenError.is(thrown, "DecodeError"), String(thrown)).toBe(true);
  });

  it("refuses a proof for a leaf the caller did not ask about", async () => {
    servedProofsRoute([PLAINTEXT_TREE.proofs[1]]);
    const pins = new Map([[`${LIST_KEY_HEX}:0`, PLAINTEXT_TREE.root]]);
    const thrown = await refusal(() =>
      plaintextSdk(pins).getPOIMerkleProofs(LIST_KEY_HEX, [BC_VALID]),
    );
    expect(RavenError.is(thrown, "DecodeError"), String(thrown)).toBe(true);
  });

  // The block is unknown on this route, so a pin for any block of the list can answer.
  it("accepts a proof whose fold is the pin of a block other than the first", async () => {
    servedProofsRoute([PLAINTEXT_TREE.proofs[1]]);
    const pins = new Map([
      [`${LIST_KEY_HEX}:0`, "33".repeat(32)],
      [`1:${LIST_KEY_HEX}:4`, PLAINTEXT_TREE.root],
    ]);
    const got = await plaintextSdk(pins).getPOIMerkleProofs(LIST_KEY_HEX, [BC_BLOCKED]);
    expect(got).toEqual([PLAINTEXT_TREE.proofs[1]]);
  });

  it("does not accept a pin for the same list on another chain", async () => {
    servedProofsRoute([PLAINTEXT_TREE.proofs[1]]);
    const pins = new Map([[`137:${LIST_KEY_HEX}:0`, PLAINTEXT_TREE.root]]);
    const thrown = await refusal(() =>
      plaintextSdk(pins).getPOIMerkleProofs(LIST_KEY_HEX, [BC_BLOCKED]),
    );
    expect(RavenError.is(thrown, "InvalidQuery"), String(thrown)).toBe(true);
    expect(server.requests).toHaveLength(0);
  });
});
