/**
 * Legacy plaintext-BC fallback tests. With `useClientPir: false` the SDK hits
 * the wallet-shim routes with BCs serialized into the JSON body; these lock
 * that wire shape.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { RavenPOINodeInterface } from "../src/index";

import { startMockServer, writeJson, type MockServer } from "./helpers/mock_server";

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
      const proofs = bcs.map((bc) => ({
        leaf: bc,
        elements: Array.from({ length: 16 }, (_, j) =>
          j.toString(16).padStart(2, "0").repeat(32),
        ),
        indices: "0x00",
        root: "ff".repeat(32),
      }));
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
      indices: "0x00",
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
    expect(got).toEqual(proof);
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
    // upstream /pois-per-list/<chainType>/<chainID> (private-proof-of-innocence node api.ts)
    server.route(
      (req) => req.url === "/pois-per-list/0/1",
      (_req, _body, res) => {
        writeJson(res, { [BC_VALID]: { [LIST_KEY_HEX]: "Valid" } });
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
    // primary then upstream passthrough
    expect(sdk.lastWireRequests().length).toBe(2);
  });

  it("legacy mode does NOT trigger fallback when freshness is missing", async () => {
    server.route(
      (req) => req.url === "/v1/poi/pois-per-list",
      (_req, _body, res) => {
        // no freshness header
        writeJson(res, { [BC_VALID]: { [LIST_KEY_HEX]: "Valid" } });
        return true;
      },
    );
    server.route(
      (req) => req.url === "/pois-per-list/0/1",
      (_req, _body, _res) => {
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

  it("getPOIMerkleProofs legacy mode falls back when freshness is below floor", async () => {
    server.route(
      (req) => req.url === "/v1/poi/merkle-proofs",
      (_req, _body, res) => {
        writeJson(res, [], {
          "x-raven-freshness": "lag_blocks=10 applied_height=5 epoch=1 confidence=0.10",
        });
        return true;
      },
    );
    // upstream /merkle-proofs/<chainType>/<chainID> (private-proof-of-innocence node api.ts)
    server.route(
      (req) => req.url === "/merkle-proofs/0/1",
      (_req, _body, res) => {
        writeJson(res, [
          {
            leaf: BC_VALID,
            elements: Array.from({ length: 16 }, () => "00".repeat(32)),
            indices: "0x00",
            root: "ff".repeat(32),
          },
        ]);
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
    const got = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_VALID]);
    expect(got).toHaveLength(1);
  });
});
