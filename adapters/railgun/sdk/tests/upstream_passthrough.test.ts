// validatePOIMerkleroots / submitPOI / submitLegacyTransactProofs forward verbatim to
// upstreamFallbackEndpoint; the adapter does not relay them. Locks wire shape + error semantics.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { RavenPOINodeInterface } from "../src/index";
import { startMockServer, writeError, writeJson, type MockServer } from "./helpers/mock_server";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "abababababababababababababababababababababababababababababababab";
const ROOT_A = "00".repeat(32);
const ROOT_B = "11".repeat(32);

describe("upstream-passthrough endpoints", () => {
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

  it("validatePOIMerkleroots returns true when no upstream is configured", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
    });
    const got = await sdk.validatePOIMerkleroots(LIST_KEY_HEX, [ROOT_A, ROOT_B]);
    expect(got).toBe(true);
    expect(sdk.lastWireRequests().length).toBe(0);
  });

  it("validatePOIMerkleroots posts the correct shape to upstream", async () => {
    // Upstream path /validate-poi-merkleroots/<chainType>/<chainID> (api.ts:786).
    server.route(
      (req) => req.url === "/validate-poi-merkleroots/0/1",
      (_req, _body, res) => {
        writeJson(res, true);
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      upstreamFallbackEndpoint: server.url,
    });
    const got = await sdk.validatePOIMerkleroots(LIST_KEY_HEX, [ROOT_A, ROOT_B]);
    expect(got).toBe(true);
    const wires = sdk.lastWireRequests();
    expect(wires.length).toBe(1);
    expect(wires[0].url).toMatch(/\/validate-poi-merkleroots\/0\/1$/);
    const decoded = JSON.parse(new TextDecoder().decode(wires[0].body));
    expect(decoded.chainType).toBe("0");
    expect(decoded.chainID).toBe("1");
    expect(decoded.txidVersion).toBe("V2_PoseidonMerkle");
    expect(decoded.listKey).toBe(LIST_KEY_HEX);
    expect(decoded.poiMerkleroots).toEqual([ROOT_A, ROOT_B]);
  });

  it("validatePOIMerkleroots throws on upstream error", async () => {
    server.route(
      (req) => req.url === "/validate-poi-merkleroots/0/1",
      (_req, _body, res) => {
        writeError(res, 500, "boom");
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      upstreamFallbackEndpoint: server.url,
    });
    await expect(
      sdk.validatePOIMerkleroots(LIST_KEY_HEX, [ROOT_A]),
    ).rejects.toThrow(/500/);
  });

  it("submitPOI requires upstream", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
    });
    const fakeProof = {
      pi_a: ["0", "0"] as [string, string],
      pi_b: [["0", "0"], ["0", "0"]] as [[string, string], [string, string]],
      pi_c: ["0", "0"] as [string, string],
    };
    await expect(
      sdk.submitPOI(
        "V2_PoseidonMerkle",
        { type: 0, id: 1 },
        LIST_KEY_HEX,
        fakeProof,
        [],
        "0".repeat(64),
        0,
        [],
        "",
      ),
    ).rejects.toThrow(/upstreamFallbackEndpoint/);
  });

  it("submitPOI posts to upstream with full upstream 9-arg shape", async () => {
    // Upstream path /submit-transact-proof/<chainType>/<chainID> (api.ts:653).
    server.route(
      (req) => req.url === "/submit-transact-proof/0/1",
      (_req, _body, res) => {
        writeJson(res, {});
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      upstreamFallbackEndpoint: server.url,
    });
    const fakeProof = {
      pi_a: ["1", "2"] as [string, string],
      pi_b: [["3", "4"], ["5", "6"]] as [[string, string], [string, string]],
      pi_c: ["7", "8"] as [string, string],
    };
    await sdk.submitPOI(
      "V2_PoseidonMerkle",
      { type: 0, id: 1 },
      LIST_KEY_HEX,
      fakeProof,
      [ROOT_A, ROOT_B],
      "ff".repeat(32),
      42,
      ["aa".repeat(32)],
      "bb".repeat(32),
    );
    const wires = sdk.lastWireRequests();
    expect(wires[0].url).toMatch(/\/submit-transact-proof\/0\/1$/);
    const decoded = JSON.parse(new TextDecoder().decode(wires[0].body));
    expect(decoded.chainType).toBe("0");
    expect(decoded.chainID).toBe("1");
    expect(decoded.txidVersion).toBe("V2_PoseidonMerkle");
    expect(decoded.listKey).toBe(LIST_KEY_HEX);
    expect(decoded.transactProofData.snarkProof).toEqual(fakeProof);
    expect(decoded.transactProofData.poiMerkleroots).toEqual([ROOT_A, ROOT_B]);
    expect(decoded.transactProofData.txidMerkleroot).toBe("ff".repeat(32));
    expect(decoded.transactProofData.txidMerklerootIndex).toBe(42);
    expect(decoded.transactProofData.blindedCommitmentsOut).toEqual(["aa".repeat(32)]);
    expect(decoded.transactProofData.railgunTxidIfHasUnshield).toBe("bb".repeat(32));
  });

  it("submitLegacyTransactProofs posts proofs array", async () => {
    server.route(
      (req) => req.url === "/submit-legacy-transact-proofs/0/1",
      (_req, _body, res) => {
        writeJson(res, {});
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      upstreamFallbackEndpoint: server.url,
    });
    await sdk.submitLegacyTransactProofs(
      [LIST_KEY_HEX],
      [
        {
          txidIndex: "0",
          npk: "00".repeat(32),
          value: "1000",
          tokenHash: "11".repeat(32),
          blindedCommitment: "22".repeat(32),
        },
        {
          txidIndex: "1",
          npk: "00".repeat(32),
          value: "2000",
          tokenHash: "33".repeat(32),
          blindedCommitment: "44".repeat(32),
        },
      ],
    );
    const wires = sdk.lastWireRequests();
    expect(wires[0].url).toMatch(/\/submit-legacy-transact-proofs\/0\/1$/);
    const decoded = JSON.parse(new TextDecoder().decode(wires[0].body));
    expect(decoded.legacyTransactProofDatas).toHaveLength(2);
    expect(decoded.listKeys).toEqual([LIST_KEY_HEX]);
    expect(decoded.chainType).toBe("0");
    expect(decoded.chainID).toBe("1");
  });

  it("submitLegacyTransactProofs requires upstream", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
    });
    await expect(
      sdk.submitLegacyTransactProofs([LIST_KEY_HEX], []),
    ).rejects.toThrow(/upstreamFallbackEndpoint/);
  });
});
