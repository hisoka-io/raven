// validatePOIMerkleroots / submitPOI / submitLegacyTransactProofs forward verbatim to
// upstreamFallbackEndpoint; the adapter does not relay them. Locks wire shape + error semantics.

import { afterAll, afterEach, beforeAll, describe, expect, expectTypeOf, it } from "vitest";

import {
  type LegacyTransactProofData,
  RavenError,
  RavenPOINodeInterface,
} from "../src/index";
import { startMockServer, writeJson, type MockServer } from "./helpers/mock_server";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "abababababababababababababababababababababababababababababababab";
const ROOT_A = "00".repeat(32);
const ROOT_B = "11".repeat(32);

interface JsonRpcRequest {
  readonly jsonrpc: string;
  readonly method: string;
  readonly params: Record<string, unknown>;
  readonly id: number;
}

function decodeJsonRpcRequest(body: Uint8Array): JsonRpcRequest {
  return JSON.parse(new TextDecoder().decode(body)) as JsonRpcRequest;
}

function writeJsonRpcResult(
  body: Uint8Array,
  res: Parameters<typeof writeJson>[0],
  result: unknown,
): JsonRpcRequest {
  const request = decodeJsonRpcRequest(body);
  writeJson(res, { jsonrpc: "2.0", id: request.id, result });
  return request;
}

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

  it("types legacy transact proof submissions with the upstream payload", () => {
    expectTypeOf<RavenPOINodeInterface["submitLegacyTransactProofs"]>().toMatchTypeOf<
      (
        txidVersion: string,
        chain: { type: number; id: number },
        listKeys: string[],
        proofs: LegacyTransactProofData[],
      ) => Promise<void>
    >();

    expectTypeOf<LegacyTransactProofData>().toEqualTypeOf<{
      txidIndex: string;
      npk: string;
      value: string;
      tokenHash: string;
      blindedCommitment: string;
    }>();
  });

  it("refuses validation when no upstream is configured", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
    });
    await expect(
      sdk.validatePOIMerkleroots(LIST_KEY_HEX, [ROOT_A, ROOT_B]),
    ).rejects.toThrow(/requires upstreamFallbackEndpoint/);
    expect(sdk.lastWireRequests().length).toBe(0);
  });

  it("returns the upstream verdict rather than a hardcoded true", async () => {
    // Without this, `validatePOIMerkleroots` could `return true` unconditionally and the
    // whole suite stays green -- the upstream rejection path had no coverage at all.
    server.route(
      (req) => req.url === "/",
      (_req, body, res) => {
        writeJsonRpcResult(body, res, false);
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      upstreamFallbackEndpoint: server.url,
    });
    expect(await sdk.validatePOIMerkleroots(LIST_KEY_HEX, [ROOT_A])).toBe(false);
  });

  it("refuses a non-boolean upstream verdict", async () => {
    server.route(
      (req) => req.url === "/",
      (_req, body, res) => {
        writeJsonRpcResult(body, res, { ok: "yes" });
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      upstreamFallbackEndpoint: server.url,
    });
    await expect(sdk.validatePOIMerkleroots(LIST_KEY_HEX, [ROOT_A])).rejects.toThrow(
      /boolean verdict/,
    );
  });

  it("validatePOIMerkleroots posts the correct shape to upstream", async () => {
    let observed: JsonRpcRequest | undefined;
    server.route(
      (req) => req.url === "/",
      (_req, body, res) => {
        observed = writeJsonRpcResult(body, res, true);
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
    expect(wires[0].url).toBe(server.url);
    const decoded = JSON.parse(new TextDecoder().decode(wires[0].body));
    expect(decoded).toEqual(observed);
    expect(decoded.jsonrpc).toBe("2.0");
    expect(decoded.method).toBe("ppoi_validate_poi_merkleroots");
    expect(decoded.params.chainType).toBe("0");
    expect(decoded.params.chainID).toBe("1");
    expect(decoded.params.txidVersion).toBe("V2_PoseidonMerkle");
    expect(decoded.params.listKey).toBe(LIST_KEY_HEX);
    expect(decoded.params.poiMerkleroots).toEqual([ROOT_A, ROOT_B]);
  });

  it("validatePOIMerkleroots throws on upstream error", async () => {
    server.route(
      (req) => req.url === "/",
      (_req, body, res) => {
        const request = decodeJsonRpcRequest(body);
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({
          jsonrpc: "2.0",
          id: request.id,
          error: { code: -32603, message: "boom" },
        }));
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
    ).rejects.toThrow(/JSON-RPC error -32603: boom/);
  });

  for (const [name, mutate] of [
    ["wrong version", (id: number) => ({ jsonrpc: "1.0", id, result: true })],
    ["wrong id", (id: number) => ({ jsonrpc: "2.0", id: id + 1, result: true })],
    [
      "result and error",
      (id: number) => ({
        jsonrpc: "2.0",
        id,
        result: true,
        error: { code: -32603, message: "conflict" },
      }),
    ],
    ["neither result nor error", (id: number) => ({ jsonrpc: "2.0", id })],
    ["malformed error", (id: number) => ({ jsonrpc: "2.0", id, error: { code: "bad" } })],
  ] as const) {
    it(`refuses a JSON-RPC envelope with ${name}`, async () => {
      server.route(
        (req) => req.url === "/",
        (_req, body, res) => {
          const request = decodeJsonRpcRequest(body);
          writeJson(res, mutate(request.id));
          return true;
        },
      );
      const sdk = new RavenPOINodeInterface({
        endpoint: server.url,
        bearerToken: TOKEN,
        upstreamFallbackEndpoint: server.url,
      });
      try {
        await sdk.validatePOIMerkleroots(LIST_KEY_HEX, [ROOT_A]);
        expect.fail("expected malformed JSON-RPC envelope refusal");
      } catch (error) {
        expect(RavenError.is(error, "DecodeError"), String(error)).toBe(true);
      }
    });
  }

  it("surfaces a valid JSON-RPC error envelope as a typed ServerError", async () => {
    server.route(
      (req) => req.url === "/",
      (_req, body, res) => {
        const request = decodeJsonRpcRequest(body);
        writeJson(res, {
          jsonrpc: "2.0",
          id: request.id,
          error: { code: -32602, message: "Invalid params" },
        });
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      upstreamFallbackEndpoint: server.url,
    });
    try {
      await sdk.validatePOIMerkleroots(LIST_KEY_HEX, [ROOT_A]);
      expect.fail("expected JSON-RPC error");
    } catch (error) {
      expect(RavenError.is(error, "ServerError"), String(error)).toBe(true);
      expect(String(error)).toContain("-32602: Invalid params");
    }
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
    let observed: JsonRpcRequest | undefined;
    server.route(
      (req) => req.url === "/",
      (_req, body, res) => {
        observed = writeJsonRpcResult(body, res, undefined);
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
    expect(wires[0].url).toBe(server.url);
    const decoded = JSON.parse(new TextDecoder().decode(wires[0].body));
    expect(decoded).toEqual(observed);
    expect(decoded.method).toBe("ppoi_submit_transact_proof");
    expect(decoded.params.chainType).toBe("0");
    expect(decoded.params.chainID).toBe("1");
    expect(decoded.params.txidVersion).toBe("V2_PoseidonMerkle");
    expect(decoded.params.listKey).toBe(LIST_KEY_HEX);
    expect(decoded.params.transactProofData.snarkProof).toEqual(fakeProof);
    expect(decoded.params.transactProofData.poiMerkleroots).toEqual([ROOT_A, ROOT_B]);
    expect(decoded.params.transactProofData.txidMerkleroot).toBe("ff".repeat(32));
    expect(decoded.params.transactProofData.txidMerklerootIndex).toBe(42);
    expect(decoded.params.transactProofData.blindedCommitmentsOut).toEqual(["aa".repeat(32)]);
    expect(decoded.params.transactProofData.railgunTxidIfHasUnshield).toBe("bb".repeat(32));
  });

  it("submitLegacyTransactProofs posts proofs array", async () => {
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
    expect(wires[0].url).toBe(server.url);
    const decoded = JSON.parse(new TextDecoder().decode(wires[0].body));
    expect(decoded.method).toBe("ppoi_submit_legacy_transact_proofs");
    expect(decoded.params.legacyTransactProofDatas).toHaveLength(2);
    expect(decoded.params.listKeys).toEqual([LIST_KEY_HEX]);
    expect(decoded.params.chainType).toBe("0");
    expect(decoded.params.chainID).toBe("1");
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
