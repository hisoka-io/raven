// Wire-parity regression suite against upstream Railgun POINodeInterface
// (github.com/Railgun-Community). Each describe block pins one contract and cites
// the upstream source so future drift is easy to triangulate.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  RavenError,
  RavenPOINodeInterface,
  hashLeftRight,
  foldMerkleRoot,
} from "../src/index";
import { startMockServer, writeJson, type MockServer } from "./helpers/mock_server";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX =
  "abababababababababababababababababababababababababababababababab";
const BC_HEX_A =
  "0000000000000000000000000000000000000000000000000000000000000001";
const BC_HEX_B =
  "0000000000000000000000000000000000000000000000000000000000000002";

// Upstream KAT vectors from engine/src/merkletree/__tests__/utxo-merkletree.test.ts ("Should hash left/right").
const UPSTREAM_HASH_LEFT_RIGHT_VECTORS = [
  {
    left: "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a",
    right: "2a92a4c8d7c21d97d946951043d11954de794cd506093dbbb97ada64c14b203b",
    result: "106dc6dc79863b23dc1a63c7ca40e8c22bb830e449b75a2286c7f7b0b87ae6c3",
  },
  {
    left: "0db945439b762ad08f144bcccc3746773b332e8a0045a11d87662dc227923df5",
    right: "09ce612d20912e20cde93cd2a03fcccdfdce5910242b555ff35b5373041bf329",
    result: "063c1c7dfb4b63255c492bb6b32d57eddddcb1c78cfb990e7b35416cf966ed79",
  },
  {
    left: "09cf3efaeb0190e482c9f9cf1534f17fbf0ed1537c26db9faf26f3d55140804d",
    right: "2651021f2d224338f1c9f408db74111c98e7381072b9fcd640bd4f748584e769",
    result: "1576a4dd906cab90e381775c1c9bb1d713f7f02c7ec0911a8bc38a1c4b0bf69e",
  },
];

describe("wire parity: C3 — Poseidon hashLeftRight matches upstream", () => {
  for (const v of UPSTREAM_HASH_LEFT_RIGHT_VECTORS) {
    it(`hashLeftRight(${v.left.slice(0, 8)}…, ${v.right.slice(0, 8)}…) matches upstream test vector`, () => {
      expect(hashLeftRight(v.left, v.right)).toBe(v.result);
    });
  }

  it("hashLeftRight is non-commutative (verifyMerkleProof relies on this)", () => {
    const a = hashLeftRight(
      UPSTREAM_HASH_LEFT_RIGHT_VECTORS[0].left,
      UPSTREAM_HASH_LEFT_RIGHT_VECTORS[0].right,
    );
    const b = hashLeftRight(
      UPSTREAM_HASH_LEFT_RIGHT_VECTORS[0].right,
      UPSTREAM_HASH_LEFT_RIGHT_VECTORS[0].left,
    );
    expect(a).not.toBe(b);
  });

  it("foldMerkleRoot(leaf, [], 0n) returns the leaf (verified bit-pattern)", () => {
    const leaf = "abcdef".padEnd(64, "0");
    expect(foldMerkleRoot(leaf, [], 0n)).toBe(leaf);
  });

  it("foldMerkleRoot one-level: indices=0 places leaf on the LEFT", () => {
    // bit 0 = 0 -> leaf is left child, sibling is right.
    const leaf = UPSTREAM_HASH_LEFT_RIGHT_VECTORS[0].left;
    const sib = UPSTREAM_HASH_LEFT_RIGHT_VECTORS[0].right;
    expect(foldMerkleRoot(leaf, [sib], 0n)).toBe(
      UPSTREAM_HASH_LEFT_RIGHT_VECTORS[0].result,
    );
  });

  it("foldMerkleRoot one-level: indices=1 places leaf on the RIGHT", () => {
    // bit 0 = 1 -> leaf is right child, sibling is left.
    const sib = UPSTREAM_HASH_LEFT_RIGHT_VECTORS[0].left;
    const leaf = UPSTREAM_HASH_LEFT_RIGHT_VECTORS[0].right;
    expect(foldMerkleRoot(leaf, [sib], 1n)).toBe(
      UPSTREAM_HASH_LEFT_RIGHT_VECTORS[0].result,
    );
  });
});

describe("wire parity: C1 — PoisPerListResponse outer key is BC (NOT listKey)", () => {
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

  it("legacy mode round-trips upstream POIsPerListMap shape verbatim", async () => {
    // Upstream `{ [BC]: { [listKey]: status } }` (poi-merkletree-manager.ts:215-218).
    const expected = {
      [BC_HEX_A]: { [LIST_KEY_HEX]: "Valid" },
      [BC_HEX_B]: { [LIST_KEY_HEX]: "ShieldBlocked" },
    };
    server.route(
      (req) => req.url === "/v1/poi/pois-per-list",
      (_req, _body, res) => {
        writeJson(res, expected);
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
      [
        { blindedCommitment: BC_HEX_A, type: "Shield" },
        { blindedCommitment: BC_HEX_B, type: "Transact" },
      ],
    );
    expect(got).toEqual(expected);
    expect(got[BC_HEX_A][LIST_KEY_HEX]).toBe("Valid");
    expect(got[BC_HEX_B][LIST_KEY_HEX]).toBe("ShieldBlocked");
    // Inverted (listKey-outer) shape must not be observable.
    expect(got[LIST_KEY_HEX]).toBeUndefined();
  });
});

describe("wire parity: C4 — MerkleProof.indices is uint256 (64 hex chars)", () => {
  it("MerkleProof type carries 64-char no-prefix hex indices", () => {
    // Upstream nToHex(index, UINT_256) -> 64 hex chars, no prefix (merkletree.ts:148).
    const proof: import("../src/index").MerkleProof = {
      leaf: "0".repeat(64),
      elements: [],
      indices: "0".repeat(64),
      root: "0".repeat(64),
    };
    expect(proof.indices.length).toBe(64);
    expect(proof.indices.startsWith("0x")).toBe(false);
  });
});

describe("wire parity: H3 — Error-class discrimination on T1 client-PIR", () => {
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

  function stubCtx(): import("../src/index").ClientPirContext {
    return {
      wasm: {
        build_client_session: () => ({ free: () => undefined }),
        build_seeded_query: () => new Uint8Array(16),
        extract_response: () => new Uint8Array(32),
        build_instance_params_blob: () => new Uint8Array(0),
        register_client_session: undefined,
        path_indices_for_leaf: () => new Uint32Array(16),
        path_indices_for_per_list_leaf: () => new Uint32Array(16),
      },
      session: { free: () => undefined },
      crsBincode: new Uint8Array(0),
      shardConfigBincode: new Uint8Array(0),
      entrySize: 32,
    };
  }

  it("ServerError (5xx) propagates as typed RavenError, NOT silent Missing", async () => {
    server.route(
      (req) => req.url?.startsWith("/v1/instance/") ?? false,
      (_req, _body, res) => {
        res.writeHead(500);
        res.end();
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[BC_HEX_A, 0]])]]),
    });
    try {
      await sdk.getPOIsPerList(
        [LIST_KEY_HEX],
        [{ blindedCommitment: BC_HEX_A, type: "Shield" }],
      );
      expect.fail("expected ServerError");
    } catch (e) {
      expect(RavenError.is(e, "ServerError")).toBe(true);
    }
  });

  it("StaleAdapter (400 + X-Raven-Schema-Version) propagates, NOT silent Missing", async () => {
    server.route(
      (req) => req.url?.startsWith("/v1/instance/") ?? false,
      (_req, _body, res) => {
        res.writeHead(400, { "x-raven-schema-version": "2" });
        res.end();
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[BC_HEX_A, 0]])]]),
    });
    try {
      await sdk.getPOIsPerList(
        [LIST_KEY_HEX],
        [{ blindedCommitment: BC_HEX_A, type: "Shield" }],
      );
      expect.fail("expected StaleAdapter");
    } catch (e) {
      expect(RavenError.is(e, "StaleAdapter")).toBe(true);
    }
  });

  it("Network failure (unreachable port) substitutes Missing per BC", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: "http://127.0.0.1:1",
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[BC_HEX_A, 0]])]]),
    });
    const got = await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_HEX_A, type: "Shield" }],
    );
    expect(got[BC_HEX_A][LIST_KEY_HEX]).toBe("Missing");
  });
});

describe("wire parity: H17 — upstream passthrough URLs include chainType + chainID", () => {
  let mainServer: MockServer;
  let upstreamServer: MockServer;
  beforeAll(async () => {
    mainServer = await startMockServer();
    upstreamServer = await startMockServer();
  });
  afterAll(async () => {
    await mainServer.close();
    await upstreamServer.close();
  });
  afterEach(() => {
    mainServer.reset();
    upstreamServer.reset();
  });

  it("getPOIMerkleProofs passthrough hits upstream `/merkle-proofs/<chainType>/<chainID>`", async () => {
    // Stale freshness forces upstream fallback; segment is `merkle-proofs`, not `poi-merkle-proofs` (api.ts:739).
    mainServer.route(
      (req) => req.url === "/v1/poi/merkle-proofs",
      (_req, _body, res) => {
        writeJson(res, [], {
          "x-raven-freshness":
            "lag_blocks=999 applied_height=10 epoch=1 confidence=0.10",
        });
        return true;
      },
    );
    let upstreamUrl = "";
    upstreamServer.route(
      (req) => req.url?.startsWith("/merkle-proofs/") ?? false,
      (req, _body, res) => {
        upstreamUrl = req.url ?? "";
        writeJson(res, [
          {
            leaf: BC_HEX_A,
            elements: Array.from({ length: 16 }, () => "00".repeat(32)),
            indices: "0".repeat(64),
            root: "0".repeat(64),
          },
        ]);
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: mainServer.url,
      bearerToken: TOKEN,
      upstreamFallbackEndpoint: upstreamServer.url,
      useClientPir: false,
      freshnessConfidenceFloor: 0.5,
      chainType: 0,
      chainId: 1,
    });
    const got = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX_A]);
    expect(got).toHaveLength(1);
    expect(upstreamUrl).toBe("/merkle-proofs/0/1");
  });

  it("getPOIsPerList passthrough hits upstream `/pois-per-list/<chainType>/<chainID>`", async () => {
    mainServer.route(
      (req) => req.url === "/v1/poi/pois-per-list",
      (_req, _body, res) => {
        writeJson(res, {}, {
          "x-raven-freshness":
            "lag_blocks=999 applied_height=10 epoch=1 confidence=0.10",
        });
        return true;
      },
    );
    let upstreamUrl = "";
    upstreamServer.route(
      (req) => req.url?.startsWith("/pois-per-list/") ?? false,
      (req, _body, res) => {
        upstreamUrl = req.url ?? "";
        writeJson(res, { [BC_HEX_A]: { [LIST_KEY_HEX]: "Valid" } });
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: mainServer.url,
      bearerToken: TOKEN,
      upstreamFallbackEndpoint: upstreamServer.url,
      useClientPir: false,
      freshnessConfidenceFloor: 0.5,
      chainType: 0,
      chainId: 11_155_111,
    });
    await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_HEX_A, type: "Shield" }],
    );
    // Sepolia chain id must round-trip into the URL, not collapse to a default.
    expect(upstreamUrl).toBe("/pois-per-list/0/11155111");
  });

  it("validatePOIMerkleroots posts to `/validate-poi-merkleroots/<chainType>/<chainID>` with poiMerkleroots field", async () => {
    let observed = "";
    let observedBody: unknown = null;
    upstreamServer.route(
      (req) => req.url?.startsWith("/validate-poi-merkleroots/") ?? false,
      (req, body, res) => {
        observed = req.url ?? "";
        observedBody = JSON.parse(new TextDecoder().decode(body));
        writeJson(res, true);
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: mainServer.url,
      bearerToken: TOKEN,
      upstreamFallbackEndpoint: upstreamServer.url,
      chainType: 0,
      chainId: 1,
    });
    const got = await sdk.validatePOIMerkleroots(LIST_KEY_HEX, [
      "11".repeat(32),
    ]);
    expect(got).toBe(true);
    expect(observed).toBe("/validate-poi-merkleroots/0/1");
    const decoded = observedBody as Record<string, unknown>;
    expect(decoded.poiMerkleroots).toEqual(["11".repeat(32)]);
    expect(decoded.listKey).toBe(LIST_KEY_HEX);
    expect(decoded.txidVersion).toBe("V2_PoseidonMerkle");
    expect(decoded.chainType).toBe("0");
    expect(decoded.chainID).toBe("1");
  });

  it("submitPOI uses upstream 9-arg signature + posts to `/submit-transact-proof/<chainType>/<chainID>`", async () => {
    let observed = "";
    let observedBody: { [k: string]: unknown } | null = null;
    upstreamServer.route(
      (req) => req.url?.startsWith("/submit-transact-proof/") ?? false,
      (req, body, res) => {
        observed = req.url ?? "";
        observedBody = JSON.parse(new TextDecoder().decode(body));
        writeJson(res, {});
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: mainServer.url,
      bearerToken: TOKEN,
      upstreamFallbackEndpoint: upstreamServer.url,
    });
    const fakeProof = {
      pi_a: ["1", "2"] as [string, string],
      pi_b: [["3", "4"], ["5", "6"]] as [
        [string, string],
        [string, string],
      ],
      pi_c: ["7", "8"] as [string, string],
    };
    await sdk.submitPOI(
      "V2_PoseidonMerkle",
      { type: 0, id: 1 },
      LIST_KEY_HEX,
      fakeProof,
      ["aa".repeat(32)],
      "ff".repeat(32),
      42,
      ["bb".repeat(32)],
      "cc".repeat(32),
    );
    expect(observed).toBe("/submit-transact-proof/0/1");
    expect(observedBody).not.toBeNull();
    const body = observedBody as unknown as { [k: string]: unknown };
    const transactProofData = body.transactProofData as Record<string, unknown>;
    expect(transactProofData.snarkProof).toEqual(fakeProof);
    expect(transactProofData.poiMerkleroots).toEqual(["aa".repeat(32)]);
    expect(transactProofData.txidMerkleroot).toBe("ff".repeat(32));
    expect(transactProofData.txidMerklerootIndex).toBe(42);
    expect(transactProofData.blindedCommitmentsOut).toEqual(["bb".repeat(32)]);
    expect(transactProofData.railgunTxidIfHasUnshield).toBe("cc".repeat(32));
  });
});
