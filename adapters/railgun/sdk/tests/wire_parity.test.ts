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
import {
  startMockServer,
  writeJsonRpcResult,
  type JsonRpcRequest,
  type MockServer,
} from "./helpers/mock_server";
import { stubCtx as pathStubCtx } from "./helpers/auth_path_stub";
import { blockLabel, forestConfig } from "./helpers/forest";
import {
  PATH10_ROW_BYTES,
  mountPath10Route,
  path10Root,
  path10Siblings,
} from "./helpers/path10_row";
import { commitmentAt, listHolding, mountPrefixChannel } from "./helpers/prefix_channel";
import { EXPECTED_WIRE_SCHEMA_VERSION } from "./helpers/wire_schema";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX =
  "abababababababababababababababababababababababababababababababab";
const BC_HEX_A = commitmentAt(1);
const BC_HEX_B = commitmentAt(2);

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
    const leaf = UPSTREAM_HASH_LEFT_RIGHT_VECTORS[0].left;
    const sib = UPSTREAM_HASH_LEFT_RIGHT_VECTORS[0].right;
    expect(foldMerkleRoot(leaf, [sib], 0n)).toBe(
      UPSTREAM_HASH_LEFT_RIGHT_VECTORS[0].result,
    );
  });

  it("foldMerkleRoot one-level: indices=1 places leaf on the RIGHT", () => {
    const sib = UPSTREAM_HASH_LEFT_RIGHT_VECTORS[0].left;
    const leaf = UPSTREAM_HASH_LEFT_RIGHT_VECTORS[0].right;
    expect(foldMerkleRoot(leaf, [sib], 1n)).toBe(
      UPSTREAM_HASH_LEFT_RIGHT_VECTORS[0].result,
    );
  });
});

const LEAF_INDEX = 1234;
const NODES = path10Siblings(0xab);

function pathSdk(endpoint: string, upstream?: string): RavenPOINodeInterface {
  return new RavenPOINodeInterface({
    ...forestConfig({
      endpoint,
      listKeyHex: LIST_KEY_HEX,
      ctx: { ...pathStubCtx(), entrySize: PATH10_ROW_BYTES },
      placed: [[BC_HEX_A, LEAF_INDEX]],
      // Every path-10 fold requires a pinned root.
      pins: new Map([[0, path10Root(BC_HEX_A, NODES, LEAF_INDEX)]]),
    }),
    bearerToken: TOKEN,
    ...(upstream === undefined ? {} : { upstreamFallbackEndpoint: upstream }),
  });
}

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

  it("answers in upstream's POIsPerListMap shape", async () => {
    // Upstream `{ [BC]: { [listKey]: status } }` (poi-merkletree-manager.ts).
    mountPrefixChannel(server, LIST_KEY_HEX, { commitments: listHolding([[BC_HEX_A, LEAF_INDEX]]) });
    const got = await pathSdk(server.url).getPOIsPerList(
      [LIST_KEY_HEX],
      [
        { blindedCommitment: BC_HEX_A, type: "Shield" },
        { blindedCommitment: BC_HEX_B, type: "Transact" },
      ],
    );
    expect(got).toEqual({
      [BC_HEX_A]: { [LIST_KEY_HEX]: "Valid" },
      [BC_HEX_B]: { [LIST_KEY_HEX]: "Missing" },
    });
    expect(got[LIST_KEY_HEX]).toBeUndefined();
  });
});

describe("wire parity: C4 — MerkleProof.indices is uint256 (64 hex chars)", () => {
  // Drives the SDK: the client-PIR proof mints `indices` itself.
  let server: MockServer;
  beforeAll(async () => {
    server = await startMockServer();
  });
  afterAll(async () => {
    await server.close();
  });

  // Upstream nToHex(index, UINT_256) -> 64 hex chars, no prefix (merkletree.ts).
  const EXPECTED = LEAF_INDEX.toString(16).padStart(64, "0");

  it("the per-list proof carries 64-char no-prefix hex indices", async () => {
    mountPath10Route(server, {
      bcHex: BC_HEX_A,
      nodes: NODES,
      instance: blockLabel(LIST_KEY_HEX, 0),
      schemaVersion: EXPECTED_WIRE_SCHEMA_VERSION,
    });
    const [proof] = await pathSdk(server.url).getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX_A]);
    expect(proof.indices).toBe(EXPECTED);
    expect(proof.indices.length).toBe(64);
    expect(proof.indices.startsWith("0x")).toBe(false);
  });
});

describe("wire parity: H3 - error-class discrimination on the proof path", () => {
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

  it("ServerError (5xx) propagates as typed RavenError", async () => {
    server.route(
      (req) => req.url?.startsWith("/v1/instance/") ?? false,
      (_req, _body, res) => {
        res.writeHead(500);
        res.end();
        return true;
      },
    );
    await expect(pathSdk(server.url).getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX_A])).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "ServerError"),
    );
  });

  it("StaleAdapter (400 + X-Raven-Schema-Version) propagates", async () => {
    server.route(
      (req) => req.url?.startsWith("/v1/instance/") ?? false,
      (_req, _body, res) => {
        res.writeHead(400, { "x-raven-schema-version": "2" });
        res.end();
        return true;
      },
    );
    await expect(pathSdk(server.url).getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX_A])).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "StaleAdapter"),
    );
  });

  it("Network failure (unreachable port) raises Network", async () => {
    await expect(
      pathSdk("http://127.0.0.1:1").getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX_A]),
    ).rejects.toSatisfy((e: unknown) => RavenError.is(e, "Network"));
  });
});

describe("wire parity: H17 — upstream JSON-RPC carries chainType + chainID", () => {
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

  // Upstream is asked only what every stock wallet asks it: never a status or a proof, which
  // would name the note to the aggregator.
  it("never asks upstream a status or proof question", async () => {
    mountPrefixChannel(mainServer, LIST_KEY_HEX, { commitments: listHolding([[BC_HEX_A, LEAF_INDEX]]) });
    mountPath10Route(mainServer, {
      bcHex: BC_HEX_A,
      nodes: NODES,
      instance: blockLabel(LIST_KEY_HEX, 0),
      freshness: "lag_blocks=999 applied_height=10 epoch=1 confidence=0.10",
    });
    upstreamServer.route(
      (req) => req.url === "/",
      (_req, body, res) => {
        writeJsonRpcResult(body, res, null);
        return true;
      },
    );
    const sdk = pathSdk(mainServer.url, upstreamServer.url);
    await sdk.getPOIsPerList([LIST_KEY_HEX], [{ blindedCommitment: BC_HEX_A, type: "Shield" }]);
    await sdk.getPOIsPerList("V2_PoseidonMerkle", { type: 0, id: 1 }, [LIST_KEY_HEX], [
      { blindedCommitment: BC_HEX_B, type: "Shield" },
    ]);
    await expect(sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX_A])).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "StaleData"),
    );
    expect(upstreamServer.requests).toHaveLength(0);
  });

  it("validatePOIMerkleroots calls ppoi_validate_poi_merkleroots with poiMerkleroots", async () => {
    let observed: JsonRpcRequest | undefined;
    upstreamServer.route(
      (req) => req.url === "/",
      (_req, body, res) => {
        observed = writeJsonRpcResult(body, res, true);
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
    expect(observed?.method).toBe("ppoi_validate_poi_merkleroots");
    expect(observed?.params.poiMerkleroots).toEqual(["11".repeat(32)]);
    expect(observed?.params.listKey).toBe(LIST_KEY_HEX);
    expect(observed?.params.txidVersion).toBe("V2_PoseidonMerkle");
    expect(observed?.params.chainType).toBe("0");
    expect(observed?.params.chainID).toBe("1");
  });

  it("submitPOI uses upstream 9-arg signature with ppoi_submit_transact_proof", async () => {
    let observed: JsonRpcRequest | undefined;
    upstreamServer.route(
      (req) => req.url === "/",
      (_req, body, res) => {
        observed = writeJsonRpcResult(body, res, null);
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
    expect(observed?.method).toBe("ppoi_submit_transact_proof");
    const transactProofData = observed?.params.transactProofData as Record<string, unknown>;
    expect(transactProofData.snarkProof).toEqual(fakeProof);
    expect(transactProofData.poiMerkleroots).toEqual(["aa".repeat(32)]);
    expect(transactProofData.txidMerkleroot).toBe("ff".repeat(32));
    expect(transactProofData.txidMerklerootIndex).toBe(42);
    expect(transactProofData.blindedCommitmentsOut).toEqual(["bb".repeat(32)]);
    expect(transactProofData.railgunTxidIfHasUnshield).toBe("cc".repeat(32));
  });
});
