// A node that has not bootstrapped serves an EMPTY bc-to-idx map, and `lookupBcMap` refuses only
// on `undefined`: an empty Map is truthy, so reading it as a list state made the SDK write "Missing"
// for every blinded commitment, with nothing logged. "Missing" is a verdict a wallet acts on, and an
// empty map cannot tell "the node has no data" from "this commitment is not on the list". So an
// absence reads "Missing" only from an index shown to cover the rows the node serves; a map, which
// carries no row count, answers one only when the caller decides it may, as "MissingStale", and the
// decision is counted.

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { RavenError, RavenPOINodeInterface } from "../src/index";
import { makeRegisterSpy, stubRemoteSessionExports } from "./helpers/register_spy";
import type { ClientPirContext, RavenInspireWasm } from "../src/index";
import { encodeBatchResponseNodes, encodedBatchCount } from "./helpers/auth_path_stub";
import { startMockServer, writeBinary, type MockServer } from "./helpers/mock_server";
import { stubQueryBundle } from "./helpers/private_wire";
import { shardConfigBincode } from "./helpers/shard_config";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "abababababababababababababababababababababababababababababababab";
const BC_HEX = "bc00112233445566778899aabbccddeeff00112233445566778899aabbccdd01";

function stubCtx(): ClientPirContext {
  const wasm: RavenInspireWasm = {
    ...stubRemoteSessionExports(),
    build_client_session: () => ({ free: () => undefined }),
    build_seeded_query: () => stubQueryBundle(),
    extract_response: (_s, _c, _st, response, _e) => new Uint8Array(response),
    build_instance_params_blob: () => new Uint8Array(0),
    register_client_session: makeRegisterSpy(),
    path_indices_for_leaf: () => new Uint32Array(16),
    path_indices_for_per_list_leaf: () => new Uint32Array(16),
  };
  return {
    wasm,
    session: { free: () => undefined },
    crsBincode: new Uint8Array(0),
    shardConfigBincode: shardConfigBincode(),
    entrySize: 32,
  };
}

describe("an empty bc-to-idx map is not a list state", () => {
  let server: MockServer;
  beforeAll(async () => {
    server = await startMockServer();
    // An all-absent batch still issues one empty-chunk query: chunkCount is max(1, ceil(0/N)).
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, body, res) => {
        const count = encodedBatchCount(body);
        writeBinary(
          res,
          encodeBatchResponseNodes(Array.from({ length: count }, () => new Uint8Array(32))),
        );
        return true;
      },
    );
    // What the shim answers for a list it holds no rows of.
    server.route(
      (req) => (req.url ?? "").startsWith(`/v1/poi/${LIST_KEY_HEX}/bc-prefixes`),
      (_req, _body, res) => {
        res.writeHead(503, { "content-type": "text/plain" });
        res.end("no wired store covers the list");
        return true;
      },
    );
  });
  afterAll(async () => {
    await server.close();
  });

  function sdkWith(
    map: Map<string, number>,
    policy?: "refuse" | "answer-at-index-rows",
  ): RavenPOINodeInterface {
    return new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, map]]),
      indexStalenessPolicy: policy,
      poiListIndexStore: false,
    });
  }

  it("refuses an absence read from an unbootstrapped node's empty map", async () => {
    const sdk = sdkWith(new Map());
    await expect(
      sdk.getPOIsPerList([LIST_KEY_HEX], [{ blindedCommitment: BC_HEX, type: "Shield" }]),
    ).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "InvalidQuery") && /carries no row count/.test(e.message),
    );
    expect(sdk.indexCounters().refused).toBe(1);
  });

  it("refuses an absence read from an empty index the node cannot bring up to date", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, stubCtx()]]),
      poiListIndexes: new Map([[LIST_KEY_HEX, { epoch: 0, total: 0, prefixes: new Uint8Array(0) }]]),
      poiListIndexStore: false,
    });
    await expect(
      sdk.getPOIsPerList([LIST_KEY_HEX], [{ blindedCommitment: BC_HEX, type: "Shield" }]),
    ).rejects.toSatisfy((e: unknown) => RavenError.is(e, "ServerError"));
    expect(sdk.indexCounters().absent).toBe(0);
  });

  it("answers MissingStale from an empty map only on the caller's decision, and counts it apart", async () => {
    const sdk = sdkWith(new Map(), "answer-at-index-rows");
    const got = await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_HEX, type: "Shield" }],
    );
    expect(got[BC_HEX][LIST_KEY_HEX]).toBe("MissingStale");
    expect(sdk.indexCounters().absentFromBareMap).toBe(1);
    expect(sdk.indexCounters().absent).toBe(0);
  });

  it("a MISSING map entry refuses too", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map(),
      poiListIndexStore: false,
    });
    await expect(
      sdk.getPOIsPerList([LIST_KEY_HEX], [{ blindedCommitment: BC_HEX, type: "Shield" }]),
    ).rejects.toThrow(/bc-to-idx-map/i);
  });
});
