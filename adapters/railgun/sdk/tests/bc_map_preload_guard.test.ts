// CHARACTERIZES a known gap, in the shape `network_and_validation.test.ts` uses for the unchecked
// chain-id header: an EMPTY bc-to-idx map is accepted as a list state.
//
// `lookupBcMap` returns whatever is cached and callers refuse only on `undefined`. An empty Map is
// truthy, so a node that has not bootstrapped — which serves an empty map — makes the SDK write
// "Missing" for every blinded commitment, with no query issued and nothing logged. "Missing" is a
// verdict a wallet acts on.
//
// Asserting that an empty map is REFUSED is what a fix looks like. It was not made here because the
// refusal cannot distinguish "the node has no data" from "this BC is genuinely not on the list"
// without the map's epoch, and the epoch is discarded by `BcToIdxMap = Map<string, number>`
// (`poi-pir.ts:25`) even though `fetchBcToIdxMap` returns it. Carrying it changes a public exported
// type, which is owner-reserved. See the open question filed for this card.

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { RavenPOINodeInterface } from "../src/index";
import { makeRegisterSpy, stubRemoteSessionExports } from "./helpers/register_spy";
import type { ClientPirContext, RavenInspireWasm } from "../src/index";
import { encodeBatchResponseNodes, encodedBatchCount } from "./helpers/auth_path_stub";
import { startMockServer, writeBinary, type MockServer } from "./helpers/mock_server";
import { stubQueryBundle } from "./helpers/private_wire";

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
    shardConfigBincode: new Uint8Array(0),
    entrySize: 32,
  };
}

describe("an empty bc-to-idx map is accepted as a list state", () => {
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
  });
  afterAll(async () => {
    await server.close();
  });

  function sdkWith(map: Map<string, number>): RavenPOINodeInterface {
    return new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, map]]),
    });
  }

  it("an unbootstrapped node's empty map reads as Missing, not as a refusal", async () => {
    const got = await sdkWith(new Map()).getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_HEX, type: "Shield" }],
    );
    // The gap: indistinguishable from a real absence, and acted on as a verdict.
    expect(got[BC_HEX][LIST_KEY_HEX]).toBe("Missing");
  });

  it("a MISSING map entry does refuse, which is the behaviour an empty map should share", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map(),
    });
    await expect(
      sdk.getPOIsPerList([LIST_KEY_HEX], [{ blindedCommitment: BC_HEX, type: "Shield" }]),
    ).rejects.toThrow(/bc-to-idx-map/i);
  });
});
