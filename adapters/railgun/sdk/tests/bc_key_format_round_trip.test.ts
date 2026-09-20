// The engine emits `0x`-prefixed blinded commitments (`blinded-commitment.ts:4-6`) and looks the
// result up with a bare object index (`abstract-wallet.ts:1420`), where a miss is an unlogged
// `continue`. So if the adapter re-keys the response, every status is dropped in silence and the
// integration is a no-op that re-queues 1,000 BCs on every refresh forever.
//
// The contract is the stock one: `TestPOINodeInterface.getPOIsPerList` keys by
// `blindedCommitmentData.blindedCommitment` VERBATIM. Normalization is for internal lookup only.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { RavenPOINodeInterface, hexToBytes } from "../src/index";
import { makeRegisterSpy, stubRemoteSessionExports } from "./helpers/register_spy";
import type { ClientPirContext, RavenInspireWasm } from "../src/index";
import { encodeBatchResponseNodes, encodedBatchCount } from "./helpers/auth_path_stub";
import { startMockServer, writeBinary, type MockServer } from "./helpers/mock_server";
import { stubQueryBundle } from "./helpers/private_wire";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "abababababababababababababababababababababababababababababababab";
const BC_BARE = "bc00112233445566778899aabbccddeeff00112233445566778899aabbccdd01";
/** The only shape the engine ever produces. */
const BC_PREFIXED = `0x${BC_BARE}`;
const STATUS_ROW_BYTES = 32;

function statusRow(statusByte: number, bcHex: string): Uint8Array {
  const row = new Uint8Array(STATUS_ROW_BYTES);
  row[0] = statusByte;
  row.set(hexToBytes(bcHex).subarray(0, STATUS_ROW_BYTES - 1), 1);
  return row;
}

function passthroughWasm(): RavenInspireWasm {
  return {
    ...stubRemoteSessionExports(),
    build_client_session: () => ({ free: () => undefined }),
    build_seeded_query: () => stubQueryBundle(),
    extract_response: (_s, _c, _st, response, _e) => new Uint8Array(response),
    build_instance_params_blob: () => new Uint8Array(0),
    register_client_session: makeRegisterSpy(),
    path_indices_for_leaf: () => new Uint32Array(16),
    path_indices_for_per_list_leaf: () => new Uint32Array(16),
  };
}

function stubCtx(): ClientPirContext {
  return {
    wasm: passthroughWasm(),
    session: { free: () => undefined },
    crsBincode: new Uint8Array(0),
    shardConfigBincode: new Uint8Array(0),
    entrySize: STATUS_ROW_BYTES,
  };
}

function mountStatusRow(server: MockServer, row: Uint8Array): void {
  server.route(
    (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
    (_req, body, res) => {
      const count = encodedBatchCount(body);
      writeBinary(res, encodeBatchResponseNodes(Array.from({ length: count }, () => row)));
      return true;
    },
  );
}

/**
 * The stock contract, copied from `engine/src/test/test-poi-node-interface.test.ts`: the outer key
 * is the caller's string, untouched. Any adapter that satisfies the interface must agree with this.
 */
function stockContractKeys(listKeys: string[], bcs: string[]): Record<string, Record<string, string>> {
  const out: Record<string, Record<string, string>> = {};
  for (const bc of bcs) {
    out[bc] ??= {};
    for (const lk of listKeys) out[bc][lk] = "Valid";
  }
  return out;
}

describe("the key format the wallet looks up with is the key format the adapter emits", () => {
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

  // The bc-to-idx map is published BARE (`http/src/poi_shim.rs:341`), so the internal lookup must
  // still normalize. Only the response key is at issue.
  function clientPirSdk(): RavenPOINodeInterface {
    return new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[BC_BARE, 0]])]]),
    });
  }

  it("client-PIR returns the caller's exact string as the outer key", async () => {
    mountStatusRow(server, statusRow(0, BC_BARE));
    const sdk = clientPirSdk();
    const got = await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_PREFIXED, type: "Shield" }],
    );
    expect(Object.keys(got)).toStrictEqual([BC_PREFIXED]);
    expect(got[BC_PREFIXED]).toBeDefined();
  });

  it("agrees with the stock contract's keying for the same input", async () => {
    mountStatusRow(server, statusRow(0, BC_BARE));
    const sdk = clientPirSdk();
    const got = await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_PREFIXED, type: "Shield" }],
    );
    const oracle = stockContractKeys([LIST_KEY_HEX], [BC_PREFIXED]);
    expect(Object.keys(got).sort()).toStrictEqual(Object.keys(oracle).sort());
    expect(Object.keys(got[BC_PREFIXED]).sort()).toStrictEqual(
      Object.keys(oracle[BC_PREFIXED]).sort(),
    );
  });

  // The absent-BC arm at `:795` writes its own key and is reached without any query.
  it("keeps the caller's string on the absent-BC arm", async () => {
    // An all-absent batch still issues one empty-chunk query: chunkCount is
    // `Math.max(1, ceil(0 / MAX_BATCH_SIZE))` = 1, so the route must exist.
    mountStatusRow(server, statusRow(0, BC_BARE));
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map<string, number>()]]),
    });
    const got = await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_PREFIXED, type: "Shield" }],
    );
    expect(Object.keys(got)).toStrictEqual([BC_PREFIXED]);
    expect(got[BC_PREFIXED][LIST_KEY_HEX]).toBe("Missing");
  });

  // `useClientPir: false` does NOT avoid the defect: `poi_shim.rs:186` re-keys with bare hex_encode.
  it("the plaintext shim path also returns the caller's exact string", async () => {
    server.route(
      (req) => req.url === "/v1/poi/pois-per-list",
      (_req, _body, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        // Exactly what the Rust shim emits today: keys are bare hex.
        res.end(JSON.stringify({ [BC_BARE]: { [LIST_KEY_HEX]: "Valid" } }));
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
      [{ blindedCommitment: BC_PREFIXED, type: "Shield" }],
    );
    expect(Object.keys(got)).toStrictEqual([BC_PREFIXED]);
    expect(got[BC_PREFIXED][LIST_KEY_HEX]).toBe("Valid");
  });

  // A bare caller must keep working byte-identically — the fix must not invert the bug.
  it("a bare-hex caller still gets a bare-hex key back", async () => {
    mountStatusRow(server, statusRow(0, BC_BARE));
    const sdk = clientPirSdk();
    const got = await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_BARE, type: "Shield" }],
    );
    expect(Object.keys(got)).toStrictEqual([BC_BARE]);
  });
});
