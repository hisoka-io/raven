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
import {
  readJsonRpcRequest,
  startMockServer,
  writeBinary,
  writeJsonRpcResult,
  type MockServer,
} from "./helpers/mock_server";
import {
  commitmentAt,
  mountPrefixChannel,
  mountStatusRows,
  prefixIndexOf,
  prefixTwinOf,
  targetNamingCtx,
  type MockList,
} from "./helpers/prefix_channel";
import { stubQueryBundle } from "./helpers/private_wire";
import { shardConfigBincode } from "./helpers/shard_config";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "abababababababababababababababababababababababababababababababab";
const BC_BARE = "bc00112233445566778899aabbccddeeff00112233445566778899aabbccdd01";
/** The only shape the engine ever produces. */
const BC_PREFIXED = `0x${BC_BARE}`;
const STATUS_ROW_BYTES = 32;
const STALE_FRESHNESS = "lag_blocks=999 applied_height=10 epoch=1 confidence=0.10";

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
    shardConfigBincode: shardConfigBincode(),
    entrySize: STATUS_ROW_BYTES,
  };
}

/** Real fetch everywhere but the PIR batch POST, which fails the way a dropped socket does. */
function batchFailsFetch(): typeof fetch {
  return async (input, init) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (/\/v1\/instance\/[^/]+\/batch$/.test(url)) {
      throw new TypeError("fetch failed");
    }
    return await fetch(input, init);
  };
}

/** Real fetch everywhere but the list-index walk, which fails the way a dropped socket does. */
function indexSyncFailsFetch(attempts: string[]): typeof fetch {
  return async (input, init) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (/\/bc-prefixes\?/.test(url)) {
      attempts.push(url);
      throw new TypeError("fetch failed");
    }
    return await fetch(input, init);
  };
}

function mountStatusRow(
  server: MockServer,
  row: Uint8Array,
  headers: Record<string, string> = {},
): void {
  server.route(
    (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
    (_req, body, res) => {
      const count = encodedBatchCount(body);
      writeBinary(res, encodeBatchResponseNodes(Array.from({ length: count }, () => row)), headers);
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
  let upstream: MockServer;
  beforeAll(async () => {
    server = await startMockServer();
    upstream = await startMockServer();
  });
  afterAll(async () => {
    await server.close();
    await upstream.close();
  });
  afterEach(() => {
    server.reset();
    upstream.reset();
  });

  // The bc-to-idx map is published BARE (`http/src/poi_shim.rs:477`), so the internal lookup must
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

  // The absent-BC arm writes the row it was handed. A bare map has no row count, so reaching the
  // arm at all takes the caller's explicit decision.
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
      indexStalenessPolicy: "answer-at-index-rows",
    });
    const got = await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_PREFIXED, type: "Shield" }],
    );
    expect(Object.keys(got)).toStrictEqual([BC_PREFIXED]);
    expect(got[BC_PREFIXED][LIST_KEY_HEX]).toBe("MissingStale");
  });

  // A row sharing only the prefix is another commitment, and once no candidate is left the absence
  // is answered on the row the caller looks up, as the no-candidate case is.
  it("keeps the caller's string when every prefix candidate is another commitment", async () => {
    const list: MockList = { commitments: [commitmentAt(0), prefixTwinOf(5)] };
    mountPrefixChannel(server, LIST_KEY_HEX, list);
    mountStatusRows(server, list, () => 1);
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, targetNamingCtx()]]),
      poiListIndexStore: false,
    });
    await sdk.syncPoiListIndex(LIST_KEY_HEX);
    const caller = `0x${commitmentAt(5)}`;
    const got = await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: caller, type: "Shield" }],
    );
    expect(Object.keys(got)).toStrictEqual([caller]);
    expect(got[caller][LIST_KEY_HEX]).toBe("Missing");
    expect(server.requests.filter((r) => /\/batch$/.test(r.url))).toHaveLength(1);
    expect(sdk.indexCounters().absent).toBe(1);
  });

  // The plaintext path re-keys whatever spelling the server chose, so it holds whether or not
  // the server echoes: the shim does (`poi_shim.rs:255`), an upstream passthrough need not.
  it("the plaintext shim path also returns the caller's exact string", async () => {
    server.route(
      (req) => req.url === "/v1/poi/pois-per-list",
      (_req, _body, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        // A server that keys by bare hex rather than echoing, which the SDK must re-key.
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

  // The degradation arms. `getPOIsPerList` catches a `Network` RavenError in two places, around the
  // PIR batch and around the index sync before it, and writes "Unreachable" per commitment.
  it("a network failure degrades to Unreachable under the caller's exact string", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[BC_BARE, 0]])]]),
      fetchImpl: batchFailsFetch(),
    });
    const got = await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_PREFIXED, type: "Shield" }],
    );
    expect(Object.keys(got)).toStrictEqual([BC_PREFIXED]);
    expect(got[BC_PREFIXED][LIST_KEY_HEX]).toBe("Unreachable");
  });

  // A held index is brought up to the node's list before it answers. When that fails on the
  // network, a commitment it holds no row for reads "Unreachable", as a failed query does.
  it("keeps the caller's string when a held index cannot sync", async () => {
    mountStatusRow(server, statusRow(0, commitmentAt(0)));
    const attempts: string[] = [];
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, stubCtx()]]),
      poiListIndexes: new Map([[LIST_KEY_HEX, prefixIndexOf([commitmentAt(0)])]]),
      poiListIndexStore: false,
      fetchImpl: indexSyncFailsFetch(attempts),
    });
    const got = await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_PREFIXED, type: "Shield" }],
    );
    expect(Object.keys(got)).toStrictEqual([BC_PREFIXED]);
    expect(got[BC_PREFIXED][LIST_KEY_HEX]).toBe("Unreachable");
    expect(attempts).toHaveLength(1);
    expect(server.requests.some((r) => r.url.endsWith("/batch"))).toBe(true);
    expect(server.requests.every((r) => /\/(session|batch)$/.test(r.url))).toBe(true);
  });

  // The disclosure fallback. Upstream keys its answer by the string it was sent
  // (`poiStatusPerBlindedCommitment` in the aggregator's merkletree manager), which is the
  // caller's, so the caller's string is the only spelling that finds it.
  it("keeps the caller's string on the stale-status upstream fallback", async () => {
    mountStatusRow(server, statusRow(0, BC_BARE), { "x-raven-freshness": STALE_FRESHNESS });
    upstream.route(
      (req) => req.url === "/",
      (_req, body, res) => {
        const request = readJsonRpcRequest(body);
        expect(request.method).toBe("ppoi_pois_per_list");
        const asked = request.params.blindedCommitmentDatas as { blindedCommitment: string }[];
        const answer: Record<string, Record<string, string>> = {};
        for (const { blindedCommitment } of asked) {
          answer[blindedCommitment] = { [LIST_KEY_HEX]: "ShieldBlocked" };
        }
        writeJsonRpcResult(body, res, answer);
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[BC_BARE, 0]])]]),
      upstreamFallbackEndpoint: upstream.url,
      privateStalePolicy: "allow-upstream-disclosure",
    });
    const got = await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_PREFIXED, type: "Shield" }],
    );
    expect(Object.keys(got)).toStrictEqual([BC_PREFIXED]);
    expect(got[BC_PREFIXED][LIST_KEY_HEX]).toBe("ShieldBlocked");
    expect(upstream.requests).toHaveLength(1);
  });

  it("a bare-hex caller also degrades to Unreachable under its own string", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[BC_BARE, 0]])]]),
      fetchImpl: batchFailsFetch(),
    });
    const got = await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_BARE, type: "Shield" }],
    );
    expect(Object.keys(got)).toStrictEqual([BC_BARE]);
    expect(got[BC_BARE][LIST_KEY_HEX]).toBe("Unreachable");
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
