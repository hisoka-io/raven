/** Client-PIR pre-flight routing tests against a stub WASM (no real PIR). */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { RavenError, RavenPOINodeInterface } from "../src/index";
import type { ClientPirContext, RavenInspireWasm } from "../src/index";

import { startMockServer, type MockServer } from "./helpers/mock_server";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "abababababababababababababababababababababababababababababababab";
const BC_HEX = "0000000000000000000000000000000000000000000000000000000000000001";

/** Stub WASM impl that returns minimal bincode-prefixed payloads. */
function stubWasm(): RavenInspireWasm {
  return {
    build_client_session: () => ({ free: () => undefined }),
    build_seeded_query: (_session, _shard, _idx) => {
      // empty (client_state, query_bytes): 8 + 0 + 8 + 0 = 16 zero bytes
      const out = new Uint8Array(16);
      return out;
    },
    extract_response: () => new Uint8Array(0),
    build_instance_params_blob: (_a, _b) => new Uint8Array(0),
    register_client_session: undefined,
    path_indices_for_leaf: () => new Uint32Array(16),
    path_indices_for_per_list_leaf: () => new Uint32Array(16),
  };
}

function stubCtx(): ClientPirContext {
  const wasm = stubWasm();
  return {
    wasm,
    session: { free: () => undefined },
    crsBincode: new Uint8Array(0),
    shardConfigBincode: new Uint8Array(0),
    entrySize: 32,
  };
}

describe("client-PIR routing + pre-flight", () => {
  let server: MockServer;

  beforeAll(async () => {
    server = await startMockServer();
  });

  afterAll(async () => {
    await server.close();
  });

  it("getPOIsPerList client-PIR mode missing context throws", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map(),
      bcToIdxMaps: new Map(),
    });
    await expect(
      sdk.getPOIsPerList(
        [LIST_KEY_HEX],
        [{ blindedCommitment: BC_HEX, type: "Shield" }],
      ),
    ).rejects.toThrow(/missing context or bc-to-idx-map/);
    expect(sdk.lastWireRequests().length).toBe(0);
  });

  it("getPOIsPerList client-PIR mode missing bc-to-idx-map throws", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map(),
    });
    await expect(
      sdk.getPOIsPerList(
        [LIST_KEY_HEX],
        [{ blindedCommitment: BC_HEX, type: "Shield" }],
      ),
    ).rejects.toThrow(/missing context or bc-to-idx-map/);
  });

  it("getPOIsPerList client-PIR mode unknown BC returns Missing", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map()]]),
    });
    const got = await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_HEX, type: "Shield" }],
    );
    expect(got[BC_HEX][LIST_KEY_HEX]).toBe("Missing");
    // missing-BC path short-circuits client-side
    expect(sdk.lastWireRequests().length).toBe(0);
  });

  it("getPOIMerkleProofs client-PIR mode unknown BC throws", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t2Path:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map()]]),
    });
    await expect(
      sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]),
    ).rejects.toThrow(/idx unknown/);
  });

  it("getMerkleProof client-PIR mode missing context throws", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map(),
    });
    await expect(sdk.getMerkleProof(0, 0)).rejects.toThrow(/missing context for commit tree 0/);
  });

  it("getPOIsPerList surfaces every (BC, listKey) cell across multiple lists", async () => {
    // outer key BC, inner list-key: upstream POIsPerListMap shape (shared-models proof-of-innocence.ts)
    const lkA = "11".repeat(32);
    const lkB = "22".repeat(32);
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([
        [`t1Status:${lkA}`, stubCtx()],
        [`t1Status:${lkB}`, stubCtx()],
      ]),
      bcToIdxMaps: new Map([
        [lkA, new Map()],
        [lkB, new Map()],
      ]),
    });
    const got = await sdk.getPOIsPerList(
      [lkA, lkB],
      [{ blindedCommitment: BC_HEX, type: "Shield" }],
    );
    expect(Object.keys(got)).toEqual([BC_HEX]);
    expect(got[BC_HEX][lkA]).toBe("Missing");
    expect(got[BC_HEX][lkB]).toBe("Missing");
  });

  it("getPOIsPerList client-PIR propagates 5xx as ServerError (no silent Missing)", async () => {
    // 5xx must propagate so the wallet retries/falls back instead of silently spending against unmarked BCs
    server.route(
      (req) => req.url?.startsWith("/v1/instance/") ?? false,
      (_req, _body, res) => {
        res.writeHead(500, { "content-type": "text/plain" });
        res.end("server error");
        return true;
      },
    );
    const bcPresent = "0000000000000000000000000000000000000000000000000000000000000099";
    const bcMap = new Map<string, number>([[bcPresent, 0]]);
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, bcMap]]),
    });
    try {
      await sdk.getPOIsPerList(
        [LIST_KEY_HEX],
        [
          { blindedCommitment: bcPresent, type: "Shield" },
          { blindedCommitment: BC_HEX, type: "Shield" },
        ],
      );
      expect.fail("expected ServerError");
    } catch (e) {
      expect(RavenError.is(e, "ServerError")).toBe(true);
    }
  });

  it("getPOIsPerList client-PIR fail-soft on Network error only", async () => {
    // unreachable port: a transient network drop is the only case where Missing is the right substitution
    const bcPresent = "0000000000000000000000000000000000000000000000000000000000000099";
    const bcMap = new Map<string, number>([[bcPresent, 0]]);
    const sdk = new RavenPOINodeInterface({
      endpoint: "http://127.0.0.1:1",
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, bcMap]]),
    });
    const got = await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: bcPresent, type: "Shield" }],
    );
    expect(got[bcPresent][LIST_KEY_HEX]).toBe("Missing");
  });

  it("captured request ring is bounded at 64 entries", async () => {
    server.route(
      () => true,
      (_req, _body, res) => {
        res.writeHead(404);
        res.end();
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
    });
    // each fetch 404s but records into the ring first; 70 > the 64 cap
    for (let i = 0; i < 70; i += 1) {
      try {
        await sdk.fetchBcToIdxMap(LIST_KEY_HEX);
      } catch {
        // expected 404
      }
    }
    const wires = sdk.lastWireRequests();
    expect(wires.length).toBeLessThanOrEqual(64);
  });

  it("resetWireCapture clears the ring", async () => {
    server.route(
      () => true,
      (_req, _body, res) => {
        res.writeHead(404);
        res.end();
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
    });
    try {
      await sdk.fetchBcToIdxMap(LIST_KEY_HEX);
    } catch {
      // expected.
    }
    expect(sdk.lastWireRequests().length).toBe(1);
    sdk.resetWireCapture();
    expect(sdk.lastWireRequests().length).toBe(0);
  });

  it("lastWireRequests returns a defensive copy (cannot mutate the ring)", async () => {
    server.route(
      () => true,
      (_req, _body, res) => {
        res.writeHead(404);
        res.end();
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
    });
    try {
      await sdk.fetchBcToIdxMap(LIST_KEY_HEX);
    } catch {
      // expected.
    }
    const ring1 = sdk.lastWireRequests();
    const len1 = ring1.length;
    ring1.push({ url: "evil", method: "POST", body: new Uint8Array(0) });
    const ring2 = sdk.lastWireRequests();
    expect(ring2.length).toBe(len1);
  });
});
