/**
 * Client-PIR routing + error-path tests.
 *
 * Locks the SDK's pre-flight checks for the encrypted-PIR codepaths:
 *
 *   - Missing `clientPirContexts` for the requested list_key:
 *     getPOIsPerList throws.
 *   - Missing `bcToIdxMaps` entry: getPOIsPerList throws.
 *   - BC absent from the bc-to-idx-map (T1) -> SDK returns "Missing"
 *     for that BC (per the M015-style fail-soft convention; the
 *     wallet should not see an exception per BC).
 *   - BC absent from the bc-to-idx-map (T2) -> SDK throws (T2 cannot
 *     fabricate a path; missing BC is a hard error).
 *   - getMerkleProof (T3) without context -> throws.
 *
 * Does NOT exercise the real wasm path; uses a stub WASM that
 * returns a deterministic byte sequence so the SDK's pre-flight
 * branches surface cleanly.
 */

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
      // Bincode shape `(client_state: Vec<u8>, query_bytes: Vec<u8>)`
      // — both empty. 8 + 0 + 8 + 0 = 16 bytes total.
      const out = new Uint8Array(16);
      // Both u64 LE length prefixes are zero already.
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
      // No contexts supplied for this list.
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
      // bc-to-idx-map is empty for this list, so BC_HEX maps to no
      // index at all.
      bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map()]]),
    });
    const got = await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_HEX, type: "Shield" }],
    );
    expect(got[BC_HEX][LIST_KEY_HEX]).toBe("Missing");
    // No wire request — the missing-BC path short-circuits client-side.
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
    // Outer key is BC hex, inner is list-key hex. Mirrors upstream
    // POIsPerListMap shape from
    // shared-models/src/models/proof-of-innocence.ts:153.
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
    // Post-H3 contract: 5xx propagates as a typed RavenError so
    // the wallet can retry against a fresh routing table or fall
    // back to upstream PPOI rather than silently spending against
    // unmarked BCs.
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
    // Pointing at an unreachable port simulates a transient network
    // error; the SDK MUST surface Missing per BC under H3. This is
    // the ONLY codepath where Missing is the right substitution —
    // genuine network drops are recoverable via wallet retry, while
    // server-side errors must propagate.
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
    // Pummel the ring with publishing-channel fetches; each fails
    // with 404 but every attempt records into the ring before the
    // fetch resolves.
    for (let i = 0; i < 70; i += 1) {
      try {
        await sdk.fetchBcToIdxMap(LIST_KEY_HEX);
      } catch {
        // 404 -> SDK throws.
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
