/** Client-PIR pre-flight routing tests against a stub WASM (no real PIR). */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { RavenError, RavenPOINodeInterface } from "../src/index";
import { makeRegisterSpy } from "./helpers/register_spy";
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
    register_client_session: makeRegisterSpy(),
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
    // The throw has to come BEFORE any wire call: a query for a BC the client cannot place
    // in the list would publish the lookup to the server the PIR path exists to blind.
    expect(sdk.lastWireRequests().length).toBe(0);
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
    // PINS A KNOWN FAIL-OPEN; it is NOT an endorsement. `Missing` is
    // the non-blocking verdict, so this substitution reports a possibly-ShieldBlocked
    // commitment as merely unproven. The companion test below asserts the consequence:
    // the result is indistinguishable from a genuinely absent record.
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

  it("a transport failure is indistinguishable from a genuinely absent record", () => {
    // CHARACTERIZATION of the fail-open above, so its consequence is a tracked contract
    // rather than an incidental fact. This is the assertion a fix must INVERT: today the
    // caller cannot tell "the network broke, this may be ShieldBlocked" from "no such
    // record exists". A commitment in the map degrades to Missing when the transport
    // fails; one absent from the map is set to Missing without any query at all. Both
    // land in the same string-valued field, and `POIStatus` carries no variant, cause or
    // flag that separates them. Inverting this assertion is what a fix looks like.
    const bcQueried = "0000000000000000000000000000000000000000000000000000000000000099";
    const bcAbsent = "00000000000000000000000000000000000000000000000000000000000000aa";
    const bcMap = new Map<string, number>([[bcQueried, 0]]);
    const sdk = new RavenPOINodeInterface({
      endpoint: "http://127.0.0.1:1",
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, bcMap]]),
    });
    return sdk
      .getPOIsPerList(
        [LIST_KEY_HEX],
        [
          { blindedCommitment: bcQueried, type: "Shield" },
          { blindedCommitment: bcAbsent, type: "Shield" },
        ],
      )
      .then((got) => {
        const fromBrokenTransport = got[bcQueried][LIST_KEY_HEX];
        const fromAbsentRecord = got[bcAbsent][LIST_KEY_HEX];
        expect(fromBrokenTransport).toBe("Missing");
        expect(fromAbsentRecord).toBe("Missing");
        expect(fromBrokenTransport).toStrictEqual(fromAbsentRecord);
      });
  });

  it("captured request ring is bounded at exactly the 64-entry cap", async () => {
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
    // Mirrors the cap literal in captureRequest (src/raven-poi-node-interface.ts); the ring
    // retains ~19 KB per slot including plaintext blinded commitments on the passthrough
    // routes, so its size is a security-relevant quantity, not a nicety.
    const WIRE_RING_CAP = 64;
    // each fetch 404s but records into the ring first; 70 > the 64 cap
    for (let i = 0; i < WIRE_RING_CAP + 6; i += 1) {
      try {
        await sdk.fetchBcToIdxMap(LIST_KEY_HEX);
      } catch {
      }
    }
    // toBe, not toBeLessThanOrEqual: zero satisfied the old bound, so the test stayed
    // green with capture deleted outright (mutation M4, w4d-sdk). Equality is the only
    // form that both catches unbounded growth AND proves capture still happens.
    const wires = sdk.lastWireRequests();
    expect(wires.length).toBe(WIRE_RING_CAP);
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
    }
    expect(sdk.lastWireRequests().length).toBe(1);
    sdk.resetWireCapture();
    expect(sdk.lastWireRequests().length).toBe(0);
  });

  it("lastWireRequests returns a fresh array (pushes cannot grow the ring)", async () => {
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
    }
    const ring1 = sdk.lastWireRequests();
    const len1 = ring1.length;
    expect(len1).toBeGreaterThan(0);
    ring1.push({ url: "evil", method: "POST", body: new Uint8Array(0) });
    const ring2 = sdk.lastWireRequests();
    expect(ring2.length).toBe(len1);
  });

  it("lastWireRequests deep-clones retained request bodies", async () => {
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
      useClientPir: false,
    });
    try {
      // Legacy JSON path: captureRequest records a NON-EMPTY body before the fetch 404s.
      await sdk.getPOIsPerList(
        [LIST_KEY_HEX],
        [{ blindedCommitment: BC_HEX, type: "Shield" }],
      );
    } catch {
    }
    const ring1 = sdk.lastWireRequests();
    expect(ring1.length).toBeGreaterThan(0);
    expect(ring1[0].body.length).toBeGreaterThan(0);
    const before = sdk.lastWireRequests()[0].body[0];
    ring1[0].body[0] = before ^ 0xff;
    const after = sdk.lastWireRequests()[0].body[0];
    expect(after).toBe(before);
  });
});
