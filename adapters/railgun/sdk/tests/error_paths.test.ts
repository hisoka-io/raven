/**
 * Error-path + truncated-response tests: the SDK must fail closed on
 * truncated/malformed/5xx responses. Silently accepting wrong data leaks
 * intent (a spend against a stale path is rejected observably on-chain).
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { RavenPOINodeInterface, RavenError, decodeClientPirQueryBundle } from "../src/index";
import { makeRegisterSpy } from "./helpers/register_spy";
import type { ClientPirContext, RavenInspireWasm } from "../src/index";

import { startMockServer, writeBinary, type MockServer } from "./helpers/mock_server";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "abababababababababababababababababababababababababababababababab";

function stubWasm(): RavenInspireWasm {
  return {
    build_client_session: () => ({ free: () => undefined }),
    build_seeded_query: () => {
      return new Uint8Array(16);
    },
    extract_response: (_session, _a, _b, response, _entry) => {
      // surface a 32 B node hash for non-empty responses; the domain decoders reject bad shapes
      return response.length === 0 ? new Uint8Array(0) : new Uint8Array(32);
    },
    build_instance_params_blob: () => new Uint8Array(0),
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

describe("error-path + truncated-response handling", () => {
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

  it("decodeClientPirQueryBundle rejects buffer < 8 bytes", () => {
    expect(() => decodeClientPirQueryBundle(new Uint8Array(4))).toThrow(/buffer too short/);
  });

  it("decodeClientPirQueryBundle rejects truncated state payload", () => {
    const buf = new Uint8Array(16);
    new DataView(buf.buffer).setUint32(0, 1000, true);
    expect(() => decodeClientPirQueryBundle(buf)).toThrow(/truncated state payload/);
  });

  it("decodeClientPirQueryBundle rejects truncated query payload", () => {
    const buf = new Uint8Array(24);
    new DataView(buf.buffer).setUint32(0, 0, true);
    new DataView(buf.buffer).setUint32(8, 100, true);
    expect(() => decodeClientPirQueryBundle(buf)).toThrow(/truncated query payload/);
  });

  it("decodeClientPirQueryBundle rejects payload > 2^32 bytes (defensive)", () => {
    const buf = new Uint8Array(32);
    // non-zero hi word trips the readU64LE 2^32 guard
    new DataView(buf.buffer).setUint32(0, 0, true);
    new DataView(buf.buffer).setUint32(4, 1, true);
    expect(() => decodeClientPirQueryBundle(buf)).toThrow(/exceeds 2\^32/);
  });

  it("getPOIsPerList legacy mode throws on malformed JSON response", async () => {
    server.route(
      (req) => req.url === "/v1/poi/pois-per-list",
      (_req, _body, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end("{not-json-at-all");
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: false,
    });
    await expect(
      sdk.getPOIsPerList(
        [LIST_KEY_HEX],
        [{ blindedCommitment: "11".repeat(32), type: "Shield" }],
      ),
    ).rejects.toThrow();
  });

  it("client-PIR query with HTTP 5xx propagates as typed ServerError (no silent Missing)", async () => {
    // 5xx must propagate so the wallet retries/falls back instead of silently spending against unmarked BCs
    server.route(
      (req) => req.url?.startsWith("/v1/instance/") ?? false,
      (_req, _body, res) => {
        res.writeHead(503, { "content-type": "text/plain" });
        res.end("server overload");
        return true;
      },
    );
    const bcMap = new Map<string, number>([["aa".repeat(32), 0]]);
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
        [{ blindedCommitment: "aa".repeat(32), type: "Shield" }],
      );
      expect.fail("expected ServerError");
    } catch (e) {
      expect(RavenError.is(e, "ServerError")).toBe(true);
    }
  });

  it("client-PIR T2 batch with HTTP 5xx surfaces as a thrown error (T2 cannot fail-soft)", async () => {
    server.route(
      (req) => req.url?.startsWith("/v1/instance/") ?? false,
      (_req, _body, res) => {
        res.writeHead(503);
        res.end();
        return true;
      },
    );
    const bcMap = new Map<string, number>([["aa".repeat(32), 0]]);
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t2Path:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, bcMap]]),
    });
    await expect(
      sdk.getPOIMerkleProofs(LIST_KEY_HEX, ["aa".repeat(32)]),
    ).rejects.toThrow(/client-PIR batch/);
  });

  it("client-PIR T2 empty batch body surfaces as a typed DecodeError (no silent zero-elt proof)", async () => {
    // a zero-byte batch body is malformed; throw rather than fabricate a 0-element proof
    server.route(
      (req) => req.url?.startsWith("/v1/instance/") ?? false,
      (_req, _body, res) => {
        writeBinary(res, new Uint8Array(0), {
          "x-raven-epoch": "1",
          "x-raven-schema-version": "1",
        });
        return true;
      },
    );
    const bcMap = new Map<string, number>([["aa".repeat(32), 0]]);
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t2Path:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, bcMap]]),
    });
    await expect(
      sdk.getPOIMerkleProofs(LIST_KEY_HEX, ["aa".repeat(32)]),
    ).rejects.toThrow(/decodeBatchBody|too short|truncated/);
  });

  // -------------------------------------------------------------------------
  // 404 on an instance route: the client-side half of the tree-4 outage class.
  // Railgun rolled to a new commit tree, the adapter had no instance for it, and
  // every instance-route request answered 404. The offline suite covered 5xx on
  // /query and 404 on bc-to-idx-map, but never 404 on /v1/instance/* — the exact
  // wire shape a wallet sees during that outage. A 404 carries no
  // X-Raven-Schema-Version header, so it must surface as ServerError (never
  // StaleAdapter, never a downgraded Network->Missing verdict).
  // -------------------------------------------------------------------------

  function mount404Instance(): void {
    server.route(
      (req) => req.url?.startsWith("/v1/instance/") ?? false,
      (_req, _body, res) => {
        res.writeHead(404, { "content-type": "text/plain" });
        res.end("no such instance");
        return true;
      },
    );
  }

  it("T1 getPOIsPerList: 404 from the instance route is a typed ServerError, no verdict fabricated", async () => {
    mount404Instance();
    const bcPresent = "aa".repeat(32);
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[bcPresent, 0]])]]),
    });
    try {
      const got = await sdk.getPOIsPerList(
        [LIST_KEY_HEX],
        [{ blindedCommitment: bcPresent, type: "Shield" }],
      );
      expect.fail(
        `expected ServerError, got a verdict map: ${JSON.stringify(got)} — ` +
          "a missing instance answered with a confident verdict is the outage made silent",
      );
    } catch (e) {
      expect(RavenError.is(e, "ServerError"), `wrong kind: ${String(e)}`).toBe(true);
      expect(RavenError.is(e, "StaleAdapter")).toBe(false);
      expect(RavenError.is(e, "Network")).toBe(false);
      expect(String((e as Error).message)).toContain("404");
    }
  });

  it("T2 getPOIMerkleProofs: 404 from the instance route is a typed ServerError", async () => {
    mount404Instance();
    const bcPresent = "aa".repeat(32);
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t2Path:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[bcPresent, 0]])]]),
    });
    try {
      await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [bcPresent]);
      expect.fail("expected ServerError");
    } catch (e) {
      expect(RavenError.is(e, "ServerError"), `wrong kind: ${String(e)}`).toBe(true);
      expect(String((e as Error).message)).toContain("404");
    }
  });

  it("T3 getMerkleProof: 404 from the instance route is a typed ServerError (tree-4 shape)", async () => {
    mount404Instance();
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([["t3CommitTree:4", stubCtx()]]),
    });
    // Tree 4 with a context but no server instance: the live incident's exact shape —
    // the CLIENT is willing, the SERVER has nothing to answer with.
    try {
      await sdk.getMerkleProof(4, 0);
      expect.fail("expected ServerError");
    } catch (e) {
      expect(RavenError.is(e, "ServerError"), `wrong kind: ${String(e)}`).toBe(true);
      expect(String((e as Error).message)).toContain("404");
    }
  });

  it("upstream submitPOI propagates 4xx errors typed", async () => {
    server.route(
      (req) => req.url === "/submit-transact-proof/0/1",
      (_req, _body, res) => {
        res.writeHead(401);
        res.end();
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      upstreamFallbackEndpoint: server.url,
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
        "a".repeat(64),
        fakeProof,
        [],
        "0".repeat(64),
        0,
        [],
        "",
      ),
    ).rejects.toThrow(/401/);
  });

  it("fetchBcToIdxMap throws on non-200", async () => {
    server.route(
      (req) => req.url?.endsWith("/bc-to-idx-map") ?? false,
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
    await expect(sdk.fetchBcToIdxMap(LIST_KEY_HEX)).rejects.toThrow(/bc-to-idx-map: 404/);
  });

  it("fetchStatusHeader throws on non-200", async () => {
    server.route(
      (req) => req.url?.endsWith("/status-header") ?? false,
      (_req, _body, res) => {
        res.writeHead(403);
        res.end();
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
    });
    await expect(sdk.fetchStatusHeader(LIST_KEY_HEX)).rejects.toThrow(/status-header: 403/);
  });
});
