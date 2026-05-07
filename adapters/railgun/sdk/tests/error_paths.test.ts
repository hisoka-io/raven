/**
 * Error-path + truncated-response handling tests.
 *
 * The SDK MUST fail closed on:
 *   - Server response truncated mid-bincode (PIR query) → typed error
 *     surfaces; SDK does not return garbage.
 *   - Server response 5xx → typed error, no silent empty result.
 *   - Server returns malformed JSON → typed error.
 *   - Client-PIR query returns a too-short bincode (truncated state
 *     prefix) → typed error from `decodeClientPirQueryBundle`.
 *
 * The "fail closed" property is the central correctness invariant
 * for a privacy adapter: a wallet that silently accepts wrong data
 * leaks information by acting on it (sending an unshield against a
 * stale path triggers a chain-side rejection that's observable to
 * the operator, leaking the wallet's intent).
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { RavenPOINodeInterface, RavenError, decodeClientPirQueryBundle } from "../src/index";
import type { ClientPirContext, RavenInspireWasm } from "../src/index";

import { startMockServer, writeBinary, type MockServer } from "./helpers/mock_server";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "abababababababababababababababababababababababababababababababab";

function stubWasm(): RavenInspireWasm {
  return {
    build_client_session: () => ({ free: () => undefined }),
    build_seeded_query: () => {
      // Valid empty bincode: 8 bytes len(0) + 8 bytes len(0) = 16.
      return new Uint8Array(16);
    },
    extract_response: (_a, _b, response, _entry) => {
      // Pass through whatever the server returned. If the server
      // sent garbage, the SDK still gets the bytes; the wallet's
      // domain layer (T1 status decoder, T2 path decoder) is
      // expected to reject zero-length / wrong-shape plaintexts.
      // For T2/T3 path queries the SDK extracts a 32 B node hash, so
      // we surface 32 zero-bytes when the response is non-empty.
      return response.length === 0 ? new Uint8Array(0) : new Uint8Array(32);
    },
    build_instance_params_blob: () => new Uint8Array(0),
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
    // Claim 1000-byte client_state, supply only 16 bytes.
    const buf = new Uint8Array(16);
    new DataView(buf.buffer).setUint32(0, 1000, true);
    expect(() => decodeClientPirQueryBundle(buf)).toThrow(/truncated state payload/);
  });

  it("decodeClientPirQueryBundle rejects truncated query payload", () => {
    // Valid 0-len state + claim 100-byte query, supply only 16+8.
    const buf = new Uint8Array(24);
    new DataView(buf.buffer).setUint32(0, 0, true);
    new DataView(buf.buffer).setUint32(8, 100, true);
    expect(() => decodeClientPirQueryBundle(buf)).toThrow(/truncated query payload/);
  });

  it("decodeClientPirQueryBundle rejects payload > 2^32 bytes (defensive)", () => {
    const buf = new Uint8Array(32);
    // hi word non-zero -> trips the readU64LE check.
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
    // Post-H3 contract: 5xx propagates as a typed RavenError so the
    // wallet can retry against a fresh routing table or fall back
    // to upstream PPOI rather than silently spending against
    // unmarked BCs (which would leak intent to the operator).
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
    // The server response is a zero-byte body; under the auth-path
    // batch flow this is malformed — there's no schema-version
    // prefix or element count. The SDK MUST throw a typed
    // RavenError.decodeError rather than silently fabricate a
    // 0-element proof, because a wallet acting on a 0-element proof
    // would attempt to spend against a malformed Merkle tree.
    server.route(
      (req) => req.url?.startsWith("/v1/instance/") ?? false,
      (_req, _body, res) => {
        writeBinary(res, new Uint8Array(0));
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
