/**
 * Error-path + truncated-response tests: the SDK must fail closed on
 * truncated/malformed/5xx responses. Silently accepting wrong data leaks
 * intent (a spend against a stale path is rejected observably on-chain).
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { RavenPOINodeInterface, RavenError, decodeClientPirQueryBundle } from "../src/index";
import { makeRegisterSpy, stubRemoteSessionExports } from "./helpers/register_spy";
import type { ClientPirContext, RavenInspireWasm } from "../src/index";

import {
  readJsonRpcRequest,
  startMockServer,
  writeBinary,
  type MockServer,
} from "./helpers/mock_server";
import { forestConfig } from "./helpers/forest";
import { shardConfigBincode } from "./helpers/shard_config";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "abababababababababababababababababababababababababababababababab";
const BC_PRESENT = "aa".repeat(32);

/** Holds `BC_PRESENT` at index 0, so a proof reaches the instance route. */
function pathSdk(server: MockServer): RavenPOINodeInterface {
  return new RavenPOINodeInterface({
    ...forestConfig({
      endpoint: server.url,
      listKeyHex: LIST_KEY_HEX,
      ctx: stubCtx(),
      placed: [[BC_PRESENT, 0]],
    }),
    bearerToken: TOKEN,
  });
}

function stubWasm(): RavenInspireWasm {
  return {
    ...stubRemoteSessionExports(),
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
  };
}

function stubCtx(): ClientPirContext {
  const wasm = stubWasm();
  return {
    wasm,
    session: { free: () => undefined },
    crsBincode: new Uint8Array(0),
    shardConfigBincode: shardConfigBincode(),
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

  it("client-PIR T2 batch with HTTP 5xx surfaces as a thrown error (T2 cannot fail-soft)", async () => {
    server.route(
      (req) => req.url?.startsWith("/v1/instance/") ?? false,
      (_req, _body, res) => {
        res.writeHead(503);
        res.end();
        return true;
      },
    );
    await expect(
      pathSdk(server).getPOIMerkleProofs(LIST_KEY_HEX, [BC_PRESENT]),
    ).rejects.toThrow(/client-PIR batch/);
  });

  it("client-PIR T2 empty batch body surfaces as a typed DecodeError (no silent zero-elt proof)", async () => {
    // a zero-byte batch body is malformed; throw rather than fabricate a 0-element proof
    server.route(
      (req) => req.url?.startsWith("/v1/instance/") ?? false,
      (_req, _body, res) => {
        writeBinary(res, new Uint8Array(0), {
          "x-raven-epoch": "1",
          "x-raven-schema-version": "6",
        });
        return true;
      },
    );
    await expect(
      pathSdk(server).getPOIMerkleProofs(LIST_KEY_HEX, [BC_PRESENT]),
    ).rejects.toThrow(/decodeBatchBody|too short|truncated/);
  });

  // 404 on an instance route: what a wallet sees when the node has no instance for a block it
  // was told about, such as a block declared before the node's config caught up. A 404 carries
  // no X-Raven-Schema-Version header, so it must surface as ServerError, never StaleAdapter.

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

  it("T2 getPOIMerkleProofs: 404 from the instance route is a typed ServerError", async () => {
    mount404Instance();
    try {
      await pathSdk(server).getPOIMerkleProofs(LIST_KEY_HEX, [BC_PRESENT]);
      expect.fail("expected ServerError");
    } catch (e) {
      expect(RavenError.is(e, "ServerError"), `wrong kind: ${String(e)}`).toBe(true);
      expect(String((e as Error).message)).toContain("404");
    }
  });

  it("upstream submitPOI propagates 4xx errors typed", async () => {
    server.route(
      (req) => req.url === "/",
      (_req, body, res) => {
        const request = readJsonRpcRequest(body);
        res.writeHead(401, { "content-type": "application/json" });
        res.end(JSON.stringify({
          jsonrpc: "2.0",
          id: request.id,
          error: { code: -32603, message: "unauthorized" },
        }));
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
    ).rejects.toThrow(/-32603: unauthorized/);
  });

  it("syncPoiListIndex throws on non-200", async () => {
    server.route(
      (req) => req.url?.includes("/bc-prefixes") ?? false,
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
    await expect(sdk.syncPoiListIndex(LIST_KEY_HEX)).rejects.toThrow(/bc-prefixes: 403/);
  });
});
