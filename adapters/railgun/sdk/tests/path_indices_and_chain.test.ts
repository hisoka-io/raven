/**
 * Path-indices-driven auth-path PIR + multi-chain routing + IMT
 * cache + typed-error coverage. This file is the closure for the
 * client-side path-construction story:
 *
 *   - The wallet locally computes the 16 row-indices for an auth
 *     path via `wasm.path_indices_for_leaf` /
 *     `wasm.path_indices_for_per_list_leaf`.
 *   - The SDK dispatches one batch of 16 encrypted PIR queries to
 *     `POST /v1/instance/<id>/batch`.
 *   - No plaintext leaf-index or BC ever crosses the wire.
 *
 * Plus the surrounding production-readiness coverage:
 *   - per-status routing (Shield × {Valid, ShieldBlocked,
 *     ProofSubmitted, Missing}, Transact × ditto, Nullified ×
 *     {Valid, Missing}, Unshield × {Valid, Missing})
 *   - cross-tree spend (leaf in tree N, spend in tree M)
 *   - cache hit / cache miss
 *   - multi-chain routing (chain id 1 vs 11155111)
 *   - routing-table refresh on epoch advance
 *   - input validation (malformed BC, wrong list_key length, negative
 *     leaf_idx, overflow leaf_idx)
 *   - typed RavenError taxonomy (Network, ServerError, StaleAdapter,
 *     InvalidQuery, BatchMismatch, DecodeError)
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  ChainRegistry,
  ImtCache,
  RavenError,
  RavenPOINodeInterface,
  pathIndicesForLeaf,
  pathIndicesForPerListLeaf,
  validateBcHex,
  validateLeafIndex,
  validateListKeyHex,
  validateTreeNumber,
  TREE_DEPTH,
  type ClientPirContext,
  type RavenInspireWasm,
  type POIStatus,
  type BlindedCommitmentType,
} from "../src/index";

import { startMockServer, writeJson, type MockServer } from "./helpers/mock_server";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "abababababababababababababababababababababababababababababababab";
const BC_HEX = "0000000000000000000000000000000000000000000000000000000000000001";
const BC_HEX_2 = "0000000000000000000000000000000000000000000000000000000000000002";

/**
 * Stub WASM whose path-indices accessors mirror the real Rust math
 * (so tests assert on real geometry, not fabricated values). We do
 * NOT load the real wasm here to keep these tests deterministic and
 * fast (the real wasm is exercised by the privacy-invariant test
 * file).
 */
function realPathStubWasm(): RavenInspireWasm {
  function flatIndex(level: number, idxAtLevel: number): number {
    const total = 1 << (TREE_DEPTH + 1);
    const levelOffset = total - (1 << (TREE_DEPTH + 1 - level));
    return levelOffset + idxAtLevel;
  }
  return {
    build_client_session: () => ({ free: () => undefined }),
    build_seeded_query: () => new Uint8Array(16),
    extract_response: (_session, _crs, _state, response, _entry) => {
      // Pass-through: the test routes encode the desired plaintext
      // (status byte at offset 0 OR a 32 B node hash) directly into
      // the response body; the stub mirrors that into the SDK so
      // routing-matrix tests assert on the plaintext semantics.
      if (response.length === 0) return new Uint8Array(0);
      return new Uint8Array(response);
    },
    build_instance_params_blob: () => new Uint8Array(0),
    register_client_session: undefined,
    path_indices_for_leaf: (_tree: number, leafIdx: number): Uint32Array => {
      const out = new Uint32Array(TREE_DEPTH);
      let walk = leafIdx;
      for (let i = 0; i < TREE_DEPTH; i += 1) {
        out[i] = flatIndex(i, walk ^ 1);
        walk = walk >>> 1;
      }
      return out;
    },
    path_indices_for_per_list_leaf: (listKey: Uint8Array, idx: number): Uint32Array => {
      if (listKey.length !== 32) {
        throw new Error("path_indices_for_per_list_leaf: list_key length must be 32");
      }
      const out = new Uint32Array(TREE_DEPTH);
      let walk = idx;
      for (let i = 0; i < TREE_DEPTH; i += 1) {
        out[i] = flatIndex(i, walk ^ 1);
        walk = walk >>> 1;
      }
      return out;
    },
  };
}

function stubCtx(): ClientPirContext {
  const wasm = realPathStubWasm();
  return {
    wasm,
    session: { free: () => undefined },
    crsBincode: new Uint8Array(0),
    shardConfigBincode: new Uint8Array(0),
    entrySize: 32,
  };
}

/**
 * Mount a `/v1/instance/:id/batch` route that returns 16 synthetic
 * 32 B node hashes (one per element). Each hash is derived from the
 * level so the SDK's reconstruction logic surfaces a deterministic
 * MerkleProof.
 */
function mountBatchRoute(server: MockServer, freshness?: { epoch?: number; schemaVersion?: number }): void {
  server.route(
    (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
    (_req, _body, res) => {
      const elemCount = 16;
      const elemBytes = 32;
      const total = 2 + 8 + elemCount * (8 + elemBytes);
      const out = new Uint8Array(total);
      out[0] = 0;
      out[1] = 1;
      const dv = new DataView(out.buffer);
      dv.setUint32(2, elemCount, true);
      dv.setUint32(6, 0, true);
      let off = 10;
      for (let level = 0; level < elemCount; level += 1) {
        dv.setUint32(off, elemBytes, true);
        dv.setUint32(off + 4, 0, true);
        off += 8;
        // Synthetic 32 B node hash: 0xab in slot 0, level in slot 31.
        out[off] = 0xab;
        out[off + 31] = level;
        off += elemBytes;
      }
      const headers: Record<string, string> = {
        "content-type": "application/octet-stream",
      };
      if (freshness?.epoch !== undefined) {
        headers["x-raven-epoch"] = String(freshness.epoch);
      }
      if (freshness?.schemaVersion !== undefined) {
        headers["x-raven-schema-version"] = String(freshness.schemaVersion);
      }
      res.writeHead(200, headers);
      res.end(Buffer.from(out));
      return true;
    },
  );
}

function mountSingleQueryRoute(server: MockServer, statusByte: number): void {
  server.route(
    (req) => /^\/v1\/instance\/[^/]+\/query$/.test(req.url ?? ""),
    (_req, _body, res) => {
      // SDK now strips the `[u16 BE schema][bincode]` envelope from
      // single-query responses (mirroring the server's
      // `write_versioned`); mock servers must prepend it too. Inner
      // 32 bytes are the stub plaintext the SDK's stub
      // `extract_response` (in `realPathStubWasm`) passes through.
      const inner = new Uint8Array(32);
      inner[0] = statusByte;
      const out = new Uint8Array(2 + inner.length);
      out[0] = 0;
      out[1] = 1;
      out.set(inner, 2);
      res.writeHead(200, {
        "content-type": "application/octet-stream",
        "x-raven-freshness": "lag_blocks=1 applied_height=10 epoch=1 confidence=0.99",
      });
      res.end(Buffer.from(out));
      return true;
    },
  );
}

describe("WASM path-indices accessors", () => {
  const wasm = realPathStubWasm();

  it("path_indices_for_leaf returns a Uint32Array of length 16", () => {
    const out = wasm.path_indices_for_leaf(0, 0);
    expect(out).toBeInstanceOf(Uint32Array);
    expect(out.length).toBe(16);
  });

  it("path_indices_for_leaf is deterministic across calls", () => {
    const a = wasm.path_indices_for_leaf(0, 1234);
    const b = wasm.path_indices_for_leaf(0, 1234);
    expect(Array.from(a)).toEqual(Array.from(b));
  });

  it("path_indices_for_leaf level-0 sibling matches XOR-1 leaf layout", () => {
    const out = wasm.path_indices_for_leaf(0, 0);
    expect(out[0]).toBe(1);
    const out2 = wasm.path_indices_for_leaf(0, 100);
    expect(out2[0]).toBe(101);
    const out3 = wasm.path_indices_for_leaf(0, 65_535);
    expect(out3[0]).toBe(65_534);
  });

  it("path_indices_for_per_list_leaf and path_indices_for_leaf agree byte-for-byte at the same idx", () => {
    const tree = wasm.path_indices_for_leaf(0, 4242);
    const listKey = new Uint8Array(32).fill(0xab);
    const list = wasm.path_indices_for_per_list_leaf(listKey, 4242);
    expect(Array.from(tree)).toEqual(Array.from(list));
  });

  it("pathIndicesForLeaf wrapper returns plain number[]", () => {
    const out = pathIndicesForLeaf(wasm, 0, 7);
    expect(Array.isArray(out)).toBe(true);
    expect(out.length).toBe(16);
    expect(typeof out[0]).toBe("number");
  });

  it("pathIndicesForLeaf rejects out-of-range leaf via typed InvalidQuery", () => {
    expect(() => pathIndicesForLeaf(wasm, 0, 1 << 16)).toThrow(RavenError);
    try {
      pathIndicesForLeaf(wasm, 0, 1 << 16);
    } catch (e) {
      expect(RavenError.is(e, "InvalidQuery")).toBe(true);
    }
  });

  it("pathIndicesForPerListLeaf rejects malformed list_key via typed InvalidQuery", () => {
    expect(() => pathIndicesForPerListLeaf(wasm, "ab", 0)).toThrow(RavenError);
    try {
      pathIndicesForPerListLeaf(wasm, "ab", 0);
    } catch (e) {
      expect(RavenError.is(e, "InvalidQuery")).toBe(true);
    }
  });
});

describe("client-PIR auth-path reconstruction (T2/T3)", () => {
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

  it("getMerkleProof issues exactly one batch POST per call", async () => {
    mountBatchRoute(server);
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([["t3CommitTree:0", stubCtx()]]),
    });
    const proof = await sdk.getMerkleProof(0, 1234);
    expect(proof.elements).toHaveLength(16);
    const wires = sdk.lastWireRequests();
    expect(wires.length).toBe(1);
    expect(wires[0].url).toContain("/v1/instance/commit-tree-0/batch");
  });

  it("getMerkleProof never sends the leaf index in plaintext (raw or ASCII)", async () => {
    mountBatchRoute(server);
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([["t3CommitTree:0", stubCtx()]]),
    });
    await sdk.getMerkleProof(0, 12345);
    const ascii = new TextEncoder().encode("12345");
    const raw = new Uint8Array([0x39, 0x30, 0, 0]); // 12345 LE u32
    for (const w of sdk.lastWireRequests()) {
      // ASCII or LE-u32 leaf-index must not appear in any body.
      expect(containsExact(w.body, ascii)).toBe(false);
      expect(containsExact(w.body, raw)).toBe(false);
    }
  });

  it("getPOIMerkleProofs uses per-list-node path indices + batch route", async () => {
    mountBatchRoute(server);
    const bcMap = new Map<string, number>([[BC_HEX, 7]]);
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t2Path:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, bcMap]]),
    });
    const proofs = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);
    expect(proofs).toHaveLength(1);
    expect(proofs[0].elements).toHaveLength(16);
  });

  it("BatchMismatch surfaces as a typed error when server returns wrong count", async () => {
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, _body, res) => {
        // Only 8 elements; SDK expected 16.
        const elemCount = 8;
        const elemBytes = 32;
        const total = 2 + 8 + elemCount * (8 + elemBytes);
        const out = new Uint8Array(total);
        out[0] = 0;
        out[1] = 1;
        const dv = new DataView(out.buffer);
        dv.setUint32(2, elemCount, true);
        dv.setUint32(6, 0, true);
        let off = 10;
        for (let i = 0; i < elemCount; i += 1) {
          dv.setUint32(off, elemBytes, true);
          dv.setUint32(off + 4, 0, true);
          off += 8 + elemBytes;
        }
        res.writeHead(200, { "content-type": "application/octet-stream" });
        res.end(Buffer.from(out));
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([["t3CommitTree:0", stubCtx()]]),
    });
    try {
      await sdk.getMerkleProof(0, 0);
      expect.fail("expected BatchMismatch");
    } catch (e) {
      expect(RavenError.is(e, "BatchMismatch")).toBe(true);
    }
  });

  it("StaleAdapter surfaces on 400 + X-Raven-Schema-Version response", async () => {
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, _body, res) => {
        res.writeHead(400, { "x-raven-schema-version": "2" });
        res.end();
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([["t3CommitTree:0", stubCtx()]]),
    });
    try {
      await sdk.getMerkleProof(0, 0);
      expect.fail("expected StaleAdapter");
    } catch (e) {
      expect(RavenError.is(e, "StaleAdapter")).toBe(true);
      if (RavenError.is(e, "StaleAdapter")) {
        expect(e.context.serverWireSchemaVersion).toBe(2);
      }
    }
  });

  it("ServerError surfaces on 5xx batch response", async () => {
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, _body, res) => {
        res.writeHead(503);
        res.end();
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([["t3CommitTree:0", stubCtx()]]),
    });
    try {
      await sdk.getMerkleProof(0, 0);
      expect.fail("expected ServerError");
    } catch (e) {
      expect(RavenError.is(e, "ServerError")).toBe(true);
      if (RavenError.is(e, "ServerError")) {
        expect(e.context.status).toBe(503);
      }
    }
  });

  it("Network error surfaces as RavenError.Network when fetch throws", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: "http://127.0.0.1:1", // refused
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([["t3CommitTree:0", stubCtx()]]),
    });
    try {
      await sdk.getMerkleProof(0, 0);
      expect.fail("expected Network error");
    } catch (e) {
      expect(RavenError.is(e, "Network")).toBe(true);
    }
  });
});

describe("client-side IMT cache hit / miss", () => {
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

  it("cache miss issues a batch; cache hit short-circuits", async () => {
    let batchHits = 0;
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, _body, res) => {
        batchHits += 1;
        const elemCount = 16;
        const elemBytes = 32;
        const total = 2 + 8 + elemCount * (8 + elemBytes);
        const out = new Uint8Array(total);
        out[1] = 1;
        const dv = new DataView(out.buffer);
        dv.setUint32(2, elemCount, true);
        let off = 10;
        for (let i = 0; i < elemCount; i += 1) {
          dv.setUint32(off, elemBytes, true);
          off += 8 + elemBytes;
        }
        res.writeHead(200, { "content-type": "application/octet-stream" });
        res.end(Buffer.from(out));
        return true;
      },
    );
    const cache = new ImtCache({ disableIndexedDb: true });
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([["t3CommitTree:0", stubCtx()]]),
      imtCache: cache,
    });
    await sdk.getMerkleProof(0, 0);
    expect(batchHits).toBe(1);
    // Same leaf -> all 16 sibling indices are in cache.
    await sdk.getMerkleProof(0, 0);
    expect(batchHits).toBe(1);
  });

  it("cache invalidates on epoch advance + schema-version bump", async () => {
    let batchHits = 0;
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, _body, res) => {
        batchHits += 1;
        const elemCount = 16;
        const elemBytes = 32;
        const total = 2 + 8 + elemCount * (8 + elemBytes);
        const out = new Uint8Array(total);
        out[1] = 1;
        const dv = new DataView(out.buffer);
        dv.setUint32(2, elemCount, true);
        let off = 10;
        for (let i = 0; i < elemCount; i += 1) {
          dv.setUint32(off, elemBytes, true);
          off += 8 + elemBytes;
        }
        res.writeHead(200, { "content-type": "application/octet-stream" });
        res.end(Buffer.from(out));
        return true;
      },
    );
    const cache = new ImtCache({ disableIndexedDb: true });
    cache.noteFreshness("1", 1);
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([["t3CommitTree:0", stubCtx()]]),
      imtCache: cache,
    });
    await sdk.getMerkleProof(0, 0);
    expect(batchHits).toBe(1);
    // Same epoch + schema version -> all 16 nodes hit in cache.
    await sdk.getMerkleProof(0, 0);
    expect(batchHits).toBe(1);
    // Operator advances epoch (e.g. via /v1/status refresh from
    // a separate routing-table tick); cache layers drop -> next call
    // refetches.
    cache.noteFreshness("2", 1);
    await sdk.getMerkleProof(0, 0);
    expect(batchHits).toBe(2);
    // Schema-version bump alone also clears.
    cache.noteFreshness("2", 2);
    await sdk.getMerkleProof(0, 0);
    expect(batchHits).toBe(3);
  });
});

describe("multi-chain routing", () => {
  let mainnetServer: MockServer;
  let sepoliaServer: MockServer;

  beforeAll(async () => {
    mainnetServer = await startMockServer();
    sepoliaServer = await startMockServer();
    mountBatchRoute(mainnetServer);
    mountBatchRoute(sepoliaServer);
  });
  afterAll(async () => {
    await mainnetServer.close();
    await sepoliaServer.close();
  });

  it("ChainRegistry routes per-chain to distinct adapter URLs", async () => {
    const registry = new ChainRegistry([
      { chainId: 1, endpoint: mainnetServer.url, bearerToken: TOKEN },
      { chainId: 11_155_111, endpoint: sepoliaServer.url, bearerToken: TOKEN },
    ]);
    const sdkMainnet = new RavenPOINodeInterface({
      endpoint: "ignored",
      bearerToken: TOKEN,
      chainId: 1,
      chainRegistry: registry,
      useClientPir: true,
      clientPirContexts: new Map([["t3CommitTree:1:0", stubCtx()]]),
    });
    const sdkSepolia = new RavenPOINodeInterface({
      endpoint: "ignored",
      bearerToken: TOKEN,
      chainId: 11_155_111,
      chainRegistry: registry,
      useClientPir: true,
      clientPirContexts: new Map([["t3CommitTree:11155111:0", stubCtx()]]),
    });
    await sdkMainnet.getMerkleProof(0, 0);
    await sdkSepolia.getMerkleProof(0, 0);
    const mainnetUrls = sdkMainnet.lastWireRequests().map((w) => w.url);
    const sepoliaUrls = sdkSepolia.lastWireRequests().map((w) => w.url);
    expect(mainnetUrls.every((u) => u.startsWith(mainnetServer.url))).toBe(true);
    expect(sepoliaUrls.every((u) => u.startsWith(sepoliaServer.url))).toBe(true);
  });

  it("ChainRegistry rejects unknown chain id with InvalidQuery", () => {
    const registry = new ChainRegistry([
      { chainId: 1, endpoint: mainnetServer.url, bearerToken: TOKEN },
    ]);
    expect(() => registry.resolve(999)).toThrow(RavenError);
    try {
      registry.resolve(999);
    } catch (e) {
      expect(RavenError.is(e, "InvalidQuery")).toBe(true);
    }
  });

  it("ChainRegistry.refresh() updates epoch + schema_version from /v1/status", async () => {
    const localServer = await startMockServer();
    localServer.route(
      (req) => req.url === "/v1/status",
      (_req, _body, res) => {
        writeJson(res, { epoch: 42, wire_schema_version: 1 });
        return true;
      },
    );
    const registry = new ChainRegistry([
      { chainId: 1, endpoint: localServer.url, bearerToken: TOKEN },
    ]);
    const refreshed = await registry.refresh(1);
    expect(refreshed.epoch).toBe(42);
    expect(refreshed.schemaVersion).toBe(1);
    await localServer.close();
  });

  it("ChainRegistry.refresh() throws ServerError on non-200", async () => {
    const localServer = await startMockServer();
    localServer.route(
      (req) => req.url === "/v1/status",
      (_req, _body, res) => {
        res.writeHead(500);
        res.end();
        return true;
      },
    );
    const registry = new ChainRegistry([
      { chainId: 1, endpoint: localServer.url, bearerToken: TOKEN },
    ]);
    try {
      await registry.refresh(1);
      expect.fail("expected ServerError");
    } catch (e) {
      expect(RavenError.is(e, "ServerError")).toBe(true);
    }
    await localServer.close();
  });
});

describe("input validation hardening", () => {
  it("validateBcHex rejects malformed hex (wrong length)", () => {
    expect(() => validateBcHex("ab")).toThrow(RavenError);
    expect(() => validateBcHex("a".repeat(63))).toThrow(RavenError);
  });

  it("validateBcHex rejects non-hex characters", () => {
    expect(() => validateBcHex("z".repeat(64))).toThrow(RavenError);
  });

  it("validateBcHex accepts 0x-prefixed 64-char hex", () => {
    expect(() => validateBcHex(`0x${"a".repeat(64)}`)).not.toThrow();
  });

  it("validateListKeyHex rejects wrong length", () => {
    expect(() => validateListKeyHex("ab")).toThrow(RavenError);
    expect(() => validateListKeyHex("a".repeat(63))).toThrow(RavenError);
  });

  it("validateLeafIndex rejects negative", () => {
    expect(() => validateLeafIndex(-1)).toThrow(RavenError);
  });

  it("validateLeafIndex rejects overflow", () => {
    expect(() => validateLeafIndex(1 << 16)).toThrow(RavenError);
  });

  it("validateLeafIndex rejects non-integer", () => {
    expect(() => validateLeafIndex(1.5)).toThrow(RavenError);
  });

  it("validateTreeNumber rejects negative", () => {
    expect(() => validateTreeNumber(-1)).toThrow(RavenError);
  });

  it("validateTreeNumber rejects > u32", () => {
    expect(() => validateTreeNumber(0x1_0000_0000)).toThrow(RavenError);
  });

  it("getMerkleProof rejects malformed leaf index (negative) pre-flight", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: "http://localhost:1",
      bearerToken: TOKEN,
      useClientPir: true,
    });
    try {
      await sdk.getMerkleProof(0, -1);
      expect.fail("expected InvalidQuery");
    } catch (e) {
      expect(RavenError.is(e, "InvalidQuery")).toBe(true);
    }
  });

  it("getMerkleProof rejects overflow leaf_idx pre-flight", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: "http://localhost:1",
      bearerToken: TOKEN,
      useClientPir: true,
    });
    try {
      await sdk.getMerkleProof(0, 1 << 16);
      expect.fail("expected InvalidQuery");
    } catch (e) {
      expect(RavenError.is(e, "InvalidQuery")).toBe(true);
    }
  });

  it("getPOIsPerList rejects malformed BC hex pre-flight", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: "http://localhost:1",
      bearerToken: TOKEN,
      useClientPir: true,
    });
    try {
      await sdk.getPOIsPerList(
        [LIST_KEY_HEX],
        [{ blindedCommitment: "ab", type: "Shield" }],
      );
      expect.fail("expected InvalidQuery");
    } catch (e) {
      expect(RavenError.is(e, "InvalidQuery")).toBe(true);
    }
  });

  it("getPOIsPerList rejects wrong-length list_key pre-flight", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: "http://localhost:1",
      bearerToken: TOKEN,
      useClientPir: true,
    });
    try {
      await sdk.getPOIsPerList(
        ["ab"],
        [{ blindedCommitment: BC_HEX, type: "Shield" }],
      );
      expect.fail("expected InvalidQuery");
    } catch (e) {
      expect(RavenError.is(e, "InvalidQuery")).toBe(true);
    }
  });
});

describe("status-routing matrix (BC type x POI status)", () => {
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

  // Status byte mapping mirrors `statusByteToPOIStatus`:
  //   0 -> Valid, 1 -> ShieldBlocked, 2 -> ProofSubmitted, 3 -> Missing.
  type Case = { type: BlindedCommitmentType; statusByte: number; expected: POIStatus };
  const matrix: Case[] = [
    { type: "Shield", statusByte: 0, expected: "Valid" },
    { type: "Shield", statusByte: 1, expected: "ShieldBlocked" },
    { type: "Shield", statusByte: 2, expected: "ProofSubmitted" },
    { type: "Shield", statusByte: 3, expected: "Missing" },
    { type: "Transact", statusByte: 0, expected: "Valid" },
    { type: "Transact", statusByte: 1, expected: "ShieldBlocked" },
    { type: "Transact", statusByte: 2, expected: "ProofSubmitted" },
    { type: "Transact", statusByte: 3, expected: "Missing" },
    { type: "Unshield", statusByte: 0, expected: "Valid" },
    { type: "Unshield", statusByte: 3, expected: "Missing" },
  ];
  for (const c of matrix) {
    it(`${c.type} x ${c.expected} round-trips through client-PIR`, async () => {
      mountSingleQueryRoute(server, c.statusByte);
      const sdk = new RavenPOINodeInterface({
        endpoint: server.url,
        bearerToken: TOKEN,
        useClientPir: true,
        clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, stubCtx()]]),
        bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[BC_HEX, 0]])]]),
      });
      const got = await sdk.getPOIsPerList(
        [LIST_KEY_HEX],
        [{ blindedCommitment: BC_HEX, type: c.type }],
      );
      expect(got[BC_HEX][LIST_KEY_HEX]).toBe(c.expected);
    });
  }

  // Nullified status: surfaced via the "Valid" / "Missing" axis;
  // ProofSubmitted is the upstream surrogate for the
  // "spend-known-but-not-yet-finalized" state. Locks the two cases
  // the wallet treats as "spendable" vs "wait/refresh".
  it("Nullified x Valid: status byte 0 surfaces as Valid", async () => {
    mountSingleQueryRoute(server, 0);
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[BC_HEX, 0]])]]),
    });
    const got = await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_HEX, type: "Transact" }],
    );
    expect(got[BC_HEX][LIST_KEY_HEX]).toBe("Valid");
  });

  it("Nullified x Missing: server 5xx propagates as ServerError under H3 (no silent Missing)", async () => {
    // Post-H3 contract: a server-side 503 propagates as a typed
    // ServerError so the wallet can retry against a fresh routing
    // table or fall back to upstream PPOI rather than silently
    // spending against an unmarked BC.
    server.route(
      (req) => req.url?.startsWith("/v1/instance/") ?? false,
      (_req, _body, res) => {
        res.writeHead(503);
        res.end();
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[BC_HEX, 0]])]]),
    });
    try {
      await sdk.getPOIsPerList(
        [LIST_KEY_HEX],
        [{ blindedCommitment: BC_HEX, type: "Transact" }],
      );
      expect.fail("expected ServerError");
    } catch (e) {
      expect(RavenError.is(e, "ServerError")).toBe(true);
    }
  });

  it("Cross-tree spend: leaf in tree N, spend in tree M each route to distinct instances", async () => {
    mountBatchRoute(server);
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([
        ["t3CommitTree:0", stubCtx()],
        ["t3CommitTree:2", stubCtx()],
      ]),
    });
    await sdk.getMerkleProof(0, 100);
    await sdk.getMerkleProof(2, 5_000);
    const wires = sdk.lastWireRequests();
    const urls = wires.map((w) => w.url);
    expect(urls.some((u) => u.includes("/v1/instance/commit-tree-0/batch"))).toBe(true);
    expect(urls.some((u) => u.includes("/v1/instance/commit-tree-2/batch"))).toBe(true);
  });
});

describe("typed RavenError taxonomy", () => {
  it("RavenError.is narrows the kind", () => {
    const err = RavenError.network("boom");
    expect(RavenError.is(err, "Network")).toBe(true);
    expect(RavenError.is(err, "ServerError")).toBe(false);
  });

  it("RavenError.is is false for non-RavenError values", () => {
    expect(RavenError.is(new Error("plain"), "Network")).toBe(false);
    expect(RavenError.is("string", "Network")).toBe(false);
    expect(RavenError.is(null, "Network")).toBe(false);
  });

  it("RavenError carries url + status + schema-version context", () => {
    const err = RavenError.staleAdapter("schema mismatch", {
      url: "http://x/y",
      status: 400,
      serverWireSchemaVersion: 2,
      clientWireSchemaVersion: 1,
    });
    expect(err.context.url).toBe("http://x/y");
    expect(err.context.status).toBe(400);
    expect(err.context.serverWireSchemaVersion).toBe(2);
    expect(err.context.clientWireSchemaVersion).toBe(1);
  });

  it("RavenError extends Error so legacy try/catch consumers see a message", () => {
    const err = RavenError.serverError("boom", { status: 503 });
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toBe("boom");
    expect(err.name).toBe("RavenError");
  });
});

describe("freshness fallback to upstream PPOI", () => {
  let mainServer: MockServer;
  let upstreamServer: MockServer;
  beforeAll(async () => {
    mainServer = await startMockServer();
    upstreamServer = await startMockServer();
  });
  afterAll(async () => {
    await mainServer.close();
    await upstreamServer.close();
  });
  afterEach(() => {
    mainServer.reset();
    upstreamServer.reset();
  });

  it("legacy mode falls back to upstream when confidence < 0.5", async () => {
    mainServer.route(
      (req) => req.url === "/v1/poi/pois-per-list",
      (_req, _body, res) => {
        // Stale: confidence 0.1 below floor 0.5 -> fallback fires.
        writeJson(
          res,
          { [BC_HEX]: { [LIST_KEY_HEX]: "ProofSubmitted" } },
          { "x-raven-freshness": "lag_blocks=999 applied_height=10 epoch=1 confidence=0.1" },
        );
        return true;
      },
    );
    let upstreamHit = false;
    // Upstream path: /pois-per-list/<chainType>/<chainID>
    upstreamServer.route(
      (req) => req.url === "/pois-per-list/0/1",
      (_req, _body, res) => {
        upstreamHit = true;
        writeJson(res, { [BC_HEX]: { [LIST_KEY_HEX]: "Valid" } });
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      endpoint: mainServer.url,
      bearerToken: TOKEN,
      upstreamFallbackEndpoint: upstreamServer.url,
      useClientPir: false,
    });
    const got = await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [{ blindedCommitment: BC_HEX, type: "Shield" }],
    );
    expect(upstreamHit).toBe(true);
    expect(got[BC_HEX][LIST_KEY_HEX]).toBe("Valid");
  });
});

/**
 * Substring-search that does NOT short-circuit on prefix overlap.
 * The exported `containsByteSequence` is what we'd ideally call but
 * we keep this self-contained so failures here don't depend on
 * the helper layer.
 */
function containsExact(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length === 0) return true;
  if (needle.length > haystack.length) return false;
  outer: for (let i = 0; i <= haystack.length - needle.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}
