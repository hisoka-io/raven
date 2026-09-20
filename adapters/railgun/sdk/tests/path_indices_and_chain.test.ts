// Locks the privacy invariant: path indices are computed locally and only the
// encrypted batch crosses the wire, never a plaintext leaf-index or BC.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  ChainRegistry,
  ImtCache,
  RavenError,
  RavenPOINodeInterface,
  hexToBytes,
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
  type RavenErrorKind,
} from "../src/index";
import {
  PATH10_ROW_BYTES,
  mountPath10Route,
  path10Root,
  path10Siblings,
} from "./helpers/path10_row";
import { EXPECTED_WIRE_SCHEMA_VERSION } from "./helpers/wire_schema";
import { makeRegisterSpy, stubRemoteSessionExports } from "./helpers/register_spy";

import * as wasmPkg from "raven-inspire-client-wasm";

import {
  startMockServer,
  writeJson,
  writeJsonRpcResult,
  type MockServer,
} from "./helpers/mock_server";
import { encodeBatchResponse, encodeBatchResponseNodes } from "./helpers/auth_path_stub";
import { authPathOf, encodedBatchCount } from "./helpers/auth_path_stub";
import { foldMerkleRoot } from "../src/poseidon";

const TOKEN = "test-token-padded-long-enough-1234";
const MOCK_EPOCH = 1;
const MOCK_SCHEMA_VERSION = EXPECTED_WIRE_SCHEMA_VERSION;
const LIST_KEY_HEX = "abababababababababababababababababababababababababababababababab";
// Non-zero in its leading bytes so a status row's BC tail cannot match by accident.
const BC_HEX = "9f3c17aa04e1b28d6605c9713fe82b40d1a7c35e96280bf4517ade0c2b6d8391";

// `expect(fn).toThrow(RavenError)` is not expressible: RavenError's constructor is
// private, so the class is not a `Constructable` for vitest's matcher.
function expectThrowsRavenError(fn: () => unknown, kind: RavenErrorKind): void {
  let thrown: unknown;
  let returned = false;
  try {
    fn();
    returned = true;
  } catch (e) {
    thrown = e;
  }
  expect(returned).toBe(false);
  expect(thrown).toBeInstanceOf(RavenError);
  expect(RavenError.is(thrown, kind)).toBe(true);
}

// Stub mirroring the real Rust path-indices math so tests assert on real geometry; the real wasm runs in the privacy-invariant file.
function realPathStubWasm(): RavenInspireWasm {
  function flatIndex(level: number, idxAtLevel: number): number {
    const total = 1 << (TREE_DEPTH + 1);
    const levelOffset = total - (1 << (TREE_DEPTH + 1 - level));
    return levelOffset + idxAtLevel;
  }
  return {
    ...stubRemoteSessionExports(),
    build_client_session: () => ({ free: () => undefined }),
    build_seeded_query: () => new Uint8Array(16),
    extract_response: (_session, _crs, _state, response, _entry) => {
      // Pass-through: test routes encode the desired plaintext directly into the response body.
      if (response.length === 0) return new Uint8Array(0);
      return new Uint8Array(response);
    },
    build_instance_params_blob: () => new Uint8Array(0),
    register_client_session: makeRegisterSpy(),
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

// Mount a batch route returning 16 synthetic 32 B node hashes, each derived from its level for a deterministic MerkleProof.
function mountBatchRoute(server: MockServer, freshness?: { epoch?: number; schemaVersion?: number }): void {
  server.route(
    (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
    (_req, _body, res) => {
      // 16 synthetic nodes: 0xab marker at byte 0, level at byte 31 — the shared
      // encoder's (epoch, slot) convention, so the shape has ONE writer.
      const out = encodeBatchResponse(0xab, 16);
      // `build_response_headers` stamps both on every batch reply, so the mock always does too.
      const headers: Record<string, string> = {
        "content-type": "application/octet-stream",
        "x-raven-epoch": String(freshness?.epoch ?? MOCK_EPOCH),
        "x-raven-schema-version": String(freshness?.schemaVersion ?? MOCK_SCHEMA_VERSION),
        "x-raven-freshness": "lag_blocks=0 applied_height=0 epoch=1 confidence=1",
      };
      res.writeHead(200, headers);
      res.end(Buffer.from(out));
      return true;
    },
  );
}

/** Batch route echoing exactly as many 32 B node hashes as the request asked for. */
function mountEchoingBatchRoute(
  server: MockServer,
  onHit?: () => void,
  freshness?: () => { epoch: number; schemaVersion: number },
): void {
  server.route(
    (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
    (_req, body, res) => {
      onHit?.();
      const slots = encodedBatchCount(body);
      const elemBytes = 32;
      const out = new Uint8Array(2 + 8 + slots * (8 + elemBytes));
      out[1] = 7;
      const dv = new DataView(out.buffer);
      dv.setUint32(2, slots, true);
      let off = 10;
      for (let slot = 0; slot < slots; slot += 1) {
        dv.setUint32(off, elemBytes, true);
        off += 8;
        out[off] = 0xab;
        out[off + elemBytes - 1] = slot;
        off += elemBytes;
      }
      const tags = freshness?.() ?? { epoch: MOCK_EPOCH, schemaVersion: MOCK_SCHEMA_VERSION };
      res.writeHead(200, {
        "content-type": "application/octet-stream",
        "x-raven-epoch": String(tags.epoch),
        "x-raven-schema-version": String(tags.schemaVersion),
        "x-raven-freshness": "lag_blocks=0 applied_height=0 epoch=1 confidence=1",
      });
      res.end(Buffer.from(out));
      return true;
    },
  );
}

function mountSingleQueryRoute(server: MockServer, statusByte: number): void {
  server.route(
    (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
    (_req, body, res) => {
      const inner = new Uint8Array(32);
      inner[0] = statusByte;
      inner.set(hexToBytes(BC_HEX).subarray(0, 31), 1);
      const out = encodeBatchResponseNodes(
        Array.from({ length: encodedBatchCount(body) }, () => inner),
      );
      res.writeHead(200, {
        "content-type": "application/octet-stream",
        "x-raven-freshness": "lag_blocks=1 applied_height=10 epoch=1 confidence=0.99",
      });
      res.end(Buffer.from(out));
      return true;
    },
  );
}

// These four ran against `realPathStubWasm()` -- the stub defined in this file -- so they
// asserted the test's own arithmetic and no change to the shipped wasm could fail them.
// They drive the real package now, which also makes them the check that the stub every other
// test in this file relies on actually mirrors the Rust geometry.
describe("WASM path-indices accessors", () => {
  const wasm = wasmPkg as unknown as RavenInspireWasm;
  const stub = realPathStubWasm();

  it("path_indices_for_leaf returns a Uint32Array of length 16", () => {
    const out = wasm.path_indices_for_leaf(0, 0);
    expect(out).toBeInstanceOf(Uint32Array);
    expect(out.length).toBe(TREE_DEPTH);
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

  // Everything else in this file reads batch slot counts and cache hit/miss through the stub,
  // so a stub that drifted from the shipped geometry would make those conclusions wrong.
  it("the in-file stub reproduces the real wasm path indices at every level", () => {
    const listKey = new Uint8Array(32).fill(0xab);
    for (const leaf of [0, 1, 7, 1234, 1234 ^ 0b111, 4096, 65_535]) {
      expect(
        Array.from(stub.path_indices_for_leaf(0, leaf)),
        `tree path for leaf ${leaf}`,
      ).toEqual(Array.from(wasm.path_indices_for_leaf(0, leaf)));
      expect(
        Array.from(stub.path_indices_for_per_list_leaf(listKey, leaf)),
        `per-list path for leaf ${leaf}`,
      ).toEqual(Array.from(wasm.path_indices_for_per_list_leaf(listKey, leaf)));
    }
  });

  it("pathIndicesForLeaf wrapper returns plain number[]", () => {
    const out = pathIndicesForLeaf(wasm, 0, 7);
    expect(Array.isArray(out)).toBe(true);
    expect(out.length).toBe(16);
    expect(typeof out[0]).toBe("number");
  });

  it("pathIndicesForLeaf rejects out-of-range leaf via typed InvalidQuery", () => {
    expectThrowsRavenError(() => pathIndicesForLeaf(wasm, 0, 1 << 16), "InvalidQuery");
    try {
      pathIndicesForLeaf(wasm, 0, 1 << 16);
    } catch (e) {
      expect(RavenError.is(e, "InvalidQuery")).toBe(true);
    }
  });

  it("pathIndicesForPerListLeaf rejects malformed list_key via typed InvalidQuery", () => {
    expectThrowsRavenError(() => pathIndicesForPerListLeaf(wasm, "ab", 0), "InvalidQuery");
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
    const path = authPathOf(await sdk.getMerkleProof(0, 1234));
    expect(path.elements).toHaveLength(16);
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
      expect(containsExact(w.body, ascii)).toBe(false);
      expect(containsExact(w.body, raw)).toBe(false);
    }
  });

  it("getPOIMerkleProofs reads one path-10 row and still yields 16 elements", async () => {
    // The path-10 record: one 512 B row (levels 0..10) plus a 160 B addendum (levels 11..15)
    // replaced sixteen 32 B node reads. The proof the wallet sees is unchanged at 16.
    const nodes = path10Siblings(0xab);
    mountPath10Route(server, {
      bcHex: BC_HEX,
      nodes,
      instance: `t2Path-${LIST_KEY_HEX}`,
      schemaVersion: MOCK_SCHEMA_VERSION,
      epoch: MOCK_EPOCH,
    });
    const bcMap = new Map<string, number>([[BC_HEX, 7]]);
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([
        [`t2Path:${LIST_KEY_HEX}`, { ...stubCtx(), entrySize: PATH10_ROW_BYTES }],
      ]),
      ppoiPinnedRoots: new Map([[`${LIST_KEY_HEX}:0`, path10Root(BC_HEX, nodes, 7)]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, bcMap]]),
    });
    const proofs = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);
    expect(proofs).toHaveLength(1);
    expect(proofs[0].elements).toHaveLength(16);
    expect(sdk.lastWireRequests()).toHaveLength(1);
  });

  it("routes a PPOI index through its configured deployed block instance", async () => {
    server.route(
      (req) => req.url === "/v1/instance/ppoi-paths-ofac-1/batch",
      (_req, _body, res) => {
        const row = new Uint8Array(512);
        row.set(Buffer.from(BC_HEX, "hex"), 0);
        row.set(new TextEncoder().encode("RVP2"), 34);
        for (let level = 0; level < 11; level += 1) row[38 + level * 32] = level + 1;
        const addendum = new Uint8Array(160);
        for (let level = 0; level < 5; level += 1) addendum[level * 32] = level + 12;
        const out = encodeBatchResponseNodes([
          new Uint8Array([...row, ...addendum]),
        ]);
        res.writeHead(200, {
          "content-type": "application/octet-stream",
          "x-raven-epoch": String(MOCK_EPOCH),
          "x-raven-schema-version": String(MOCK_SCHEMA_VERSION),
          "x-raven-freshness": "lag_blocks=0 applied_height=0 epoch=1 confidence=1",
        });
        res.end(Buffer.from(out));
        return true;
      },
    );
    const globalIndex = 65_536 + 7;
    const pathContext = { ...stubCtx(), entrySize: 512 };
    const siblings = Array.from({ length: 16 }, (_unused, level) => {
      const sibling = new Uint8Array(32);
      sibling[0] = level + 1;
      return Buffer.from(sibling).toString("hex");
    });
    const pinnedRoot = foldMerkleRoot(BC_HEX, siblings, 7n);
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t2Path:${LIST_KEY_HEX}`, pathContext]]),
      clientPirInstanceLabels: new Map([
        [`t2Path:${LIST_KEY_HEX}:1`, "ppoi-paths-ofac-1"],
      ]),
      ppoiPinnedRoots: new Map([[`${LIST_KEY_HEX}:1`, pinnedRoot]]),
      bcToIdxMaps: new Map([
        [LIST_KEY_HEX, new Map([[BC_HEX, globalIndex]])],
      ]),
    });

    await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);

    expect(sdk.lastWireRequests()[0].url).toContain(
      "/v1/instance/ppoi-paths-ofac-1/batch",
    );
  });

  it("BatchMismatch surfaces as a typed error when server returns wrong count", async () => {
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, _body, res) => {
        // 8 zero nodes where 16 were requested: the wrong-count reply.
        const out = encodeBatchResponseNodes(
          Array.from({ length: 8 }, () => new Uint8Array(32)),
        );
        res.writeHead(200, {
          "content-type": "application/octet-stream",
          "x-raven-epoch": String(MOCK_EPOCH),
          "x-raven-schema-version": String(MOCK_SCHEMA_VERSION),
        });
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
        expect(e.context.clientWireSchemaVersion).toBe(EXPECTED_WIRE_SCHEMA_VERSION);
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

  it("a cache hit still issues a batch, and serves the same path", async () => {
    let batchHits = 0;
    mountEchoingBatchRoute(server, () => {
      batchHits += 1;
    });
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([["t3CommitTree:0", stubCtx()]]),
      imtCache: new ImtCache({ disableIndexedDb: true }),
    });
    const cold = authPathOf(await sdk.getMerkleProof(0, 0));
    expect(batchHits).toBe(1);
    const warm = authPathOf(await sdk.getMerkleProof(0, 0));
    expect(batchHits).toBe(2);
    expect(warm.elements).toEqual(cold.elements);
  });

  it("a schema-version advance drops the cached levels", async () => {
    let schemaVersion = 6;
    mountEchoingBatchRoute(server, undefined, () => ({
      epoch: MOCK_EPOCH,
      schemaVersion,
    }));
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([["t3CommitTree:0", stubCtx()]]),
      imtCache: new ImtCache({ disableIndexedDb: true }),
    });
    await sdk.getMerkleProof(0, 1234);

    // 1234 ^ 0b111 shares every sibling above level 2, so only 3 levels miss the cache.
    sdk.resetWireCapture();
    await sdk.getMerkleProof(0, 1234 ^ 0b111);
    expect(encodedBatchCount(sdk.lastWireRequests()[0].body)).toBe(4);

    schemaVersion = 7;
    await sdk.getMerkleProof(0, 1234 ^ 0b111);
    sdk.resetWireCapture();
    await sdk.getMerkleProof(0, 1234 ^ 0b111);
    expect(encodedBatchCount(sdk.lastWireRequests()[0].body)).toBe(16);
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
    expectThrowsRavenError(() => registry.resolve(999), "InvalidQuery");
    try {
      registry.resolve(999);
    } catch (e) {
      expect(RavenError.is(e, "InvalidQuery")).toBe(true);
    }
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
    expectThrowsRavenError(() => validateBcHex("ab"), "InvalidQuery");
    expectThrowsRavenError(() => validateBcHex("a".repeat(63)), "InvalidQuery");
  });

  it("validateBcHex rejects non-hex characters", () => {
    expectThrowsRavenError(() => validateBcHex("z".repeat(64)), "InvalidQuery");
  });

  it("validateBcHex accepts 0x-prefixed 64-char hex", () => {
    expect(() => validateBcHex(`0x${"a".repeat(64)}`)).not.toThrow();
  });

  it("validateListKeyHex rejects wrong length", () => {
    expectThrowsRavenError(() => validateListKeyHex("ab"), "InvalidQuery");
    expectThrowsRavenError(() => validateListKeyHex("a".repeat(63)), "InvalidQuery");
  });

  it("validateLeafIndex rejects negative", () => {
    expectThrowsRavenError(() => validateLeafIndex(-1), "InvalidQuery");
  });

  it("validateLeafIndex rejects overflow", () => {
    expectThrowsRavenError(() => validateLeafIndex(1 << 16), "InvalidQuery");
  });

  it("validateLeafIndex rejects non-integer", () => {
    expectThrowsRavenError(() => validateLeafIndex(1.5), "InvalidQuery");
  });

  it("validateTreeNumber rejects negative", () => {
    expectThrowsRavenError(() => validateTreeNumber(-1), "InvalidQuery");
  });

  it("validateTreeNumber rejects > u32", () => {
    expectThrowsRavenError(() => validateTreeNumber(0x1_0000_0000), "InvalidQuery");
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

  // Nullified surfaces on the Valid/Missing axis; locks the spendable vs wait/refresh cases.
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
    // A 503 propagates as a typed ServerError so the wallet retries or falls back rather than spending on an unmarked BC.
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
        // confidence 0.1 below floor 0.5 fires the fallback.
        writeJson(
          res,
          { [BC_HEX]: { [LIST_KEY_HEX]: "ProofSubmitted" } },
          { "x-raven-freshness": "lag_blocks=999 applied_height=10 epoch=1 confidence=0.1" },
        );
        return true;
      },
    );
    let upstreamHit = false;
    upstreamServer.route(
      (req) => req.url === "/",
      (_req, body, res) => {
        upstreamHit = true;
        const request = writeJsonRpcResult(
          body,
          res,
          { [BC_HEX]: { [LIST_KEY_HEX]: "Valid" } },
        );
        expect(request.method).toBe("ppoi_pois_per_list");
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

// Self-contained byte-substring search so failures here do not depend on the helper layer.
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
