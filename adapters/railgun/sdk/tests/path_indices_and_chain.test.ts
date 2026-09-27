// Locks the privacy invariant: path indices are computed locally and only the encrypted batch
// crosses the wire, never a plaintext leaf index or BC.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  ChainRegistry,
  RavenError,
  RavenPOINodeInterface,
  pathIndicesForPerListLeaf,
  validateBcHex,
  validateLeafIndex,
  validateListKeyHex,
  TREE_DEPTH,
  type BlindedCommitmentType,
  type ClientPirContext,
  type POIStatus,
  type Proof,
  type RavenInspireWasm,
  type RavenErrorKind,
} from "../src/index";
import { blockLabel, forestConfig } from "./helpers/forest";
import {
  PATH10_ROW_BYTES,
  mountPath10Route,
  path10Root,
  path10Siblings,
} from "./helpers/path10_row";
import { EXPECTED_WIRE_SCHEMA_VERSION } from "./helpers/wire_schema";
import { makeRegisterSpy, stubRemoteSessionExports } from "./helpers/register_spy";
import { stubQueryBundle, targetNamingQueryBundle } from "./helpers/private_wire";
import { commitmentAt, listHolding, mountPrefixChannel } from "./helpers/prefix_channel";

import * as wasmPkg from "raven-inspire-client-wasm";

import { startMockServer, writeJsonRpcResult, type MockServer } from "./helpers/mock_server";
import { encodeBatchResponseNodes } from "./helpers/auth_path_stub";
import { foldMerkleRoot } from "../src/poseidon";
import { shardConfigBincode } from "./helpers/shard_config";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "abababababababababababababababababababababababababababababababab";
const BC_HEX = "9f3c17aa04e1b28d6605c9713fe82b40d1a7c35e96280bf4517ade0c2b6d8391";
const LOCAL_LEAF = 12_345;

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

// Stub mirroring the real Rust path-indices math; the real wasm runs in the privacy-invariant file.
function realPathStubWasm(): RavenInspireWasm {
  function flatIndex(level: number, idxAtLevel: number): number {
    const total = 1 << (TREE_DEPTH + 1);
    const levelOffset = total - (1 << (TREE_DEPTH + 1 - level));
    return levelOffset + idxAtLevel;
  }
  return {
    ...stubRemoteSessionExports(),
    build_client_session: () => ({ free: () => undefined }),
    build_seeded_query: (_session, _shards, target) => targetNamingQueryBundle(target),
    extract_response: (_session, _crs, _state, response, _entry) => new Uint8Array(response),
    build_instance_params_blob: () => new Uint8Array(0),
    register_client_session: makeRegisterSpy(),
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
  return {
    wasm: realPathStubWasm(),
    session: { free: () => undefined },
    crsBincode: new Uint8Array(0),
    shardConfigBincode: shardConfigBincode(),
    entrySize: PATH10_ROW_BYTES,
  };
}

/** Holds BC_HEX at `index`, in the block the index names. */
function pathSdk(endpoint: string, index = LOCAL_LEAF, root?: string): RavenPOINodeInterface {
  const block = Math.floor(index / 65_536);
  return new RavenPOINodeInterface({
    ...forestConfig({
      endpoint,
      listKeyHex: LIST_KEY_HEX,
      ctx: stubCtx(),
      placed: [[BC_HEX, index]],
      pins: new Map([[block, root ?? path10Root(BC_HEX, path10Siblings(0xab), index % 65_536)]]),
    }),
    bearerToken: TOKEN,
  });
}

describe("WASM path-indices accessors", () => {
  const wasm = wasmPkg as unknown as RavenInspireWasm;
  const stub = realPathStubWasm();
  const listKey = new Uint8Array(32).fill(0xab);

  it("path_indices_for_per_list_leaf returns a deterministic Uint32Array of length 16", () => {
    const a = wasm.path_indices_for_per_list_leaf(listKey, 1234);
    const b = wasm.path_indices_for_per_list_leaf(listKey, 1234);
    expect(a).toBeInstanceOf(Uint32Array);
    expect(a.length).toBe(TREE_DEPTH);
    expect(Array.from(a)).toEqual(Array.from(b));
  });

  it("path_indices_for_per_list_leaf level-0 sibling matches XOR-1 leaf layout", () => {
    expect(wasm.path_indices_for_per_list_leaf(listKey, 0)[0]).toBe(1);
    expect(wasm.path_indices_for_per_list_leaf(listKey, 100)[0]).toBe(101);
    expect(wasm.path_indices_for_per_list_leaf(listKey, 65_535)[0]).toBe(65_534);
  });

  it("the in-file stub reproduces the real wasm path indices at every level", () => {
    for (const leaf of [0, 1, 7, 1234, 1234 ^ 0b111, 4096, 65_535]) {
      expect(
        Array.from(stub.path_indices_for_per_list_leaf(listKey, leaf)),
        `per-list path for leaf ${leaf}`,
      ).toEqual(Array.from(wasm.path_indices_for_per_list_leaf(listKey, leaf)));
    }
  });

  it("pathIndicesForPerListLeaf wrapper returns plain number[]", () => {
    const out = pathIndicesForPerListLeaf(wasm, LIST_KEY_HEX, 7);
    expect(Array.isArray(out)).toBe(true);
    expect(out.length).toBe(16);
    expect(typeof out[0]).toBe("number");
  });

  it("pathIndicesForPerListLeaf rejects malformed list_key via typed InvalidQuery", () => {
    expectThrowsRavenError(() => pathIndicesForPerListLeaf(wasm, "ab", 0), "InvalidQuery");
  });

  it("pathIndicesForPerListLeaf rejects an out-of-range leaf via typed InvalidQuery", () => {
    expectThrowsRavenError(() => pathIndicesForPerListLeaf(wasm, LIST_KEY_HEX, 1 << 16), "InvalidQuery");
  });
});

describe("client-PIR auth-path reconstruction", () => {
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

  it("reads one path-10 row per proof, in one batch, and still yields 16 elements", async () => {
    // One 512 B row (levels 0..10) plus a 160 B addendum (levels 11..15); the proof the wallet
    // sees is unchanged at 16.
    mountPath10Route(server, {
      bcHex: BC_HEX,
      nodes: path10Siblings(0xab),
      instance: blockLabel(LIST_KEY_HEX, 0),
      schemaVersion: EXPECTED_WIRE_SCHEMA_VERSION,
    });
    const sdk = pathSdk(server.url);
    const proofs = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);
    expect(proofs).toHaveLength(1);
    expect(proofs[0].elements).toHaveLength(16);
    expect(sdk.lastWireRequests().filter((w) => w.method === "POST")).toHaveLength(1);
  });

  it("never sends the leaf index in plaintext (raw or ASCII)", async () => {
    mountPath10Route(server, {
      bcHex: BC_HEX,
      nodes: path10Siblings(0xab),
      instance: blockLabel(LIST_KEY_HEX, 0),
    });
    // Queries whose bytes do not depend on the target, so only the SDK's own framing is judged.
    const opaque = stubCtx();
    const sdk = new RavenPOINodeInterface({
      ...forestConfig({
        endpoint: server.url,
        listKeyHex: LIST_KEY_HEX,
        ctx: { ...opaque, wasm: { ...opaque.wasm, build_seeded_query: () => stubQueryBundle() } },
        placed: [[BC_HEX, LOCAL_LEAF]],
        pins: new Map([[0, path10Root(BC_HEX, path10Siblings(0xab), LOCAL_LEAF)]]),
      }),
      bearerToken: TOKEN,
    });
    await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);
    const ascii = new TextEncoder().encode(String(LOCAL_LEAF));
    const raw = new Uint8Array([0x39, 0x30, 0, 0]); // 12345 LE u32
    const posted = sdk.lastWireRequests().filter((w) => w.method === "POST");
    expect(posted.length).toBeGreaterThan(0);
    for (const w of posted) {
      expect(containsExact(w.body, ascii)).toBe(false);
      expect(containsExact(w.body, raw)).toBe(false);
    }
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
        res.writeHead(200, {
          "content-type": "application/octet-stream",
          "x-raven-freshness": "lag_blocks=0 applied_height=0 epoch=1 confidence=1",
        });
        res.end(Buffer.from(encodeBatchResponseNodes([new Uint8Array([...row, ...addendum])])));
        return true;
      },
    );
    const globalIndex = 65_536 + 7;
    const siblings = Array.from({ length: 16 }, (_unused, level) => {
      const sibling = new Uint8Array(32);
      sibling[0] = level + 1;
      return Buffer.from(sibling).toString("hex");
    });
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      clientPirContexts: new Map([[`t2Path:1:${LIST_KEY_HEX}`, stubCtx()]]),
      clientPirInstanceLabels: new Map([[`t2Path:1:${LIST_KEY_HEX}:1`, "ppoi-paths-ofac-1"]]),
      ppoiPinnedRoots: new Map([[`1:${LIST_KEY_HEX}:1`, foldMerkleRoot(BC_HEX, siblings, 7n)]]),
      poiListIndexes: new Map([[`1:${LIST_KEY_HEX}`, pathIndexHolding(globalIndex)]]),
      poiListIndexStore: false,
    });

    await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);

    const posted = sdk.lastWireRequests().filter((w) => w.method === "POST");
    expect(posted.map((w) => w.url)).toEqual([
      `${server.url}/v1/instance/ppoi-paths-ofac-1/batch`,
    ]);
  });

  it("BatchMismatch surfaces as a typed error when server returns wrong count", async () => {
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, _body, res) => {
        // Two slots where one was requested: the wrong-count reply.
        res.writeHead(200, {
          "content-type": "application/octet-stream",
          "x-raven-freshness": "lag_blocks=0 applied_height=0 epoch=1 confidence=1",
        });
        res.end(Buffer.from(encodeBatchResponseNodes([new Uint8Array(672), new Uint8Array(672)])));
        return true;
      },
    );
    await expect(pathSdk(server.url).getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX])).rejects.toSatisfy(
      (e: unknown) => RavenError.is(e, "BatchMismatch"),
    );
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
    try {
      await pathSdk(server.url).getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);
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
    try {
      await pathSdk(server.url).getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);
      expect.fail("expected ServerError");
    } catch (e) {
      expect(RavenError.is(e, "ServerError")).toBe(true);
      if (RavenError.is(e, "ServerError")) {
        expect(e.context.status).toBe(503);
      }
    }
  });

  it("Network error surfaces as RavenError.Network when fetch throws", async () => {
    await expect(
      pathSdk("http://127.0.0.1:1").getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]),
    ).rejects.toSatisfy((e: unknown) => RavenError.is(e, "Network"));
  });
});

/** The preloaded index a node publishes with BC_HEX at `index`. */
function pathIndexHolding(index: number) {
  const rows = listHolding([[BC_HEX, index]]);
  const prefixes = new Uint8Array(rows.length * 6);
  rows.forEach((bc, row) => prefixes.set(Buffer.from(bc.slice(0, 12), "hex"), row * 6));
  return { epoch: 0, prefixes, total: rows.length };
}

describe("multi-chain routing", () => {
  let mainnetServer: MockServer;
  let sepoliaServer: MockServer;

  beforeAll(async () => {
    mainnetServer = await startMockServer();
    sepoliaServer = await startMockServer();
    mountPrefixChannel(mainnetServer, LIST_KEY_HEX, { commitments: [BC_HEX] });
    mountPrefixChannel(sepoliaServer, LIST_KEY_HEX, { commitments: [BC_HEX] });
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
      clientPirContexts: new Map([[`t2Path:1:${LIST_KEY_HEX}`, stubCtx()]]),
      poiListIndexStore: false,
    });
    const sdkSepolia = new RavenPOINodeInterface({
      endpoint: "ignored",
      bearerToken: TOKEN,
      chainId: 11_155_111,
      chainRegistry: registry,
      clientPirContexts: new Map([[`t2Path:11155111:${LIST_KEY_HEX}`, stubCtx()]]),
      poiListIndexStore: false,
    });
    const asked = [{ blindedCommitment: BC_HEX, type: "Shield" as const }];
    await sdkMainnet.getPOIsPerList([LIST_KEY_HEX], asked);
    await sdkSepolia.getPOIsPerList([LIST_KEY_HEX], asked);
    const mainnetUrls = sdkMainnet.lastWireRequests().map((w) => w.url);
    const sepoliaUrls = sdkSepolia.lastWireRequests().map((w) => w.url);
    expect(mainnetUrls.length).toBeGreaterThan(0);
    expect(sepoliaUrls.length).toBeGreaterThan(0);
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

  it("getPOIsPerList rejects malformed BC hex pre-flight", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: "http://localhost:1",
      bearerToken: TOKEN,
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

describe("status matrix on the device (BC type x POI status)", () => {
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

  const PROOF: Proof = { pi_a: ["1", "2"], pi_b: [["3", "4"], ["5", "6"]], pi_c: ["7", "8"] };
  const LISTED = commitmentAt(1);
  const SUBMITTED = commitmentAt(2);
  const ABSENT = commitmentAt(3);

  // ShieldBlocked is never answered: nothing on the device says a shield is blocked.
  type Case = { type: BlindedCommitmentType; bc: string; expected: POIStatus };
  const matrix: Case[] = [];
  for (const type of ["Shield", "Transact", "Unshield"] as const) {
    matrix.push({ type, bc: LISTED, expected: "Valid" });
    matrix.push({ type, bc: SUBMITTED, expected: "ProofSubmitted" });
    matrix.push({ type, bc: ABSENT, expected: "Missing" });
  }
  for (const c of matrix) {
    it(`${c.type} x ${c.expected}`, async () => {
      mountPrefixChannel(server, LIST_KEY_HEX, { commitments: [LISTED] });
      server.route(
        (req) => req.url === "/",
        (_req, body, res) => {
          writeJsonRpcResult(body, res, null);
          return true;
        },
      );
      const sdk = new RavenPOINodeInterface({
        ...forestConfig({ endpoint: server.url, listKeyHex: LIST_KEY_HEX, ctx: stubCtx() }),
        bearerToken: TOKEN,
        upstreamFallbackEndpoint: `${server.url}/`,
      });
      await sdk.submitPOI("V2_PoseidonMerkle", { type: 0, id: 1 }, LIST_KEY_HEX, PROOF, [], "00".repeat(32), 0, [SUBMITTED], "0x00");
      const got = await sdk.getPOIsPerList(
        [LIST_KEY_HEX],
        [{ blindedCommitment: c.bc, type: c.type }],
      );
      expect(got[c.bc][LIST_KEY_HEX]).toBe(c.expected);
    });
  }

  it("an index sync that fails with a 5xx propagates as ServerError, never a silent Missing", async () => {
    server.route(
      (req) => (req.url ?? "").includes("/bc-prefixes"),
      (_req, _body, res) => {
        res.writeHead(503);
        res.end();
        return true;
      },
    );
    const sdk = new RavenPOINodeInterface({
      ...forestConfig({ endpoint: server.url, listKeyHex: LIST_KEY_HEX, ctx: stubCtx() }),
      bearerToken: TOKEN,
    });
    await expect(
      sdk.getPOIsPerList([LIST_KEY_HEX], [{ blindedCommitment: BC_HEX, type: "Transact" }]),
    ).rejects.toSatisfy((e: unknown) => RavenError.is(e, "ServerError"));
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
