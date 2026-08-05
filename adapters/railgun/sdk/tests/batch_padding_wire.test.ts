// The batch a warm cache produces is padded to a ladder step before it leaves
// the SDK, so the wire never publishes the exact cache-miss count. Without the
// padding the second call below sends 3 slots, which the server refuses.

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  RavenPOINodeInterface,
  TREE_DEPTH,
  isOnLadder,
  type ClientPirContext,
  type RavenInspireWasm,
} from "../src/index";

import { startMockServer, type MockServer } from "./helpers/mock_server";

const TOKEN = "test-token-padded-long-enough-1234";

function pathStubWasm(): RavenInspireWasm {
  function flatIndex(level: number, idxAtLevel: number): number {
    const total = 1 << (TREE_DEPTH + 1);
    const levelOffset = total - (1 << (TREE_DEPTH + 1 - level));
    return levelOffset + idxAtLevel;
  }
  return {
    build_client_session: () => ({ free: () => undefined }),
    build_seeded_query: () => new Uint8Array(16),
    extract_response: (_session, _crs, _state, response, _entry) =>
      response.length === 0 ? new Uint8Array(0) : new Uint8Array(response),
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
  return {
    wasm: pathStubWasm(),
    session: { free: () => undefined },
    crsBincode: new Uint8Array(0),
    shardConfigBincode: new Uint8Array(0),
    entrySize: 32,
  };
}

/** Encoded slot count of a `[u16 BE version][u64 LE count][...]` batch body. */
function encodedBatchCount(body: Uint8Array): number {
  const dv = new DataView(body.buffer, body.byteOffset, body.byteLength);
  return dv.getUint32(2, true);
}

/** Batch route echoing exactly as many 32 B node hashes as the request asked for. */
function mountEchoingBatchRoute(server: MockServer): void {
  server.route(
    (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
    (_req, body, res) => {
      const elemCount = encodedBatchCount(body);
      const elemBytes = 32;
      const out = new Uint8Array(2 + 8 + elemCount * (8 + elemBytes));
      out[0] = 0;
      out[1] = 1;
      const dv = new DataView(out.buffer);
      dv.setUint32(2, elemCount, true);
      dv.setUint32(6, 0, true);
      let off = 10;
      for (let slot = 0; slot < elemCount; slot += 1) {
        dv.setUint32(off, elemBytes, true);
        dv.setUint32(off + 4, 0, true);
        off += 8;
        out[off] = 0xab;
        out[off + 31] = slot;
        off += elemBytes;
      }
      res.writeHead(200, { "content-type": "application/octet-stream" });
      res.end(Buffer.from(out));
      return true;
    },
  );
}

describe("batch bodies leaving the SDK are padded to a ladder step", () => {
  let server: MockServer;
  beforeAll(async () => {
    server = await startMockServer();
    mountEchoingBatchRoute(server);
  });
  afterAll(async () => {
    await server.close();
  });

  it("pads a 3-miss warm-cache batch up to 4 slots", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([["t3CommitTree:0", stubCtx()]]),
    });

    await sdk.getMerkleProof(0, 1234);
    const cold = sdk.lastWireRequests();
    expect(cold).toHaveLength(1);
    expect(encodedBatchCount(cold[0].body)).toBe(16);

    // 1234 ^ 0b111 shares every sibling above level 2, so exactly 3 levels miss.
    sdk.resetWireCapture();
    await sdk.getMerkleProof(0, 1234 ^ 0b111);
    const warm = sdk.lastWireRequests();
    expect(warm).toHaveLength(1);
    const sent = encodedBatchCount(warm[0].body);
    expect(isOnLadder(sent)).toBe(true);
    expect(sent).toBe(4);
  });

  it("keeps every batch length on the ladder across a walk of nearby leaves", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([["t3CommitTree:0", stubCtx()]]),
    });
    for (const leaf of [4096, 4097, 4099, 4103, 4111, 4127, 4159, 4223]) {
      sdk.resetWireCapture();
      await sdk.getMerkleProof(0, leaf);
      for (const wire of sdk.lastWireRequests()) {
        const sent = encodedBatchCount(wire.body);
        expect(isOnLadder(sent)).toBe(true);
      }
    }
  });
});
