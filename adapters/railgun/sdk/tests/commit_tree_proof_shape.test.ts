// The commit-tree client-PIR path fetches auth-path siblings only. Folding a root needs
// the leaf, which that path never retrieves, so the result must not carry a `root` field
// at all: a substituted zero leaf folds to a root matching no tree state the server ever
// published, while the same method's plaintext path returns the adapter's real root.

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { RavenPOINodeInterface } from "../src/index";
import type { ClientPirContext, RavenInspireWasm } from "../src/index";

import { startMockServer, writeJson, type MockServer } from "./helpers/mock_server";

const TOKEN = "test-token-padded-long-enough-1234";
const TREE_NUMBER = 0;
const LEAF = 1234;
const NODE_BYTES = 32;
const MOCK_EPOCH = 1;
const MOCK_SCHEMA_VERSION = 1;

function stubWasm(): RavenInspireWasm {
  return {
    build_client_session: () => ({ free: () => undefined }),
    build_seeded_query: () => new Uint8Array(16),
    extract_response: (_session, _crs, _state, response, _entry) => new Uint8Array(response),
    build_instance_params_blob: () => new Uint8Array(0),
    register_client_session: () => {},
    path_indices_for_leaf: () => new Uint32Array(16),
    path_indices_for_per_list_leaf: () => new Uint32Array(16),
  };
}

function stubCtx(): ClientPirContext {
  return {
    wasm: stubWasm(),
    session: { free: () => undefined },
    crsBincode: new Uint8Array(0),
    shardConfigBincode: new Uint8Array(0),
    entrySize: NODE_BYTES,
  };
}

function mountBatchRoute(server: MockServer): void {
  server.route(
    (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
    (_req, _body, res) => {
      const slots = 16;
      const out = new Uint8Array(2 + 8 + slots * (8 + NODE_BYTES));
      out[1] = 1;
      const dv = new DataView(out.buffer);
      dv.setUint32(2, slots, true);
      let off = 10;
      for (let slot = 0; slot < slots; slot += 1) {
        dv.setUint32(off, NODE_BYTES, true);
        off += 8;
        out[off] = 0xab;
        out[off + NODE_BYTES - 1] = slot;
        off += NODE_BYTES;
      }
      res.writeHead(200, {
        "content-type": "application/octet-stream",
        "x-raven-epoch": String(MOCK_EPOCH),
        "x-raven-schema-version": String(MOCK_SCHEMA_VERSION),
      });
      res.end(Buffer.from(out));
      return true;
    },
  );
}

describe("commit-tree proof shape per retrieval path", () => {
  let server: MockServer;

  beforeAll(async () => {
    server = await startMockServer();
    mountBatchRoute(server);
    server.route(
      (req) => /^\/v1\/commit-tree\/\d+\/merkle-proof$/.test(req.url ?? ""),
      (_req, _body, res) => {
        writeJson(res, {
          leaf: "aa".repeat(32),
          elements: Array.from({ length: 16 }, (_unused, i) => `${i.toString(16).padStart(2, "0")}`.repeat(32)),
          indices: LEAF.toString(16).padStart(64, "0"),
          root: "cc".repeat(32),
        });
        return true;
      },
    );
  });

  afterAll(async () => {
    await server.close();
  });

  it("the client-PIR path returns an auth path with no root field", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t3CommitTree:${TREE_NUMBER}`, stubCtx()]]),
    });
    const got = await sdk.getMerkleProof(TREE_NUMBER, LEAF);
    expect(got.kind).toBe("authPath");
    if (got.kind !== "authPath") throw new Error("unreachable");
    expect(got.elements).toHaveLength(16);
    expect(got.indices).toBe(LEAF.toString(16).padStart(64, "0"));
    expect(Object.keys(got)).not.toContain("root");
    expect(Object.keys(got)).not.toContain("leaf");
  });

  it("no zero-leaf placeholder is reachable through the client-PIR path", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t3CommitTree:${TREE_NUMBER}`, stubCtx()]]),
    });
    const got = await sdk.getMerkleProof(TREE_NUMBER, LEAF);
    const serialized = JSON.stringify(got);
    expect(serialized).not.toContain("0".repeat(64));
  });

  it("the plaintext path still carries the adapter's own root", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: false,
    });
    const got = await sdk.getMerkleProof(TREE_NUMBER, LEAF);
    expect(got.kind).toBe("rooted");
    if (got.kind !== "rooted") throw new Error("unreachable");
    expect(got.proof.root).toBe("cc".repeat(32));
    expect(got.proof.leaf).toBe("aa".repeat(32));
  });
});
