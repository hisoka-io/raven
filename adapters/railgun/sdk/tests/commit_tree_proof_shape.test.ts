// A commit-tree proof carries no root on either path. Client-PIR fetches auth-path siblings only
// and never the leaf, and a substituted zero leaf would fold to a root no tree state ever had. The
// plaintext route does send a root, but only the serving node vouches for it, so it is dropped and
// the wallet folds its own note, which the contract's root history then checks.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { RavenError, RavenPOINodeInterface } from "../src/index";
import { makeRegisterSpy, stubRemoteSessionExports } from "./helpers/register_spy";
import type { ClientPirContext, RavenInspireWasm } from "../src/index";

import { startMockServer, writeJson, type MockServer } from "./helpers/mock_server";

const TOKEN = "test-token-padded-long-enough-1234";
const TREE_NUMBER = 0;
const LEAF = 1234;
const NODE_BYTES = 32;
const MOCK_EPOCH = 1;
const MOCK_SCHEMA_VERSION = 7;
const LEAF_INDICES = LEAF.toString(16).padStart(64, "0");
/** What the node's plaintext route sends: its own leaf and root beside the path. */
const PLAINTEXT_BODY = {
  leaf: "aa".repeat(32),
  elements: Array.from({ length: 16 }, (_unused, i) => i.toString(16).padStart(2, "0").repeat(32)),
  indices: LEAF_INDICES,
  root: "cc".repeat(32),
};

function stubWasm(): RavenInspireWasm {
  return {
    ...stubRemoteSessionExports(),
    build_client_session: () => ({ free: () => undefined }),
    build_seeded_query: () => new Uint8Array(16),
    extract_response: (_session, _crs, _state, response, _entry) => new Uint8Array(response),
    build_instance_params_blob: () => new Uint8Array(0),
    register_client_session: makeRegisterSpy(),
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
      out[1] = 8;
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
  let plaintextBody: unknown = PLAINTEXT_BODY;

  beforeAll(async () => {
    server = await startMockServer();
    mountBatchRoute(server);
    server.route(
      (req) => /^\/v1\/commit-tree\/\d+\/merkle-proof$/.test(req.url ?? ""),
      (_req, _body, res) => {
        writeJson(res, plaintextBody);
        return true;
      },
    );
  });

  afterEach(() => {
    plaintextBody = PLAINTEXT_BODY;
  });

  afterAll(async () => {
    await server.close();
  });

  function plaintextSdk(): RavenPOINodeInterface {
    return new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: false,
    });
  }

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

  it.each([
    { label: "as the node spells it", body: PLAINTEXT_BODY },
    {
      label: "from a 0x-prefixed upper-case spelling",
      body: {
        ...PLAINTEXT_BODY,
        elements: PLAINTEXT_BODY.elements.map((element) => `0x${element.toUpperCase()}`),
        indices: `0x${LEAF.toString(16)}`,
      },
    },
  ])("the plaintext path returns the same rootless auth path $label", async ({ body }) => {
    plaintextBody = body;
    const got = await plaintextSdk().getMerkleProof(TREE_NUMBER, LEAF);
    expect(got).toStrictEqual({
      kind: "authPath",
      elements: PLAINTEXT_BODY.elements,
      indices: LEAF_INDICES,
    });
    expect(JSON.stringify(got)).not.toContain(PLAINTEXT_BODY.root);
  });

  it.each([
    {
      label: "answers another leaf",
      body: { ...PLAINTEXT_BODY, indices: (LEAF + 1).toString(16).padStart(64, "0") },
      reason: /do not name leaf 1234/,
    },
    {
      label: "is fifteen levels deep",
      body: { ...PLAINTEXT_BODY, elements: PLAINTEXT_BODY.elements.slice(1) },
      reason: /not 16 32-byte hex/,
    },
    {
      label: "carries a non-hex sibling",
      body: { ...PLAINTEXT_BODY, elements: ["zz".repeat(32), ...PLAINTEXT_BODY.elements.slice(1)] },
      reason: /not 16 32-byte hex/,
    },
  ])("refuses a plaintext path that $label", async ({ body, reason }) => {
    plaintextBody = body;
    const thrown = await plaintextSdk()
      .getMerkleProof(TREE_NUMBER, LEAF)
      .then(
        () => undefined,
        (error: unknown) => error,
      );
    expect(RavenError.is(thrown, "DecodeError"), String(thrown)).toBe(true);
    expect(String((thrown as Error).message)).toMatch(reason);
  });
});
