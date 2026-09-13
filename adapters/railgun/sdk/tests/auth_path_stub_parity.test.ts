// Five test files read batch slot counts and cache hit/miss through the shared path-indices
// stub, so every conclusion they draw about padding and cache warmth rests on that stub
// matching the shipped wasm. Nothing checked that, and a drifted stub fails nothing.

import { describe, expect, it } from "vitest";

import * as wasmPkg from "raven-inspire-client-wasm";

import { RavenPOINodeInterface, TREE_DEPTH, type RavenInspireWasm } from "../src/index";
import {
  TOKEN,
  authPathOf,
  encodeBatchResponseNodes,
  stubCtx,
  stubWasm,
} from "./helpers/auth_path_stub";
import { startMockServer } from "./helpers/mock_server";

const real = wasmPkg as unknown as RavenInspireWasm;
const stub = stubWasm();
const LIST_KEY = new Uint8Array(32).fill(0xab);
// The leaves the stub-driven suites actually query, plus both ends of the tree.
const LEAVES = [0, 1, 7, 100, 1234, 1234 ^ 0b111, 4096, 4223, 65_534, 65_535];

describe("shared auth-path stub matches the shipped wasm geometry", () => {
  it("reproduces path_indices_for_leaf at every level", () => {
    for (const leaf of LEAVES) {
      const got = Array.from(stub.path_indices_for_leaf(0, leaf));
      expect(got, `leaf ${leaf}`).toEqual(Array.from(real.path_indices_for_leaf(0, leaf)));
      expect(got).toHaveLength(TREE_DEPTH);
    }
  });

  it("reproduces path_indices_for_per_list_leaf at every level", () => {
    for (const leaf of LEAVES) {
      expect(
        Array.from(stub.path_indices_for_per_list_leaf(LIST_KEY, leaf)),
        `leaf ${leaf}`,
      ).toEqual(Array.from(real.path_indices_for_per_list_leaf(LIST_KEY, leaf)));
    }
  });

  // The partial-hit arithmetic the padding tests assert on: 1234 and 1234^0b111 must share
  // every sibling above level 2, or "exactly 3 levels miss" is a claim about nothing.
  it("agrees with the wasm on how many levels two nearby leaves share", () => {
    const a = Array.from(real.path_indices_for_leaf(0, 1234));
    const b = Array.from(real.path_indices_for_leaf(0, 1234 ^ 0b111));
    const shared = a.filter((v, i) => v === b[i]).length;
    expect(shared).toBe(TREE_DEPTH - 3);
  });
});

describe("shared batch-response encoder round-trips through the SDK's own decode", () => {
  // Ten suites now serve batch replies through encodeBatchResponse*; this pins that ONE
  // writer to the real reader (stripSchemaEnvelope + decodeBatchBody + element slicing in
  // src/raven-poi-node-interface.ts) byte-for-byte, so the helper tracks the wire shape
  // the server actually speaks rather than a memory of it.
  it("every node byte comes back as the corresponding auth-path element", async () => {
    const server = await startMockServer();
    try {
      const nodes = Array.from({ length: TREE_DEPTH }, (_unused, i) => {
        const node = new Uint8Array(32);
        node[0] = 0x10 + i;
        node[15] = 0xa5;
        node[31] = 0xee;
        return node;
      });
      server.route(
        (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
        (_req, _body, res) => {
          res.writeHead(200, {
            "content-type": "application/octet-stream",
            "x-raven-epoch": "1",
            "x-raven-schema-version": "3",
          });
          res.end(Buffer.from(encodeBatchResponseNodes(nodes)));
          return true;
        },
      );
      const sdk = new RavenPOINodeInterface({
        endpoint: server.url,
        bearerToken: TOKEN,
        useClientPir: true,
        clientPirContexts: new Map([["t3CommitTree:0", stubCtx()]]),
      });
      const proof = authPathOf(await sdk.getMerkleProof(0, 5));
      expect(proof.elements).toHaveLength(TREE_DEPTH);
      const hex = (b: Uint8Array): string =>
        Array.from(b)
          .map((v) => v.toString(16).padStart(2, "0"))
          .join("");
      for (let i = 0; i < TREE_DEPTH; i += 1) {
        expect(proof.elements[i], `level ${i}`).toBe(hex(nodes[i]));
      }
    } finally {
      await server.close();
    }
  });
});
