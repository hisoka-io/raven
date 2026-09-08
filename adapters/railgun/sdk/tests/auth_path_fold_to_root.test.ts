// The SDK folds a PIR-fetched auth path into the root a wallet verifies against, and
// nothing else in the suite reads that root: replacing the whole fold with `root = leaf`
// left all 265 offline tests green. The two properties a wrong root needs are pinned here
// - the siblings arrive in level order, and the fold consumes every sibling and every
// index bit - because both fail silently at HTTP 200 with a well-formed 64-char answer.

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { ImtCache, RavenPOINodeInterface, TREE_DEPTH, hashLeftRight } from "../src/index";

import { startMockServer, type MockServer } from "./helpers/mock_server";
import {
  TOKEN,
  authPathOf,
  encodeBatchResponse,
  encodedBatchCount,
  stubCtx,
} from "./helpers/auth_path_stub";

const LIST_KEY_HEX = "ab".repeat(32);
const BC_HEX = "11".repeat(32);
const LEAF = 1234;
const TREE_NUMBER = 0;

/** Root of the fixed (BC, leaf index, sibling set) below, folded by this SDK at HEAD. */
const PINNED_ROOT =
  "21c3bd4a0c9fa6a964d426705abc9425edaa99ee3ad24645ec1bc5e39519d717";

function mountBatchRoute(server: MockServer, epoch: number): void {
  server.route(
    (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
    (_req, body, res) => {
      res.writeHead(200, {
        "content-type": "application/octet-stream",
        "x-raven-epoch": String(epoch),
        "x-raven-schema-version": "1",
      });
      res.end(Buffer.from(encodeBatchResponse(epoch, encodedBatchCount(body))));
      return true;
    },
  );
}

function newSdk(server: MockServer): RavenPOINodeInterface {
  return new RavenPOINodeInterface({
    endpoint: server.url,
    bearerToken: TOKEN,
    useClientPir: true,
    clientPirContexts: new Map([
      [`t2Path:${LIST_KEY_HEX}`, stubCtx()],
      [`t3CommitTree:${TREE_NUMBER}`, stubCtx()],
    ]),
    bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[BC_HEX, LEAF]])]]),
    imtCache: new ImtCache({ disableIndexedDb: true }),
  });
}

/**
 * Reference fold built from `hashLeftRight` alone, so it survives a rewrite of
 * `foldMerkleRoot` itself and still catches a swapped orientation or a reordered path.
 */
function referenceFold(leaf: string, siblings: string[], leafIndex: number): string {
  let current = leaf;
  for (let level = 0; level < siblings.length; level += 1) {
    const onRight = ((leafIndex >> level) & 1) === 1;
    current = onRight
      ? hashLeftRight(siblings[level], current)
      : hashLeftRight(current, siblings[level]);
  }
  return current;
}

/** Slot tag `encodeBatchResponse` writes into the last byte of every node. */
function slotTagOf(elementHex: string): number {
  return Number.parseInt(elementHex.slice(62), 16);
}

describe("the SDK's PPOI auth path folds to a verifiable root", () => {
  let server: MockServer;

  beforeAll(async () => {
    server = await startMockServer();
    mountBatchRoute(server, 9);
  });
  afterAll(async () => {
    await server.close();
  });

  it("returns the leaf, the 256-bit index word and a root folded over all 16 siblings", async () => {
    const [proof] = await newSdk(server).getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);

    expect(proof.leaf).toBe(BC_HEX);
    expect(proof.elements).toHaveLength(TREE_DEPTH);
    // nToHex(leafIndex, UINT_256), not the 8-char uint32 that upstream verifyMerkleProof rejects
    expect(proof.indices).toBe(LEAF.toString(16).padStart(64, "0"));
    expect(proof.root).toBe(PINNED_ROOT);
    expect(proof.root).toBe(referenceFold(proof.leaf, proof.elements, LEAF));
  });

  it("orders the siblings level 0 first, which is the order the fold assumes", async () => {
    const [proof] = await newSdk(server).getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);

    // A reversed or rotated assembly still yields 16 well-formed nodes and a 64-char root.
    expect(proof.elements.map(slotTagOf)).toEqual(
      Array.from({ length: TREE_DEPTH }, (_unused, level) => level),
    );
  });

  it("consumes the index bits: a sibling-identical neighbour leaf folds to a different root", async () => {
    const neighbour = LEAF ^ 0b1;
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t2Path:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[BC_HEX, neighbour]])]]),
      imtCache: new ImtCache({ disableIndexedDb: true }),
    });
    const [proof] = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);

    // The stub keys nodes on slot, not on index, so only the fold's index bits differ.
    expect(proof.elements).toEqual(
      (await newSdk(server).getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]))[0].elements,
    );
    expect(proof.root).not.toBe(PINNED_ROOT);
    expect(proof.root).toBe(referenceFold(proof.leaf, proof.elements, neighbour));
  });

  it("consumes the sibling bytes: nodes served at another epoch fold to a different root", async () => {
    const other = await startMockServer();
    mountBatchRoute(other, 8);
    try {
      const [proof] = await newSdk(other).getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);

      expect(proof.elements.map(slotTagOf)).toEqual(
        Array.from({ length: TREE_DEPTH }, (_unused, level) => level),
      );
      expect(proof.root).not.toBe(PINNED_ROOT);
      expect(proof.root).toBe(referenceFold(proof.leaf, proof.elements, LEAF));
    } finally {
      await other.close();
    }
  });

  it("hands the commit-tree caller siblings in the same level order it must fold in", async () => {
    // T3 returns no root, so the level order IS the whole contract with the wallet.
    const path = authPathOf(await newSdk(server).getMerkleProof(TREE_NUMBER, LEAF));

    expect(path.elements.map(slotTagOf)).toEqual(
      Array.from({ length: TREE_DEPTH }, (_unused, level) => level),
    );
  });
});
