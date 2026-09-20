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
import {
  PATH10_ROW_BYTES,
  mountPath10Route,
  path10Root,
  path10Siblings,
} from "./helpers/path10_row";

const LIST_KEY_HEX = "ab".repeat(32);
const BC_HEX = "11".repeat(32);
const LEAF = 1234;
const TREE_NUMBER = 0;

// The path-10 record replaced sixteen 32 B node reads with one 512 B row plus a 160 B
// upper-sibling addendum, and the pinned root became mandatory (D-06). The served sibling
// set is now fixture data rather than a literal, so the root is derived from it here --
// a hardcoded root would only restate whatever the helper happens to emit.
const PATH10_NODES = path10Siblings(0xab);
/** A second sibling set, standing in for nodes served at a different epoch. */
const OTHER_NODES = path10Siblings(0xcd);
const PATH10_BLOCK = Math.floor(LEAF / 65_536);
const PATH10_INSTANCE = `t2Path-${LIST_KEY_HEX}`;
const TRUE_ROOT = path10Root(BC_HEX, PATH10_NODES, LEAF);

function mountBatchRoute(server: MockServer, epoch: number): void {
  server.route(
    (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
    (_req, body, res) => {
      res.writeHead(200, {
        "content-type": "application/octet-stream",
        "x-raven-epoch": String(epoch),
        "x-raven-schema-version": "6",
        "x-raven-freshness": "lag_blocks=0 applied_height=0 epoch=1 confidence=1",
      });
      res.end(Buffer.from(encodeBatchResponse(epoch, encodedBatchCount(body))));
      return true;
    },
  );
}

function newSdk(
  server: MockServer,
  overrides: { leaf?: number; pinnedRoot?: string } = {},
): RavenPOINodeInterface {
  const leaf = overrides.leaf ?? LEAF;
  const pathCtx = { ...stubCtx(), entrySize: PATH10_ROW_BYTES };
  return new RavenPOINodeInterface({
    endpoint: server.url,
    bearerToken: TOKEN,
    useClientPir: true,
    clientPirContexts: new Map([
      [`t2Path:${LIST_KEY_HEX}`, pathCtx],
      [`t3CommitTree:${TREE_NUMBER}`, stubCtx()],
    ]),
    // D-06: every path-10 fold requires a pinned root, so the rig always supplies one.
    ppoiPinnedRoots: new Map([
      [`${LIST_KEY_HEX}:${PATH10_BLOCK}`, overrides.pinnedRoot ?? TRUE_ROOT],
    ]),
    bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[BC_HEX, leaf]])]]),
    imtCache: new ImtCache({ disableIndexedDb: true }),
  });
}

/** Assert the SDK refused specifically because the fold missed the pinned root. */
async function expectPinnedRootRefusal(promise: Promise<unknown>): Promise<void> {
  let message = "";
  let returned = false;
  try {
    await promise;
    returned = true;
  } catch (e) {
    message = String((e as Error).message);
  }
  expect(returned, "a fold that misses the pinned root must not return a proof").toBe(false);
  expect(message).toMatch(/does not match pinned root/);
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
    mountPath10Route(server, {
      bcHex: BC_HEX,
      nodes: PATH10_NODES,
      instance: PATH10_INSTANCE,
    });
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
    expect(proof.root).toBe(TRUE_ROOT);
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
    // The served siblings are identical, so ONLY the fold's index bits differ. Computed
    // with `hashLeftRight` alone, independently of the SDK's fold.
    const neighbourRoot = referenceFold(
      BC_HEX,
      PATH10_NODES.map((n) => Buffer.from(n).toString("hex")),
      neighbour,
    );
    expect(neighbourRoot).not.toBe(TRUE_ROOT);

    // Under D-06 the SDK no longer merely folds to something else -- it refuses, because
    // the fold misses the pinned root. That is strictly stronger than the old assertion.
    await expectPinnedRootRefusal(
      newSdk(server, { leaf: neighbour }).getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]),
    );
    // ...and it accepts the same neighbour fold once its own root is the pinned one,
    // which proves the refusal tracked the index bits rather than the leaf being odd.
    const [proof] = await newSdk(server, {
      leaf: neighbour,
      pinnedRoot: neighbourRoot,
    }).getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);
    expect(proof.root).toBe(neighbourRoot);
  });

  it("consumes the sibling bytes: nodes served at another epoch fold to a different root", async () => {
    const other = await startMockServer();
    mountPath10Route(other, {
      bcHex: BC_HEX,
      nodes: OTHER_NODES,
      instance: PATH10_INSTANCE,
    });
    try {
      const otherRoot = path10Root(BC_HEX, OTHER_NODES, LEAF);
      expect(otherRoot).not.toBe(TRUE_ROOT);

      // Same leaf, same index bits, different sibling BYTES: refused against the pin.
      await expectPinnedRootRefusal(newSdk(other).getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]));

      const [proof] = await newSdk(other, { pinnedRoot: otherRoot }).getPOIMerkleProofs(
        LIST_KEY_HEX,
        [BC_HEX],
      );
      expect(proof.elements.map(slotTagOf)).toEqual(
        Array.from({ length: TREE_DEPTH }, (_unused, level) => level),
      );
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
