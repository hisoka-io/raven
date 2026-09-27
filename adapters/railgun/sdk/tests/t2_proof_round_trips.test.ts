/**
 * How many requests a server sees when a wallet proves K commitments.
 *
 * Measured, not asserted: the numbers below come from counting POSTs on the mock, and the
 * test fails on the count rather than on a comment. It exists because the T2 proof path
 * used to `await` one batch per commitment, and each of those batches reached the ladder
 * with a single real target -- `paddedBatchLength(1)` is 1, so no cover slots were drawn
 * and the server could read the wallet's exact cache-miss count off a stable client id.
 * The round-trip cost and the leak were one defect, and one change fixes both down to the
 * ladder's own resolution: a padded length names a dyadic bucket, and the buckets for one and
 * two real queries hold one value each, so K = 1 and K = 2 remain exact.
 *
 * Grouping is per BLOCK because each block routes to its own instance label, so the win
 * caps at the number of blocks a wallet's notes span -- about six for the OFAC list today.
 * That ceiling is asserted too; a test that only proved the happy case would overstate it.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  MAX_BATCH_SIZE,
  RavenPOINodeInterface,
  hashLeftRight,
  paddedBatchLength,
} from "../src/index";
import { startMockServer, type MockServer } from "./helpers/mock_server";
import { TOKEN, encodeBatchResponseNodes, stubCtx } from "./helpers/auth_path_stub";
import { namedBatchTargets } from "./helpers/private_wire";
import { indexHolding } from "./helpers/prefix_channel";
import {
  PATH10_ROW_BYTES,
  path10Root,
  path10Siblings,
  path10Slot,
} from "./helpers/path10_row";

const LIST_KEY_HEX = "ab".repeat(32);
const LEAVES_PER_BLOCK = 65_536;
const TOTAL_LEVELS = 16;

function bcAt(n: number): string {
  return n.toString(16).padStart(4, "0").repeat(16);
}

/**
 * Sibling sets for `2^m` leaves sharing one subtree, so every one of them folds to the SAME
 * root -- which is what lets a single pinned root per block cover the whole group. Levels
 * below `m` come from the explicit subtree; levels at or above it are shared.
 */
function groupSiblings(leaves: readonly string[], marker: number): {
  perLeaf: string[][];
  root: string;
} {
  const m = Math.log2(leaves.length);
  if (!Number.isInteger(m)) throw new Error(`group size ${leaves.length} must be a power of two`);
  const upper = path10Siblings(marker).map((n) => Buffer.from(n).toString("hex"));
  const perLeaf: string[][] = leaves.map(() => []);
  let level = leaves.map((leaf) => leaf);
  for (let l = 0; l < m; l += 1) {
    for (let i = 0; i < leaves.length; i += 1) {
      perLeaf[i].push(level[(i >> l) ^ 1]);
    }
    const next: string[] = [];
    for (let j = 0; j < level.length; j += 2) next.push(hashLeftRight(level[j], level[j + 1]));
    level = next;
  }
  for (let i = 0; i < leaves.length; i += 1) {
    for (let l = m; l < TOTAL_LEVELS; l += 1) perLeaf[i].push(upper[l]);
  }
  const roots = leaves.map((leaf, i) => path10Root(leaf, perLeaf[i].map(hexToBytes), i));
  // Self-check: the rig is only meaningful if the group really does share a root.
  expect(new Set(roots).size).toBe(1);
  return { perLeaf, root: roots[0] };
}

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex.replace(/^0x/, ""), "hex"));
}

interface Plan {
  /** Blocks in the order the SDK will meet them, each with its own leaf group. */
  readonly blocks: { block: number; bcs: string[]; perLeaf: string[][]; root: string }[];
}

/** `blockSizes[i]` commitments in block `i`, each block's leaves at local indices 0.. */
function plan(blockSizes: readonly number[]): Plan {
  let next = 1;
  return {
    blocks: blockSizes.map((size, block) => {
      // The shared root needs a power-of-two subtree; leaves past `size` only fill it out.
      const width = 2 ** Math.ceil(Math.log2(size));
      const leaves = Array.from({ length: width }, () => bcAt(next++));
      const { perLeaf, root } = groupSiblings(leaves, 0xa0 + block);
      return { block, bcs: leaves.slice(0, size), perLeaf: perLeaf.slice(0, size), root };
    }),
  };
}

describe("round trips for a K-commitment proof", () => {
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

  function rig(p: Plan): { sdk: RavenPOINodeInterface; bcs: string[]; queriesPerPost: number[] } {
    const queriesPerPost: number[] = [];
    const slots = new Map<string, Uint8Array>();
    const placed: [string, number][] = [];
    const pinned = new Map<string, string>();
    for (const { block, bcs, perLeaf, root } of p.blocks) {
      pinned.set(`1:${LIST_KEY_HEX}:${block}`, root);
      bcs.forEach((bcHex, i) => {
        placed.push([bcHex, block * LEAVES_PER_BLOCK + i]);
        slots.set(bcHex, path10Slot({ bcHex, nodes: perLeaf[i].map(hexToBytes) }));
      });
    }

    // A real PIR server cannot know which row a query targets -- this rig's stub queries name
    // it, which is the only reason the assertions below can check ORDER at all.
    const bcAtRow = new Map<string, string>(
      p.blocks.flatMap(({ block, bcs }) => bcs.map((bc, row) => [`${block}:${row}`, bc])),
    );

    server.route(
      (req) => /^\/v1\/instance\/([^/]+)\/batch$/.test(req.url ?? ""),
      (req, body, res) => {
        const raw = /^\/v1\/instance\/([^/]+)\/batch$/.exec(req.url ?? "")?.[1] ?? "";
        const label = decodeURIComponent(raw);
        const block = Number(label.slice(label.lastIndexOf(":") + 1));
        if (!p.blocks.some((planned) => planned.block === block)) {
          throw new Error(`no planned block for instance label ${label}`);
        }
        const targets = namedBatchTargets(body);
        queriesPerPost.push(targets.length);
        // A cover slot names a row this rig holds no commitment at; any well-formed row answers it.
        const served = targets.map((row) => {
          const bc = bcAtRow.get(`${block}:${row}`);
          return slots.get(bc ?? p.blocks[0].bcs[0])!;
        });
        res.writeHead(200, {
          "content-type": "application/octet-stream",
          "x-raven-epoch": "1",
          "x-raven-schema-version": "7",
          "x-raven-freshness": "lag_blocks=0 applied_height=0 epoch=1 confidence=1",
        });
        res.end(Buffer.from(encodeBatchResponseNodes(served)));
        return true;
      },
    );

    const pathCtx = { ...stubCtx(), entrySize: PATH10_ROW_BYTES };
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      // One context per list; the per-block LABELS below are what route to an instance.
      clientPirContexts: new Map([[`t2Path:1:${LIST_KEY_HEX}`, pathCtx]]),
      clientPirInstanceLabels: new Map(
        p.blocks.map(({ block }) => [
          `t2Path:1:${LIST_KEY_HEX}:${block}`,
          `t2Path-${LIST_KEY_HEX}:${block}`,
        ]),
      ),
      ppoiPinnedRoots: pinned,
      poiListIndexes: new Map([[`1:${LIST_KEY_HEX}`, indexHolding(placed)]]),
      poiListIndexStore: false,
    });
    return { sdk, bcs: p.blocks.flatMap(({ bcs }) => bcs), queriesPerPost };
  }

  function batchPosts(): number {
    return server.requests.filter((r) => (r.url ?? "").endsWith("/batch")).length;
  }

  // 3 and 5 are here because at a power of two the padded length IS K, and a test of those
  // alone would pass with the padding deleted.
  for (const k of [1, 2, 3, 4, 5, 8]) {
    it(`K=${k} in one block costs ONE request carrying ${paddedBatchLength(k)} padded queries`, async () => {
      const { sdk, bcs, queriesPerPost } = rig(plan([k]));
      const started = Date.now();
      const proofs = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, bcs);
      const elapsedMs = Date.now() - started;

      expect(proofs).toHaveLength(k);
      expect(batchPosts()).toBe(1);
      expect(queriesPerPost).toEqual([paddedBatchLength(k)]);
      // Printed, not just asserted: the point of this file is that a reader gets the number.
      console.log(`K=${k}: ${batchPosts()} batch POST(s), ${elapsedMs} ms wall clock`);
    });
  }

  // The ceiling, stated honestly: grouping is per block, so notes spread across blocks still
  // cost one request each. A wallet whose six notes sit in six blocks sees no improvement.
  it("costs one request per BLOCK, not one per commitment", async () => {
    const { sdk, bcs } = rig(plan([2, 2, 2]));
    const proofs = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, bcs);
    expect(proofs).toHaveLength(6);
    expect(batchPosts()).toBe(3);
  });

  // Above the ladder's ceiling a group splits, and each chunk is padded independently --
  // `paddedBatchLength` refuses a count with no dyadic step under the ceiling, so a single
  // oversized batch is not an option the code could have taken by accident.
  it(`splits a block group above MAX_BATCH_SIZE=${MAX_BATCH_SIZE}`, async () => {
    const { sdk, bcs } = rig(plan([64]));
    const proofs = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, bcs);
    expect(proofs).toHaveLength(64);
    expect(batchPosts()).toBe(2);
  });

  // Order is the property a grouped implementation is most likely to lose: the caller gets
  // proofs back in the order it asked, not in block order.
  it("returns proofs in the caller's order across blocks", async () => {
    const p = plan([2, 2]);
    const interleaved = [
      p.blocks[1].bcs[0],
      p.blocks[0].bcs[1],
      p.blocks[1].bcs[1],
      p.blocks[0].bcs[0],
    ];
    const { sdk } = rig(p);
    const proofs = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, interleaved);
    expect(proofs.map((proof) => proof.leaf)).toEqual(interleaved);
  });
});
