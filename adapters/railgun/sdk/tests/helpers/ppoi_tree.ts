/** A real depth-16 PPOI tree over a few leaves, so a served proof folds to a root a test can pin. */

import { TREE_DEPTH, hashLeftRight, type MerkleProof } from "../../src/index";

const ZERO_LEAF = "00".repeat(32);

export interface PpoiTree {
  readonly root: string;
  /** One proof per leaf, in leaf order, in the upstream wire shape. */
  readonly proofs: MerkleProof[];
}

export function ppoiTree(leaves: readonly string[]): PpoiTree {
  if (leaves.length === 0) throw new Error("ppoiTree needs at least one leaf");
  const zeros = [ZERO_LEAF];
  for (let level = 1; level <= TREE_DEPTH; level += 1) {
    zeros.push(hashLeftRight(zeros[level - 1], zeros[level - 1]));
  }
  const levels: string[][] = [leaves.map((leaf) => leaf.replace(/^0x/i, "").toLowerCase())];
  for (let level = 0; level < TREE_DEPTH; level += 1) {
    const nodes = levels[level];
    const parents: string[] = [];
    for (let i = 0; i < nodes.length; i += 2) {
      parents.push(hashLeftRight(nodes[i], nodes[i + 1] ?? zeros[level]));
    }
    levels.push(parents);
  }
  const root = levels[TREE_DEPTH][0];
  const proofs = leaves.map((leaf, index) => ({
    leaf,
    elements: levels
      .slice(0, TREE_DEPTH)
      .map((nodes, level) => nodes[(index >> level) ^ 1] ?? zeros[level]),
    indices: index.toString(16).padStart(64, "0"),
    root,
  }));
  return { root, proofs };
}
