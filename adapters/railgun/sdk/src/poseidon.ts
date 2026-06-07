// Folds a leaf with PIR-fetched siblings into a root client-side: the
// adapter returns only auth-path nodes, not the on-chain root. Must
// match upstream Merkletree.hashLeftRight so the root verifies against
// upstream verifyMerkleProof.

import { poseidonHex } from "@railgun-community/poseidon-hash-wasm";

const FIELD_HEX_LEN = 64;

/** Poseidon-BN254 hash of two 64-char no-prefix hex inputs; output matches upstream Merkletree.hashLeftRight byte shape. */
export function hashLeftRight(left: string, right: string): string {
  const a = stripAndPad(left);
  const b = stripAndPad(right);
  return padTo64(poseidonHex([a, b]));
}

/** Fold a leaf with siblings into a root; `indices` bit `i` set means the leaf is the right child at level `i`. */
export function foldMerkleRoot(
  leaf: string,
  siblings: string[],
  indices: bigint,
): string {
  let current = stripAndPad(leaf);
  for (let i = 0; i < siblings.length; i += 1) {
    const sib = stripAndPad(siblings[i]);
    const bit = (indices >> BigInt(i)) & 1n;
    if (bit === 1n) {
      current = hashLeftRight(sib, current);
    } else {
      current = hashLeftRight(current, sib);
    }
  }
  return current;
}

function stripAndPad(hex: string): string {
  const stripped = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  return padTo64(stripped.toLowerCase());
}

function padTo64(hex: string): string {
  if (hex.length >= FIELD_HEX_LEN) {
    return hex.slice(hex.length - FIELD_HEX_LEN);
  }
  return hex.padStart(FIELD_HEX_LEN, "0");
}
