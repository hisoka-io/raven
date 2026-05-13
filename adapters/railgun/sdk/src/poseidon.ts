/**
 * Thin Poseidon binding for the SDK.
 *
 * Wraps `@railgun-community/poseidon-hash-wasm` so the merkle-proof
 * folder in `raven-poi-node-interface.ts` can compute the root hash
 * by combining the leaf with the 16 sibling node hashes returned by
 * the PIR auth-path fetch. The hash function and field arithmetic
 * MUST match upstream's `Merkletree.hashLeftRight` exactly so the
 * resulting `MerkleProof.root` value verifies against an upstream
 * `verifyMerkleProof` invocation.
 *
 * Two reasons for this module's existence:
 *
 * 1. The PIR adapter does NOT return the on-chain root from a
 *    sibling fetch — it only returns the auth-path nodes. The
 *    SDK reconstructs the root client-side by folding the leaf with
 *    the siblings using the same Poseidon hashLeftRight upstream
 *    uses.
 *
 * 2. Upstream's `Merkletree.getMerkleProof` reads the root from a
 *    separately stored top-level node. Without the upstream DB the
 *    SDK has nothing to read, so the only way to surface a
 *    verifiable `root` to the wallet is to fold and emit the result.
 */

import { poseidonHex } from "@railgun-community/poseidon-hash-wasm";

const FIELD_HEX_LEN = 64;

/**
 * Hash two 32-byte inputs together using Poseidon over BN254. Both
 * inputs are hex strings (no `0x` prefix, exactly 64 chars). Output
 * is 64-char no-prefix hex matching upstream's
 * `Merkletree.hashLeftRight` byte shape.
 */
export function hashLeftRight(left: string, right: string): string {
  const a = stripAndPad(left);
  const b = stripAndPad(right);
  // `poseidonHex` from the WASM package returns hex without 0x; pad
  // to 64 chars to mirror upstream's `formatToByteLength(_, UINT_256)`
  // post-processing.
  return padTo64(poseidonHex([a, b]));
}

/**
 * Fold a leaf with `siblings` according to `indices`. `indices` is
 * the upstream-format leaf-index bitmap encoded as 64-char hex (LE
 * bit `i` = path bit at level `i`; bit set means the leaf at that
 * level is the right child).
 *
 * Returns the computed root as 64-char no-prefix hex.
 */
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
      // bit set -> current is the right child at this level
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
