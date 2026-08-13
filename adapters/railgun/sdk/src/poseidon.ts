// The adapter returns auth-path nodes, not the root, so the fold happens here and
// must match upstream Merkletree.hashLeftRight to verify under verifyMerkleProof.

import { poseidonHex } from "@railgun-community/poseidon-hash-wasm";

const FIELD_HEX_LEN = 64;

/** Poseidon-BN254 over two 64-char no-prefix hex inputs. */
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

/**
 * Left-pad a field element to 64 hex chars, refusing anything longer.
 *
 * Truncating an over-long input - which this did, keeping the LAST 64 chars - silently
 * hashes a DIFFERENT field element and returns a plausible root for input the caller
 * never supplied. There is no over-long value whose correct interpretation is "drop the
 * leading bytes": a 33-byte value is a bug at the caller, and the only safe answer is to
 * say so. Short values are still zero-padded; that is the documented contract and the
 * Rust side agrees.
 */
function padTo64(hex: string): string {
  if (!/^[0-9a-f]*$/.test(hex)) {
    throw new Error(
      `poseidon: field element must be lower-case hex, got ${JSON.stringify(hex)}`,
    );
  }
  if (hex.length > FIELD_HEX_LEN) {
    throw new Error(
      `poseidon: field element is ${hex.length} hex chars, over the ${FIELD_HEX_LEN}-char ` +
        `field width; truncating it would hash a different value and return a root for ` +
        `input that was never supplied`,
    );
  }
  return hex.padStart(FIELD_HEX_LEN, "0");
}
