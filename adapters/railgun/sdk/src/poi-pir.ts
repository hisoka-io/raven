/** Railgun POI input validation. */

import { RavenError } from "./errors";

/** Wallet-facing POI verdict, spelled as engine's `TXOPOIListStatus`. */
export type POIStatus = "Valid" | "ShieldBlocked" | "ProofSubmitted" | "Missing";

/** Convert a hex string with an optional `0x` prefix to bytes. */
export function hexToBytes(hex: string): Uint8Array {
  const stripped = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (stripped.length % 2 !== 0) {
    throw RavenError.invalidQuery(`hexToBytes: odd-length input (${stripped.length})`);
  }
  const invalidOffset = stripped.search(/[^0-9a-fA-F]/);
  if (invalidOffset !== -1) {
    throw RavenError.invalidQuery(
      `hexToBytes: invalid hex pair at offset ${invalidOffset - (invalidOffset % 2)}`,
    );
  }
  const out = new Uint8Array(stripped.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(stripped.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Lower-case hex without a prefix. */
export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

/** True when `haystack` contains `needle` contiguously. */
export function containsByteSequence(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length === 0) return true;
  if (needle.length > haystack.length) return false;
  outer: for (let i = 0; i <= haystack.length - needle.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

/** Commitment-tree depth; mirrors `raven-railgun-engine::imt::TREE_DEPTH`. */
export const TREE_DEPTH = 16;

/** Maximum leaves per tree. */
export const TREE_MAX_LEAVES = 1 << TREE_DEPTH;

/** The 64 lower-case hex digits of the 32-byte value a blinded commitment spells. Upstream serves
 *  some commitments without their leading zero digits, so 1 to 64 digits are taken, as the node's
 *  mirror takes them. */
export function canonicalCommitmentHex(bc: string, label: string = "blindedCommitment"): string {
  const stripped = bc.startsWith("0x") || bc.startsWith("0X") ? bc.slice(2) : bc;
  if (stripped.length === 0 || stripped.length > 64) {
    throw RavenError.invalidQuery(
      `${label}: expected 1 to 64 hex digits (a 32-byte value), got ${stripped.length}`,
    );
  }
  if (!/^[0-9a-fA-F]+$/.test(stripped)) {
    throw RavenError.invalidQuery(`${label}: contains non-hex characters`);
  }
  return stripped.toLowerCase().padStart(64, "0");
}

/** Validate a blinded commitment as every commitment-taking method reads one: 1 to 64 hex
 *  digits, optionally after `0x`. */
export function validateBcHex(bc: string, label: string = "blindedCommitment"): void {
  canonicalCommitmentHex(bc, label);
}

/** Validate that a list key is exactly 32 bytes of hex. */
export function validateListKeyHex(listKey: string, label: string = "listKey"): void {
  const stripped = listKey.startsWith("0x") || listKey.startsWith("0X") ? listKey.slice(2) : listKey;
  if (stripped.length !== 64) {
    throw RavenError.invalidQuery(
      `${label}: expected 64 hex chars (32 bytes), got ${stripped.length}`,
    );
  }
  if (!/^[0-9a-fA-F]+$/.test(stripped)) {
    throw RavenError.invalidQuery(`${label}: contains non-hex characters`);
  }
}

/** Validate a leaf index against the depth-16 range. */
export function validateLeafIndex(idx: number, label: string = "leafIndex"): void {
  if (!Number.isInteger(idx)) {
    throw RavenError.invalidQuery(`${label}: ${idx} must be an integer`);
  }
  if (idx < 0) {
    throw RavenError.invalidQuery(`${label}: ${idx} must be >= 0`);
  }
  if (idx >= TREE_MAX_LEAVES) {
    throw RavenError.invalidQuery(`${label}: ${idx} >= 2^${TREE_DEPTH} (${TREE_MAX_LEAVES})`);
  }
}
