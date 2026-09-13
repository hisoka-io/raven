/** Railgun POI row decoding, validation, and Merkle-path addressing. */

import { RavenError } from "./errors";

/**
 * Wallet-facing POI verdict. `Unreachable` is SDK-local: no adapter response was
 * received, so it must not be treated like the adapter's non-blocking `Missing` verdict.
 */
export type POIStatus =
  | "Valid"
  | "ShieldBlocked"
  | "ProofSubmitted"
  | "Missing"
  | "Unreachable";

/** Railgun Merkle-path methods supplied by `raven-inspire-client-wasm`. */
export interface RavenPOIPathWasm {
  /** 16 flat-global auth-path row indices for a commit-tree leaf. */
  path_indices_for_leaf(treeNumber: number, leafIdx: number): Uint32Array;
  /** 16 flat-global auth-path row indices for a per-list leaf. */
  path_indices_for_per_list_leaf(listKey: Uint8Array, idx: number): Uint32Array;
}

/** BC -> idx map for one PPOI list, fetched from `GET /v1/poi/:list/bc-to-idx-map`. */
export type BcToIdxMap = Map<string, number>;

/** Narrowest T1 status row the Rust status encoder will build. */
export const MIN_STATUS_ROW_BYTES = 32;

/**
 * Read a T1 verdict out of a status row, refusing any row whose blinded-commitment
 * tail is not `expectedBcHex`. An unpopulated row is zero-filled and status byte 0
 * means `Valid`, so the tail is the only thing separating a real verdict from a row
 * that was never written.
 */
export function decodeStatusRow(
  plaintext: Uint8Array,
  expectedBcHex: string,
  label: string,
): POIStatus {
  if (plaintext.length < MIN_STATUS_ROW_BYTES) {
    throw RavenError.decodeError(
      `${label}: status row is ${plaintext.length} bytes, need >= ${MIN_STATUS_ROW_BYTES}`,
    );
  }
  validateBcHex(expectedBcHex, `${label}: expected blindedCommitment`);
  const expected = hexToBytes(expectedBcHex);
  const tailLen = Math.min(plaintext.length - 1, expected.length);
  for (let i = 0; i < tailLen; i += 1) {
    if (plaintext[1 + i] !== expected[i]) {
      throw RavenError.decodeError(
        `${label}: status row BC tail differs from the requested ${expectedBcHex} ` +
          `at tail byte ${i} of ${tailLen}; the row does not describe this blinded commitment`,
      );
    }
  }
  return statusByteToPOIStatus(plaintext[0]);
}

/**
 * Map the leading plaintext-row byte to the POI status enum; mirrors `PerListStatusEncoder`.
 * `Unreachable` has no wire byte; the SDK emits it only when no response arrives.
 */
export function statusByteToPOIStatus(b: number): POIStatus {
  switch (b) {
    case 0:
      return "Valid";
    case 1:
      return "ShieldBlocked";
    case 2:
      return "ProofSubmitted";
    case 3:
      return "Missing";
    default:
      throw RavenError.decodeError(`statusByteToPOIStatus: unknown POI status byte ${b}`);
  }
}

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

/** Validate that a blinded commitment is exactly 32 bytes of hex. */
export function validateBcHex(bc: string, label: string = "blindedCommitment"): void {
  const stripped = bc.startsWith("0x") || bc.startsWith("0X") ? bc.slice(2) : bc;
  if (stripped.length !== 64) {
    throw RavenError.invalidQuery(
      `${label}: expected 64 hex chars (32 bytes), got ${stripped.length}`,
    );
  }
  if (!/^[0-9a-fA-F]+$/.test(stripped)) {
    throw RavenError.invalidQuery(`${label}: contains non-hex characters`);
  }
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

/** Validate a tree number against the upstream `u32` range. */
export function validateTreeNumber(treeNumber: number, label: string = "treeNumber"): void {
  if (!Number.isInteger(treeNumber)) {
    throw RavenError.invalidQuery(`${label}: ${treeNumber} must be an integer`);
  }
  if (treeNumber < 0) {
    throw RavenError.invalidQuery(`${label}: ${treeNumber} must be >= 0`);
  }
  if (treeNumber > 0xffffffff) {
    throw RavenError.invalidQuery(`${label}: ${treeNumber} exceeds u32 range`);
  }
}

/** Validate and copy the commit-tree path indices returned by WASM. */
export function pathIndicesForLeaf(
  wasm: RavenPOIPathWasm,
  treeNumber: number,
  leafIdx: number,
): number[] {
  validateTreeNumber(treeNumber);
  validateLeafIndex(leafIdx);
  let raw: Uint32Array;
  try {
    raw = wasm.path_indices_for_leaf(treeNumber, leafIdx);
  } catch (cause) {
    throw RavenError.invalidQuery(
      `path_indices_for_leaf: wasm threw on (tree=${treeNumber}, leaf=${leafIdx})`,
      { cause: String(cause) },
    );
  }
  if (raw.length !== TREE_DEPTH) {
    throw RavenError.decodeError(
      `path_indices_for_leaf: wasm returned ${raw.length} indices (expected ${TREE_DEPTH})`,
    );
  }
  const out: number[] = new Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) {
    out[i] = raw[i];
  }
  return out;
}

/** Validate and copy the per-list path indices returned by WASM. */
export function pathIndicesForPerListLeaf(
  wasm: RavenPOIPathWasm,
  listKeyHex: string,
  idx: number,
): number[] {
  validateListKeyHex(listKeyHex);
  validateLeafIndex(idx, "perListIndex");
  const listKeyBytes = hexToBytes(listKeyHex);
  let raw: Uint32Array;
  try {
    raw = wasm.path_indices_for_per_list_leaf(listKeyBytes, idx);
  } catch (cause) {
    throw RavenError.invalidQuery(`path_indices_for_per_list_leaf: wasm threw on (idx=${idx})`, {
      cause: String(cause),
    });
  }
  if (raw.length !== TREE_DEPTH) {
    throw RavenError.decodeError(
      `path_indices_for_per_list_leaf: wasm returned ${raw.length} indices (expected ${TREE_DEPTH})`,
    );
  }
  const out: number[] = new Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) {
    out[i] = raw[i];
  }
  return out;
}
