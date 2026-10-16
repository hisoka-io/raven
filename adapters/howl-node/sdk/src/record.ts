import { HowlError } from "./errors.js";

/** How the wallet represents a BN254 field element: Howl passes `Fr.fromBuffer` / `toBuffer`. */
export interface FieldCodec<F> {
  /** 32 bytes big-endian to the wallet's element. */
  fromBytes(bytes: Uint8Array): F;
  /** The element as 32 bytes big-endian. */
  toBytes(value: F): Uint8Array;
}

/** Field elements as `bigint`, for callers without a field type of their own. */
export const bigintField: FieldCodec<bigint> = {
  fromBytes(bytes) {
    let value = 0n;
    for (const byte of bytes) value = (value << 8n) | BigInt(byte);
    return value;
  },
  toBytes(value) {
    const out = new Uint8Array(32);
    let rest = value;
    for (let i = 31; i >= 0; i--) {
      out[i] = Number(rest & 0xffn);
      rest >>= 8n;
    }
    if (rest !== 0n || value < 0n) throw new RangeError("value does not fit 32 bytes");
    return out;
  },
};

export const RECORD_KIND_SELF = 0;
export const RECORD_KIND_INCOMING = 1;
export const HOWL_NOTE_LAYOUT_VERSION = 1;
export const HOWL_NOTE_RECORD_BYTES = 246;
export const HOWL_NOTE_CELL_BYTES = 256;
export const COMMITMENT_PREFIX_BYTES = 16;
export const CIPHERTEXT_KEPT_WORDS = 5;

/** One discovery cell, decoded: the shape of Howl's `HowlNoteRecord`. */
export interface HowlNoteRecord<F> {
  readonly layoutVersion: number;
  readonly recordKind: 0 | 1;
  readonly leafIndex: number;
  readonly commitmentPrefix: Uint8Array;
  readonly ephemeralPkX: F;
  readonly cekWrap: F;
  readonly ciphertextKept: readonly F[];
}

/**
 * The record a probe returns for a tag with no match: well-formed, at the genesis position,
 * all zero, so it opens under no key.
 */
export function missRecord<F>(field: FieldCodec<F>): HowlNoteRecord<F> {
  const zero = () => field.fromBytes(new Uint8Array(32));
  return {
    layoutVersion: HOWL_NOTE_LAYOUT_VERSION,
    recordKind: RECORD_KIND_INCOMING,
    leafIndex: 0,
    commitmentPrefix: new Uint8Array(COMMITMENT_PREFIX_BYTES),
    ephemeralPkX: zero(),
    cekWrap: zero(),
    ciphertextKept: Array.from({ length: CIPHERTEXT_KEPT_WORDS }, zero),
  };
}

// howl-note-v1 offsets, frozen by the cell layout both sides decode.
const OFF_KIND = 1;
const OFF_LEAF_INDEX = 2;
const OFF_COMMITMENT_PREFIX = 6;
const OFF_EPH_X = 22;
const OFF_CEK_WRAP = 54;
const OFF_CIPHERTEXT = 86;
const FIELD_BYTES = 32;

/**
 * Decode a 256-byte `howl-note-v1` cell read at `position`. The table is positional, so a cell
 * whose own leaf index differs from the position it was read at is refused.
 */
export function decodeCell<F>(
  cell: Uint8Array,
  position: number,
  field: FieldCodec<F>,
): HowlNoteRecord<F> {
  const fail = (why: string): never => {
    throw new HowlError("Protocol", `cell at ${position}: ${why}`);
  };
  if (cell.length !== HOWL_NOTE_CELL_BYTES) fail(`${cell.length} bytes`);
  const layoutVersion = cell[0];
  if (layoutVersion !== HOWL_NOTE_LAYOUT_VERSION) fail(`layout version ${layoutVersion}`);
  const kind = cell[OFF_KIND];
  if (kind !== RECORD_KIND_SELF && kind !== RECORD_KIND_INCOMING) fail(`record kind ${kind}`);
  for (let i = HOWL_NOTE_RECORD_BYTES; i < HOWL_NOTE_CELL_BYTES; i++) {
    if (cell[i] !== 0) fail(`padding is non-zero at byte ${i}`);
  }
  const leafIndex = new DataView(cell.buffer, cell.byteOffset, cell.byteLength).getUint32(
    OFF_LEAF_INDEX,
    false,
  );
  if (leafIndex !== position) fail(`carries leaf index ${leafIndex}`);
  const word = (offset: number): F => field.fromBytes(cell.slice(offset, offset + FIELD_BYTES));
  const ciphertextKept: F[] = [];
  for (let i = 0; i < CIPHERTEXT_KEPT_WORDS; i++) {
    ciphertextKept.push(word(OFF_CIPHERTEXT + i * FIELD_BYTES));
  }
  return {
    layoutVersion,
    recordKind: kind as 0 | 1,
    leafIndex,
    commitmentPrefix: cell.slice(OFF_COMMITMENT_PREFIX, OFF_COMMITMENT_PREFIX + COMMITMENT_PREFIX_BYTES),
    ephemeralPkX: word(OFF_EPH_X),
    cekWrap: word(OFF_CEK_WRAP),
    ciphertextKept,
  };
}
