/**
 * The wire a Raven node speaks, and the env the live tier reads, for the tests that frame
 * requests by hand.
 *
 * The live tier used to carry three private copies of this, each with its own version literal,
 * and all three were left behind at envelope 2 while the server moved on. Here it reads the one
 * pin in `wire_schema.ts`, and the local PPOI smoke exercises it on every run, so a wire change
 * reddens an offline test instead of waiting for someone to point the live tier at a node.
 */

import { bearerHeaders } from "../../src/bearer-auth";
import type { InstanceParams } from "../../src/instance-params";
import { EXPECTED_WIRE_SCHEMA_PREFIX, EXPECTED_WIRE_SCHEMA_VERSION } from "./wire_schema";

function setting(name: string): string | undefined {
  const value = process.env[name];
  return value === undefined || value === "" ? undefined : value;
}

/** The node under test. Unset, every live case skips. */
export const LIVE_URL = setting("RAVEN_LIVE_URL")?.replace(/\/$/, "");

/**
 * Optional. The read path takes no credential, so this is only for a node built before reads
 * went public, which answers 401 without one. The SDK ignores it on public routes either way.
 */
export const LIVE_TOKEN = setting("RAVEN_LIVE_TOKEN");

/** The PPOI aggregator the PPOI smoke checks the node against. */
export const LIVE_AGGREGATOR = setting("RAVEN_PIN_UPSTREAM");

/** Instance ids are operator config; the default is the one the shipped example uses. */
const PPOI_PATH_INSTANCE_PREFIX =
  setting("RAVEN_LIVE_PPOI_PATH_INSTANCE_PREFIX") ?? "ppoi-paths-ofac-";

/** The path instance holding one PPOI block. */
export function ppoiPathInstance(block: number): string {
  return `${PPOI_PATH_INSTANCE_PREFIX}${block}`;
}

/** Headers for a hand-rolled request to the node: the credential when one is configured. */
export function liveHeaders(): Record<string, string> {
  return bearerHeaders(LIVE_TOKEN);
}

function readU64(view: DataView, offset: number, label: string): number {
  if (offset + 8 > view.byteLength) {
    throw new Error(`${label}: truncated u64 at offset ${offset} of ${view.byteLength}`);
  }
  const lo = view.getUint32(offset, true);
  const hi = view.getUint32(offset + 4, true);
  if (hi !== 0) {
    throw new Error(`${label}: u64 at offset ${offset} exceeds 2^32 (hi=${hi})`);
  }
  return lo;
}

function readBytes(
  buf: Uint8Array,
  view: DataView,
  offset: number,
  label: string,
): { value: Uint8Array; next: number } {
  const len = readU64(view, offset, label);
  const start = offset + 8;
  const end = start + len;
  if (end > buf.length) {
    throw new Error(`${label}: truncated (need ${end}, have ${buf.length}) at offset ${offset}`);
  }
  return { value: new Uint8Array(buf.subarray(start, end)), next: end };
}

function envelopeOf(buf: Uint8Array, label: string): number {
  if (buf.length < 2) {
    throw new Error(`${label}: ${buf.length} bytes is too short for the schema envelope`);
  }
  return (buf[0] << 8) | buf[1];
}

/** The test-side writer for a mock node. The server writes one version into both fields. */
export function encodeInstanceParams(
  params: Omit<InstanceParams, "envelope" | "wireSchemaVersion">,
  version: number = EXPECTED_WIRE_SCHEMA_VERSION,
  innerVersion: number = version,
): Uint8Array {
  const variant = new TextEncoder().encode(params.variant);
  const vecs = [params.crsBincode, params.shardConfigBincode, params.inspireParamsBincode];
  let total = 4 + 8 + 8 + variant.length + 8;
  for (const v of vecs) total += 8 + v.length;
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  view.setUint16(0, version, false);
  view.setUint16(2, innerVersion, true);
  let off = 4;
  const putU64 = (value: bigint): void => {
    view.setBigUint64(off, value, true);
    off += 8;
  };
  for (const v of vecs) {
    putU64(BigInt(v.length));
    out.set(v, off);
    off += v.length;
  }
  putU64(BigInt(params.entrySize));
  putU64(BigInt(variant.length));
  out.set(variant, off);
  off += variant.length;
  putU64(params.epoch);
  return out;
}

/** `/query` request: `[u16 BE version][one bincode query]`. */
export function versionedQueryBody(query: Uint8Array): Uint8Array {
  const out = new Uint8Array(2 + query.length);
  out.set(EXPECTED_WIRE_SCHEMA_PREFIX, 0);
  out.set(query, 2);
  return out;
}

/** `/batch` request: `[u16 BE version][u64 LE count][concatenated bincode queries]`. */
export function versionedBatchBody(queries: readonly Uint8Array[]): Uint8Array {
  let total = 2 + 8;
  for (const q of queries) total += q.length;
  const out = new Uint8Array(total);
  out.set(EXPECTED_WIRE_SCHEMA_PREFIX, 0);
  new DataView(out.buffer).setBigUint64(2, BigInt(queries.length), true);
  let off = 10;
  for (const q of queries) {
    out.set(q, off);
    off += q.length;
  }
  return out;
}

/** The payload of a versioned `/query` response, refusing any other version. */
export function stripVersionedResponse(buf: Uint8Array, label: string): Uint8Array {
  const envelope = envelopeOf(buf, label);
  if (envelope !== EXPECTED_WIRE_SCHEMA_VERSION) {
    throw new Error(
      `${label}: response is wire schema ${envelope}, this client speaks ${EXPECTED_WIRE_SCHEMA_VERSION}`,
    );
  }
  return buf.subarray(2);
}

/** `/batch` response: `[u16 BE version][u64 LE count]{[u64 LE len][bincode]}*`. */
export function decodeBatchResponse(buf: Uint8Array, label: string): Uint8Array[] {
  const payload = stripVersionedResponse(buf, label);
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const count = readU64(view, 0, label);
  const out: Uint8Array[] = [];
  let off = 8;
  for (let i = 0; i < count; i += 1) {
    const elem = readBytes(payload, view, off, `${label} element ${i}`);
    out.push(elem.value);
    off = elem.next;
  }
  if (off !== payload.length) {
    throw new Error(`${label}: ${payload.length - off} trailing bytes after ${count} elements`);
  }
  return out;
}
