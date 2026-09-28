/** A PIR instance's public parameters, from `GET /v1/instance/:id/params`. */

import { bearerHeaders } from "./bearer-auth";
import { RavenError } from "./errors";
import { WIRE_SCHEMA_VERSION } from "./raven-poi-node-interface";
import { checkedRequestTimeoutMs, fetchWithDeadline } from "./request-deadline";

/** `InstanceParams` as the server serializes it; the byte fields feed `loadClientPirContext`. */
export interface InstanceParams {
  readonly envelope: number;
  readonly wireSchemaVersion: number;
  readonly crsBincode: Uint8Array;
  readonly shardConfigBincode: Uint8Array;
  readonly inspireParamsBincode: Uint8Array;
  readonly entrySize: number;
  readonly variant: string;
  readonly epoch: bigint;
}

const LABEL = "instance params";

function readU64(view: DataView, offset: number, label: string): number {
  if (offset + 8 > view.byteLength) {
    throw RavenError.decodeError(`${label}: truncated u64 at offset ${offset} of ${view.byteLength}`);
  }
  const lo = view.getUint32(offset, true);
  const hi = view.getUint32(offset + 4, true);
  if (hi !== 0) {
    throw RavenError.decodeError(`${label}: u64 at offset ${offset} exceeds 2^32 (hi=${hi})`);
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
    throw RavenError.decodeError(
      `${label}: truncated (need ${end}, have ${buf.length}) at offset ${offset}`,
    );
  }
  return { value: new Uint8Array(buf.subarray(start, end)), next: end };
}

function staleSchema(message: string, served: number): RavenError {
  return RavenError.staleAdapter(message, {
    serverWireSchemaVersion: served,
    clientWireSchemaVersion: WIRE_SCHEMA_VERSION,
  });
}

/**
 * `[u16 BE envelope][u16 LE wire_schema_version][Vec crs][Vec shard_config][Vec inspire_params]
 * [u64 entry_size][String variant][u64 epoch]`, every length and integer little-endian. Both
 * version fields are checked, the envelope first, as `StaleAdapter` naming the served version:
 * that is the first thing to know about a node that has not been redeployed.
 */
export function decodeInstanceParams(buf: Uint8Array): InstanceParams {
  if (buf.length < 2) {
    throw RavenError.decodeError(`${LABEL}: ${buf.length} bytes is too short for the schema envelope`);
  }
  const envelope = (buf[0] << 8) | buf[1];
  if (envelope !== WIRE_SCHEMA_VERSION) {
    throw staleSchema(
      `${LABEL}: envelope is wire schema ${envelope}, this client speaks ${WIRE_SCHEMA_VERSION}`,
      envelope,
    );
  }
  if (buf.length < 4) {
    throw RavenError.decodeError(`${LABEL}: ${buf.length} bytes is too short for the inner version`);
  }
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const wireSchemaVersion = view.getUint16(2, true);
  if (wireSchemaVersion !== WIRE_SCHEMA_VERSION) {
    throw staleSchema(
      `${LABEL}: body declares wire schema ${wireSchemaVersion}, this client speaks ${WIRE_SCHEMA_VERSION}`,
      wireSchemaVersion,
    );
  }
  const crs = readBytes(buf, view, 4, `${LABEL} crs`);
  const shard = readBytes(buf, view, crs.next, `${LABEL} shard config`);
  const inspire = readBytes(buf, view, shard.next, `${LABEL} inspire params`);
  const entrySize = readU64(view, inspire.next, `${LABEL} entry size`);
  const variant = readBytes(buf, view, inspire.next + 8, `${LABEL} variant`);
  if (variant.next + 8 !== buf.length) {
    throw RavenError.decodeError(
      `${LABEL}: epoch must end the body at ${variant.next + 8}, body is ${buf.length} bytes`,
    );
  }
  const epoch =
    (BigInt(view.getUint32(variant.next + 4, true)) << 32n) |
    BigInt(view.getUint32(variant.next, true));
  let variantName: string;
  try {
    variantName = new TextDecoder("utf-8", { fatal: true }).decode(variant.value);
  } catch {
    throw RavenError.decodeError(`${LABEL}: variant is not UTF-8`);
  }
  return {
    envelope,
    wireSchemaVersion,
    crsBincode: crs.value,
    shardConfigBincode: shard.value,
    inspireParamsBincode: inspire.value,
    entrySize,
    variant: variantName,
    epoch,
  };
}

export interface FetchInstanceParamsOptions {
  /** The Raven node, without a trailing path. */
  readonly endpoint: string;
  readonly instanceId: string;
  /** Sent only when set; the params route is public on current nodes. */
  readonly bearerToken?: string;
  readonly fetchImpl?: typeof fetch;
  /** Deadline from request to last body byte; 60 000 ms by default. */
  readonly requestTimeoutMs?: number;
}

/** Fetches and decodes one instance's params. A failed request is `Network`, a non-2xx answer
 *  `ServerError` with its status, and a body this client cannot read `DecodeError` or
 *  `StaleAdapter`, each carrying the URL. */
export async function fetchInstanceParams(options: FetchInstanceParamsOptions): Promise<InstanceParams> {
  const fetchImpl = fetchWithDeadline(
    options.fetchImpl ?? fetch,
    checkedRequestTimeoutMs(options.requestTimeoutMs),
  );
  const url =
    `${options.endpoint.replace(/\/$/, "")}/v1/instance/` +
    `${encodeURIComponent(options.instanceId)}/params`;
  const headers = bearerHeaders(options.bearerToken);
  let response: Response;
  let body: Uint8Array;
  try {
    response = await fetchImpl(url, { headers });
    body = new Uint8Array(await response.arrayBuffer());
  } catch (cause) {
    throw RavenError.network(`${LABEL} ${options.instanceId}`, { url, cause: String(cause) });
  }
  if (!response.ok) {
    throw RavenError.serverError(`${LABEL} ${options.instanceId}: HTTP ${response.status}`, {
      url,
      status: response.status,
    });
  }
  try {
    return decodeInstanceParams(body);
  } catch (e) {
    if (RavenError.is(e, "StaleAdapter")) {
      throw RavenError.staleAdapter(e.message, { ...e.context, url });
    }
    if (RavenError.is(e, "DecodeError")) {
      throw RavenError.decodeError(e.message, { url });
    }
    throw e;
  }
}
