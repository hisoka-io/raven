import {
  containsByteSequence,
  decodeClientPirQueryBundle,
  hexToBytes,
  type RavenInspireWasm,
} from "../../src/index";
import { EXPECTED_WIRE_SCHEMA_PREFIX } from "./wire_schema";

export const STUB_QUERY_BYTES = 64;

export interface TestWireRequest {
  readonly url: string;
  readonly method: string;
  readonly body: Uint8Array;
}

export interface InspectedPirRequest {
  readonly request: TestWireRequest;
  readonly payloadOffset: number;
  readonly queryCount: number;
  readonly queryBytes: number;
}

interface PirInspectionOptions {
  readonly expectedQueryCount: number;
  readonly expectedQueryBytes?: number;
}

function requestPath(url: string): string {
  return new URL(url, "http://test.invalid").pathname;
}

function fail(request: TestWireRequest, message: string): never {
  throw new Error(`private PIR request ${request.method} ${request.url}: ${message}`);
}

function inspectPirRequest(
  request: TestWireRequest,
  options: PirInspectionOptions,
): InspectedPirRequest {
  const path = requestPath(request.url);
  const isBatch = path.endsWith("/batch");
  const headerBytes = isBatch ? 10 : 2;
  if (request.body.length < headerBytes) {
    fail(request, `body is ${request.body.length} bytes, shorter than ${headerBytes}-byte header`);
  }
  const [hi, lo] = EXPECTED_WIRE_SCHEMA_PREFIX;
  if (request.body[0] !== hi || request.body[1] !== lo) {
    fail(
      request,
      `schema prefix is [${request.body[0]}, ${request.body[1]}], expected [${hi}, ${lo}]`,
    );
  }

  let queryCount = 1;
  if (isBatch) {
    const view = new DataView(request.body.buffer, request.body.byteOffset, request.body.byteLength);
    const encodedCount = view.getBigUint64(2, true);
    if (encodedCount === 0n || encodedCount > BigInt(Number.MAX_SAFE_INTEGER)) {
      fail(request, `invalid batch query count ${encodedCount}`);
    }
    queryCount = Number(encodedCount);
  }
  if (queryCount !== options.expectedQueryCount) {
    fail(request, `query count ${queryCount}, expected ${options.expectedQueryCount}`);
  }

  const payloadBytes = request.body.length - headerBytes;
  if (payloadBytes % queryCount !== 0) {
    fail(request, `${payloadBytes} payload bytes do not divide across ${queryCount} queries`);
  }
  const queryBytes = payloadBytes / queryCount;
  if (queryBytes < 32) {
    fail(request, `query payload is ${queryBytes} bytes, shorter than a 32-byte commitment`);
  }
  if (options.expectedQueryBytes !== undefined && queryBytes !== options.expectedQueryBytes) {
    fail(request, `query payload is ${queryBytes} bytes, expected ${options.expectedQueryBytes}`);
  }
  return { request, payloadOffset: headerBytes, queryCount, queryBytes };
}

export function inspectPirDataPosts(
  requests: readonly TestWireRequest[],
  options: PirInspectionOptions,
): InspectedPirRequest[] {
  const selected = requests.filter((request) => {
    const path = requestPath(request.url);
    return (
      request.method === "POST" && /^\/v1\/instance\/[^/]+\/(?:query|batch)$/.test(path)
    );
  });
  if (selected.length === 0) {
    throw new Error("private PIR assertion selected no POST query/batch requests");
  }
  return selected.map((request) => inspectPirRequest(request, options));
}

function assertBodyCarriesNoCommitment(
  request: TestWireRequest,
  commitmentHexes: readonly string[],
): void {
  for (const commitmentHex of commitmentHexes) {
    const raw = hexToBytes(commitmentHex);
    const ascii = new TextEncoder().encode(commitmentHex);
    const prefixedAscii = new TextEncoder().encode(`0x${commitmentHex}`);
    if (containsByteSequence(request.body, raw)) {
      fail(request, `contains raw blinded commitment ${commitmentHex}`);
    }
    if (containsByteSequence(request.body, prefixedAscii)) {
      fail(request, `contains 0x-prefixed ASCII blinded commitment ${commitmentHex}`);
    }
    if (containsByteSequence(request.body, ascii)) {
      fail(request, `contains ASCII blinded commitment ${commitmentHex}`);
    }
  }
}

export function assertNoCommitmentsInPirRequests(
  requests: readonly TestWireRequest[],
  commitmentHexes: readonly string[],
  options: PirInspectionOptions,
): InspectedPirRequest[] {
  const inspected = inspectPirDataPosts(requests, options);
  for (const { request } of inspected) {
    assertBodyCarriesNoCommitment(request, commitmentHexes);
  }
  return inspected;
}

/**
 * The same leak check over EVERY request, not only the instance query paths.
 *
 * `inspectPirDataPosts` narrows to `/v1/instance/<id>/(query|batch)` and throws on an
 * empty selection, and every caller passes an exact `expectedQueryCount` — so it cannot be
 * widened without changing what those callers assert. Pin resolution talks to a different host
 * on a different path, which means the narrow helper filters those requests straight back out
 * and structurally cannot fail on a leak there. This is the sibling that can.
 *
 * Deliberately has no expected count: it asserts an absence over whatever was sent, so it stays
 * correct when a path sends nothing at all.
 */
export function assertNoCommitmentsAnywhere(
  requests: readonly TestWireRequest[],
  commitmentHexes: readonly string[],
): void {
  for (const request of requests) {
    assertBodyCarriesNoCommitment(request, commitmentHexes);
  }
}

export function injectCommitment(
  inspected: InspectedPirRequest,
  commitmentHex: string,
  encoding: "raw" | "ascii" | "prefixed-ascii" = "raw",
): TestWireRequest {
  const commitment =
    encoding === "raw"
      ? hexToBytes(commitmentHex)
      : new TextEncoder().encode(`${encoding === "prefixed-ascii" ? "0x" : ""}${commitmentHex}`);
  if (commitment.length > inspected.queryBytes) {
    fail(
      inspected.request,
      `cannot inject ${commitment.length} bytes into ${inspected.queryBytes}-byte query`,
    );
  }
  const body = new Uint8Array(inspected.request.body);
  body.set(commitment, inspected.payloadOffset);
  return { ...inspected.request, body };
}

export function stubQueryBundle(queryBytes: Uint8Array = defaultStubQuery()): Uint8Array {
  const out = new Uint8Array(16 + queryBytes.length);
  const view = new DataView(out.buffer);
  view.setBigUint64(8, BigInt(queryBytes.length), true);
  out.set(queryBytes, 16);
  return out;
}

/** A stub query naming its target in its first 8 bytes, so a mock answers per row as a node does
 *  rather than per slot, which the SDK shuffles. */
export function targetNamingQueryBundle(target: bigint | number): Uint8Array {
  const query = defaultStubQuery();
  new DataView(query.buffer).setBigUint64(0, BigInt(target), true);
  return stubQueryBundle(query);
}

/** Targets named by a batch of `targetNamingQueryBundle` queries, in wire order. */
export function namedBatchTargets(body: Uint8Array): number[] {
  const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
  const count = Number(view.getBigUint64(2, true));
  return Array.from({ length: count }, (_unused, slot) =>
    Number(view.getBigUint64(10 + slot * STUB_QUERY_BYTES, true)),
  );
}

function defaultStubQuery(): Uint8Array {
  const query = new Uint8Array(STUB_QUERY_BYTES);
  query.fill(0xa5);
  return query;
}

/** `wasm` with every query it builds remembered by its bytes, so a mock can answer an encrypted
 *  batch per target, as a node does, although the SDK shuffles its slots. */
export function targetRecordingWasm(wasm: RavenInspireWasm): {
  wasm: RavenInspireWasm;
  targetsOf: (batchBody: Uint8Array) => (number | undefined)[];
} {
  const targets = new Map<string, number>();
  const recording: RavenInspireWasm = {
    ...wasm,
    build_seeded_query: (session, shardConfig, target) => {
      const bundle = wasm.build_seeded_query(session, shardConfig, target);
      const { queryBytes } = decodeClientPirQueryBundle(bundle);
      targets.set(Buffer.from(queryBytes).toString("base64"), Number(target));
      return bundle;
    },
  };
  const targetsOf = (batchBody: Uint8Array): (number | undefined)[] => {
    const view = new DataView(batchBody.buffer, batchBody.byteOffset, batchBody.byteLength);
    const count = Number(view.getBigUint64(2, true));
    const width = (batchBody.length - 10) / count;
    return Array.from({ length: count }, (_unused, slot) =>
      targets.get(
        Buffer.from(batchBody.subarray(10 + slot * width, 10 + (slot + 1) * width)).toString(
          "base64",
        ),
      ),
    );
  };
  return { wasm: recording, targetsOf };
}
