import { containsByteSequence, hexToBytes } from "../../src/index";

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
  if (request.body[0] !== 0 || request.body[1] !== 6) {
    fail(request, `schema prefix is [${request.body[0]}, ${request.body[1]}], expected [0, 6]`);
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
      request.method === "POST" && /^\/v1\/instance\/[^/]+\/(?:query|batch|fanout)$/.test(path)
    );
  });
  if (selected.length === 0) {
    throw new Error("private PIR assertion selected no POST query/batch/fanout requests");
  }
  return selected.map((request) => inspectPirRequest(request, options));
}

export function assertNoCommitmentsInPirRequests(
  requests: readonly TestWireRequest[],
  commitmentHexes: readonly string[],
  options: PirInspectionOptions,
): InspectedPirRequest[] {
  const inspected = inspectPirDataPosts(requests, options);
  for (const { request } of inspected) {
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
  return inspected;
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

function defaultStubQuery(): Uint8Array {
  const query = new Uint8Array(STUB_QUERY_BYTES);
  query.fill(0xa5);
  return query;
}
