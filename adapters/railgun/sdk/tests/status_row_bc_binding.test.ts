// A T1 status row is a verdict about the blinded commitment whose bytes it carries.
// Unpopulated rows are zero-filled and status byte 0 decodes as `Valid`, so a decode
// that ignores the row's BC tail turns an absent record into a spend authorisation.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  RavenError,
  RavenPOINodeInterface,
  hexToBytes,
} from "../src/index";
import { makeRegisterSpy, stubRemoteSessionExports } from "./helpers/register_spy";
import type { ClientPirContext, POIStatus, RavenInspireWasm } from "../src/index";

import { encodeBatchResponseNodes, encodedBatchCount } from "./helpers/auth_path_stub";
import { startMockServer, writeBinary, type MockServer } from "./helpers/mock_server";
import {
  assertNoCommitmentsInPirRequests,
  injectCommitment,
  STUB_QUERY_BYTES,
  stubQueryBundle,
} from "./helpers/private_wire";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "abababababababababababababababababababababababababababababababab";
const BC_AT_IDX_0 = "bc00112233445566778899aabbccddeeff00112233445566778899aabbccdd01";
const BC_AT_IDX_1 = "7f00112233445566778899aabbccddeeff00112233445566778899aabbccdd01";
const BC_AT_IDX_2 = "5a00112233445566778899aabbccddeeff00112233445566778899aabbccdd01";
/** Same BC as index 0 except in its final byte, which a 32 B row has no space for. */
const BC_LAST_BYTE_TWIN = "bc00112233445566778899aabbccddeeff00112233445566778899aabbccdd02";
const STATUS_ROW_BYTES = 32;

/** Row bytes the Rust `PerListStatusEncoder` writes: `[status, bc[0..min(rowBytes-1, 32)]]`. */
function statusRow(statusByte: number, bcHex: string, rowBytes: number): Uint8Array {
  const row = new Uint8Array(rowBytes);
  row[0] = statusByte;
  const tailLen = Math.min(rowBytes - 1, 32);
  row.set(hexToBytes(bcHex).subarray(0, tailLen), 1);
  return row;
}

function passthroughWasm(): RavenInspireWasm {
  return {
    ...stubRemoteSessionExports(),
    build_client_session: () => ({ free: () => undefined }),
    build_seeded_query: () => stubQueryBundle(),
    // Test routes encode the intended plaintext row into the response body directly.
    extract_response: (_session, _crs, _state, response, _entry) => new Uint8Array(response),
    build_instance_params_blob: () => new Uint8Array(0),
    register_client_session: makeRegisterSpy(),
    path_indices_for_leaf: () => new Uint32Array(16),
    path_indices_for_per_list_leaf: () => new Uint32Array(16),
  };
}

function stubCtx(entrySize: number = STATUS_ROW_BYTES): ClientPirContext {
  return {
    wasm: passthroughWasm(),
    session: { free: () => undefined },
    crsBincode: new Uint8Array(0),
    shardConfigBincode: new Uint8Array(0),
    entrySize,
  };
}

function mountStatusRows(server: MockServer, rows: readonly Uint8Array[]): void {
  server.route(
    (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
    (_req, body, res) => {
      const count = encodedBatchCount(body);
      const responses = Array.from({ length: count }, (_unused, slot) =>
        slot < rows.length ? rows[slot] : rows[0],
      );
      writeBinary(res, encodeBatchResponseNodes(responses));
      return true;
    },
  );
}

function mountStatusRoute(server: MockServer, row: Uint8Array): void {
  mountStatusRows(server, [row]);
}

function sdkFor(server: MockServer, entrySize: number = STATUS_ROW_BYTES): RavenPOINodeInterface {
  return new RavenPOINodeInterface({
    endpoint: server.url,
    bearerToken: TOKEN,
    useClientPir: true,
    clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, stubCtx(entrySize)]]),
    bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[BC_AT_IDX_0, 0]])]]),
  });
}

function askStatus(sdk: RavenPOINodeInterface): Promise<Record<string, Record<string, POIStatus>>> {
  return sdk.getPOIsPerList(
    [LIST_KEY_HEX],
    [{ blindedCommitment: BC_AT_IDX_0, type: "Shield" }],
  );
}

describe("T1 status verdict is bound to the requested blinded commitment", () => {
  let server: MockServer;

  beforeAll(async () => {
    server = await startMockServer();
  });

  afterAll(async () => {
    await server.close();
  });

  afterEach(() => {
    server.reset();
  });

  it("refuses an unpopulated zero-filled row instead of reading it as Valid", async () => {
    mountStatusRoute(server, new Uint8Array(STATUS_ROW_BYTES));
    const sdk = sdkFor(server);
    let thrown: unknown;
    let resolved: Record<string, Record<string, POIStatus>> | undefined;
    try {
      resolved = await askStatus(sdk);
    } catch (e) {
      thrown = e;
    }
    expect(resolved).toBeUndefined();
    expect(RavenError.is(thrown, "DecodeError")).toBe(true);
  });

  it("refuses a row carrying another index's blinded commitment", async () => {
    mountStatusRoute(server, statusRow(0, BC_AT_IDX_1, STATUS_ROW_BYTES));
    const sdk = sdkFor(server);
    await expect(askStatus(sdk)).rejects.toThrow(/BC tail/);
  });

  it("refuses a row narrower than the minimum record width", async () => {
    for (const rowBytes of [1, 8, STATUS_ROW_BYTES - 1]) {
      mountStatusRoute(server, statusRow(0, BC_AT_IDX_0, rowBytes));
      const sdk = sdkFor(server);
      await expect(askStatus(sdk)).rejects.toThrow(/status row/);
      server.reset();
    }
  });

  it("binds all 32 tail bytes when the record is wide enough to carry them", async () => {
    const wide = 64;
    mountStatusRoute(server, statusRow(0, BC_LAST_BYTE_TWIN, wide));
    await expect(askStatus(sdkFor(server, wide))).rejects.toThrow(/BC tail/);
  });

  // The narrowest row the Rust encoder builds holds bc[0..31], so the binding a 32 B
  // record can offer stops one byte short of the whole blinded commitment.
  it("cannot bind the final BC byte at the minimum record width", async () => {
    mountStatusRoute(server, statusRow(1, BC_LAST_BYTE_TWIN, STATUS_ROW_BYTES));
    const got = await askStatus(sdkFor(server));
    expect(got[BC_AT_IDX_0][LIST_KEY_HEX]).toBe("ShieldBlocked");
  });

  it("returns the row's status byte when the tail matches the request", async () => {
    const expected: POIStatus[] = ["Valid", "ShieldBlocked", "ProofSubmitted", "Missing"];
    for (let statusByte = 0; statusByte < expected.length; statusByte += 1) {
      mountStatusRoute(server, statusRow(statusByte, BC_AT_IDX_0, STATUS_ROW_BYTES));
      const got = await askStatus(sdkFor(server));
      expect(got[BC_AT_IDX_0][LIST_KEY_HEX]).toBe(expected[statusByte]);
      server.reset();
    }
  });

  it("batches three statuses in order, pads to four, and sends no BC bytes", async () => {
    const rows = [
      statusRow(0, BC_AT_IDX_0, STATUS_ROW_BYTES),
      statusRow(1, BC_AT_IDX_1, STATUS_ROW_BYTES),
      statusRow(2, BC_AT_IDX_2, STATUS_ROW_BYTES),
    ];
    mountStatusRows(server, rows);
    const sdk = new RavenPOINodeInterface({
      endpoint: server.url,
      bearerToken: TOKEN,
      useClientPir: true,
      clientPirContexts: new Map([[`t1Status:${LIST_KEY_HEX}`, stubCtx()]]),
      bcToIdxMaps: new Map([
        [
          LIST_KEY_HEX,
          new Map([
            [BC_AT_IDX_0, 0],
            [BC_AT_IDX_1, 1],
            [BC_AT_IDX_2, 2],
          ]),
        ],
      ]),
    });

    const got = await sdk.getPOIsPerList(
      [LIST_KEY_HEX],
      [BC_AT_IDX_0, BC_AT_IDX_1, BC_AT_IDX_2].map((blindedCommitment) => ({
        blindedCommitment,
        type: "Shield" as const,
      })),
    );

    expect([
      got[BC_AT_IDX_0][LIST_KEY_HEX],
      got[BC_AT_IDX_1][LIST_KEY_HEX],
      got[BC_AT_IDX_2][LIST_KEY_HEX],
    ]).toEqual(["Valid", "ShieldBlocked", "ProofSubmitted"]);
    const requests = sdk.lastWireRequests();
    expect(requests).toHaveLength(1);
    const commitments = [BC_AT_IDX_0, BC_AT_IDX_1, BC_AT_IDX_2];
    const inspected = assertNoCommitmentsInPirRequests(requests, commitments, {
      expectedQueryCount: 4,
      expectedQueryBytes: STUB_QUERY_BYTES,
    });
    expect(inspected).toHaveLength(1);

    const injected = injectCommitment(inspected[0], BC_AT_IDX_0);
    expect(() =>
      assertNoCommitmentsInPirRequests([injected], commitments, {
        expectedQueryCount: 4,
        expectedQueryBytes: STUB_QUERY_BYTES,
      }),
    ).toThrow(/contains raw blinded commitment/);

    const asciiInjected = injectCommitment(inspected[0], BC_AT_IDX_0, "ascii");
    expect(() =>
      assertNoCommitmentsInPirRequests([asciiInjected], commitments, {
        expectedQueryCount: 4,
        expectedQueryBytes: STUB_QUERY_BYTES,
      }),
    ).toThrow(/contains ASCII blinded commitment/);
  });

  it("refuses an unrecognised status byte after binding the row", async () => {
    for (const statusByte of [4, 99, 255]) {
      mountStatusRoute(server, statusRow(statusByte, BC_AT_IDX_0, STATUS_ROW_BYTES));
      await expect(askStatus(sdkFor(server)), `byte ${statusByte}`).rejects.toThrow(
        /unknown POI status byte/,
      );
      server.reset();
    }
  });

  it("accepts a matching tail on a record wider than the tail it can carry", async () => {
    const wide = 64;
    mountStatusRoute(server, statusRow(2, BC_AT_IDX_0, wide));
    const got = await askStatus(sdkFor(server, wide));
    expect(got[BC_AT_IDX_0][LIST_KEY_HEX]).toBe("ProofSubmitted");
  });
});
