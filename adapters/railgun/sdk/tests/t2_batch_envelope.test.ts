// The batch reply's framing on the path proof: `[u16 BE version][u64 LE count][{u64 LE len,
// bytes}*]`. The stub context extracts a slot's bytes unchanged, so a version the SDK failed to
// check would decode into a valid proof, and each refusal below is the envelope's own.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { RavenError, RavenPOINodeInterface } from "../src/index";
import { TOKEN, encodeBatchResponseNodes, encodedBatchCount, stubCtx } from "./helpers/auth_path_stub";
import { forestConfig } from "./helpers/forest";
import { startMockServer, writeBinary, type MockServer } from "./helpers/mock_server";
import {
  PATH10_ROW_BYTES,
  path10Root,
  path10Siblings,
  path10Slot,
} from "./helpers/path10_row";
import { EXPECTED_WIRE_SCHEMA_PREFIX, EXPECTED_WIRE_SCHEMA_VERSION } from "./helpers/wire_schema";

const LIST_KEY_HEX = "42".repeat(32);
const BC_HEX = "0bc1".repeat(16);
const NODES = path10Siblings(0x5c);

describe("path proof batch envelope", () => {
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

  /** Answers every slot with the one real slot, framed by `frame`. */
  function serveFramed(frame: (framed: Uint8Array) => Uint8Array): void {
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, requestBody, res) => {
        const slot = path10Slot({ bcHex: BC_HEX, nodes: NODES });
        const framed = encodeBatchResponseNodes(
          Array.from({ length: encodedBatchCount(requestBody) }, () => slot),
        );
        writeBinary(res, frame(framed));
        return true;
      },
    );
  }

  function makeSdk(): RavenPOINodeInterface {
    return new RavenPOINodeInterface({
      ...forestConfig({
        endpoint: server.url,
        listKeyHex: LIST_KEY_HEX,
        ctx: { ...stubCtx(), entrySize: PATH10_ROW_BYTES },
        placed: [[BC_HEX, 3]],
        pins: new Map([[0, path10Root(BC_HEX, NODES, 3)]]),
      }),
      bearerToken: TOKEN,
    });
  }

  const prove = (): Promise<unknown> => makeSdk().getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);

  it("proves a well-framed reply, so every refusal below is the framing's", async () => {
    serveFramed((framed) => framed);
    await expect(prove()).resolves.toHaveLength(1);
  });

  it("refuses an unknown schema envelope version instead of eating two payload bytes", async () => {
    // Deleting the version branch of `stripSchemaEnvelope` leaves this reply decodable into a
    // proof, so only this message tells the guard ran.
    serveFramed((framed) => {
      framed[1] = EXPECTED_WIRE_SCHEMA_VERSION + 1;
      return framed;
    });
    try {
      await prove();
      expect.fail("an unknown envelope version must not decode");
    } catch (e) {
      expect(RavenError.is(e, "DecodeError")).toBe(true);
      expect(String((e as Error).message)).toMatch(
        new RegExp(`unexpected schema envelope version ${EXPECTED_WIRE_SCHEMA_VERSION + 1}`),
      );
    }
  });

  it("refuses a previous-schema prefix before WASM extraction", async () => {
    serveFramed((framed) => {
      framed[1] = 2;
      return framed;
    });
    await expect(prove()).rejects.toThrow(/unexpected schema envelope version 2/);
  });

  it("refuses trailing bytes after a complete batch response", async () => {
    serveFramed((framed) => {
      const overlong = new Uint8Array(framed.length + 1);
      overlong.set(framed);
      overlong[overlong.length - 1] = 0xa5;
      return overlong;
    });
    await expect(prove()).rejects.toThrow(/trailing bytes/);
  });

  it("still fails closed when the envelope is stripped entirely", async () => {
    serveFramed((framed) => framed.subarray(2));
    await expect(prove()).rejects.toThrow();
  });

  it("sends the current schema and classifies an old v2 server refusal with both versions", async () => {
    let requestPrefix: number[] = [];
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, body, res) => {
        requestPrefix = Array.from(body.subarray(0, 2));
        res.writeHead(400, { "x-raven-schema-version": "2" });
        res.end();
        return true;
      },
    );
    let thrown: unknown;
    try {
      await prove();
    } catch (error) {
      thrown = error;
    }

    expect(requestPrefix).toEqual([...EXPECTED_WIRE_SCHEMA_PREFIX]);
    expect(RavenError.is(thrown, "StaleAdapter")).toBe(true);
    if (RavenError.is(thrown, "StaleAdapter")) {
      expect(thrown.context.clientWireSchemaVersion).toBe(EXPECTED_WIRE_SCHEMA_VERSION);
      expect(thrown.context.serverWireSchemaVersion).toBe(2);
    }
  });
});
