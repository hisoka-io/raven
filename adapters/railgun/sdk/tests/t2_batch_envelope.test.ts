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
import {
  EXPECTED_WIRE_SCHEMA_PREFIX,
  EXPECTED_WIRE_SCHEMA_VERSION,
  EXPECTED_WIRE_SCHEMA_VERSION_APPROXIMATE_GADGET,
} from "./helpers/wire_schema";

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

  /** A stub context whose session registers under `schema`, as the wasm stamps it. */
  function ctxSpeaking(schema: number): ReturnType<typeof stubCtx> {
    const ctx = stubCtx();
    return {
      ...ctx,
      wasm: {
        ...ctx.wasm,
        client_packing_keys_versioned: () => new Uint8Array([schema >>> 8, schema & 0xff, 1, 2]),
      },
      entrySize: PATH10_ROW_BYTES,
    };
  }

  function makeSdk(schema: number = EXPECTED_WIRE_SCHEMA_VERSION): RavenPOINodeInterface {
    return new RavenPOINodeInterface({
      ...forestConfig({
        endpoint: server.url,
        listKeyHex: LIST_KEY_HEX,
        ctx: ctxSpeaking(schema),
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

  describe("an instance on the approximate-gadget schema", () => {
    const APPROXIMATE = EXPECTED_WIRE_SCHEMA_VERSION_APPROXIMATE_GADGET;
    const proveAt = (schema: number): Promise<unknown> =>
      makeSdk(schema).getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);

    it("sends the session's schema on the session and the batch and proves its reply", async () => {
      let sessionPrefix: number[] = [];
      let batchPrefix: number[] = [];
      server.routeSession((_req, body, res) => {
        sessionPrefix = Array.from(body.subarray(0, 2));
        res.writeHead(200, { "x-raven-session": "1" });
        res.end("{}");
        return true;
      });
      server.route(
        (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
        (_req, requestBody, res) => {
          batchPrefix = Array.from(requestBody.subarray(0, 2));
          const slot = path10Slot({ bcHex: BC_HEX, nodes: NODES });
          const framed = encodeBatchResponseNodes(
            Array.from({ length: encodedBatchCount(requestBody) }, () => slot),
          );
          framed[1] = APPROXIMATE;
          writeBinary(res, framed);
          return true;
        },
      );
      await expect(proveAt(APPROXIMATE)).resolves.toHaveLength(1);
      expect([sessionPrefix, batchPrefix]).toEqual([
        [0, APPROXIMATE],
        [0, APPROXIMATE],
      ]);
    });

    it("refuses a reply framed for the exact set", async () => {
      serveFramed((framed) => framed);
      await expect(proveAt(APPROXIMATE)).rejects.toThrow(
        new RegExp(`unexpected schema envelope version ${EXPECTED_WIRE_SCHEMA_VERSION}`),
      );
    });

    it("classifies an exact-set node's refusal as StaleAdapter naming both schemas", async () => {
      server.route(
        (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
        (_req, _body, res) => {
          res.writeHead(400, { "x-raven-schema-version": String(EXPECTED_WIRE_SCHEMA_VERSION) });
          res.end();
          return true;
        },
      );
      const thrown = await proveAt(APPROXIMATE).catch((e: unknown) => e);
      expect(RavenError.is(thrown, "StaleAdapter"), String(thrown)).toBe(true);
      if (RavenError.is(thrown, "StaleAdapter")) {
        expect(thrown.context.clientWireSchemaVersion).toBe(APPROXIMATE);
        expect(thrown.context.serverWireSchemaVersion).toBe(EXPECTED_WIRE_SCHEMA_VERSION);
      }
    });

    it("classifies a session refused by an exact-set node as StaleAdapter", async () => {
      server.routeSession((_req, _body, res) => {
        res.writeHead(400, { "x-raven-schema-version": String(EXPECTED_WIRE_SCHEMA_VERSION) });
        res.end();
        return true;
      });
      const thrown = await proveAt(APPROXIMATE).catch((e: unknown) => e);
      expect(RavenError.is(thrown, "StaleAdapter"), String(thrown)).toBe(true);
      if (RavenError.is(thrown, "StaleAdapter")) {
        expect(thrown.context.serverWireSchemaVersion).toBe(EXPECTED_WIRE_SCHEMA_VERSION);
      }
    });

    it("refuses a session on a schema this client does not speak before sending anything", async () => {
      serveFramed((framed) => framed);
      const thrown = await proveAt(APPROXIMATE + 1).catch((e: unknown) => e);
      expect(RavenError.is(thrown, "StaleAdapter"), String(thrown)).toBe(true);
      expect(server.requests.filter((r) => /\/(batch|session)$/.test(r.url))).toHaveLength(0);
    });
  });
});
