// A wallet builds its PIR context from these two exports alone, so a node that drifted, lied about
// lengths or failed must be refused here by kind, never handed to the WASM.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { RavenError, decodeInstanceParams, fetchInstanceParams } from "../src/index";
import { encodeInstanceParams } from "./helpers/live_wire";
import { startMockServer, writeBinary, writeError, type MockServer } from "./helpers/mock_server";
import { shardConfigBincode } from "./helpers/shard_config";
import { EXPECTED_WIRE_SCHEMA_VERSION } from "./helpers/wire_schema";

const PARAMS = {
  crsBincode: new Uint8Array([1, 2, 3, 4]),
  shardConfigBincode: shardConfigBincode(65_536, 512),
  inspireParamsBincode: new Uint8Array([5, 6]),
  entrySize: 512,
  variant: "InspiRING",
  epoch: 2n ** 40n + 7n,
};

function caught(f: () => unknown): unknown {
  try {
    f();
  } catch (e) {
    return e;
  }
  return undefined;
}

describe("decodeInstanceParams", () => {
  it("round-trips what the server writes", () => {
    const decoded = decodeInstanceParams(encodeInstanceParams(PARAMS));
    expect(decoded).toEqual({
      envelope: EXPECTED_WIRE_SCHEMA_VERSION,
      wireSchemaVersion: EXPECTED_WIRE_SCHEMA_VERSION,
      ...PARAMS,
    });
  });

  it("reads a body that sits at an offset inside a larger buffer", () => {
    const body = encodeInstanceParams(PARAMS);
    const padded = new Uint8Array(body.length + 7);
    padded.set(body, 7);
    expect(decodeInstanceParams(padded.subarray(7)).epoch).toBe(PARAMS.epoch);
  });

  it("refuses another envelope as StaleAdapter naming the served version", () => {
    const e = caught(() => decodeInstanceParams(encodeInstanceParams(PARAMS, EXPECTED_WIRE_SCHEMA_VERSION - 1)));
    expect(RavenError.is(e, "StaleAdapter"), String(e)).toBe(true);
    expect((e as RavenError).message).toBe(
      `instance params: envelope is wire schema ${EXPECTED_WIRE_SCHEMA_VERSION - 1}, ` +
        `this client speaks ${EXPECTED_WIRE_SCHEMA_VERSION}`,
    );
    expect((e as RavenError).context).toEqual({
      serverWireSchemaVersion: EXPECTED_WIRE_SCHEMA_VERSION - 1,
      clientWireSchemaVersion: EXPECTED_WIRE_SCHEMA_VERSION,
    });
  });

  it("refuses a body whose inner version disagrees with its envelope", () => {
    const body = encodeInstanceParams(PARAMS, EXPECTED_WIRE_SCHEMA_VERSION, EXPECTED_WIRE_SCHEMA_VERSION + 1);
    const e = caught(() => decodeInstanceParams(body));
    expect(RavenError.is(e, "StaleAdapter"), String(e)).toBe(true);
    expect((e as RavenError).message).toContain(`body declares wire schema ${EXPECTED_WIRE_SCHEMA_VERSION + 1}`);
  });

  it.each([
    ["an empty body", () => new Uint8Array(), "too short for the schema envelope"],
    ["a body cut after the envelope", () => encodeInstanceParams(PARAMS).subarray(0, 3), "too short for the inner version"],
    ["a body cut inside the crs", () => encodeInstanceParams(PARAMS).subarray(0, 14), "crs: truncated (need 16, have 14)"],
    ["a body missing its last epoch byte", () => encodeInstanceParams(PARAMS).subarray(0, encodeInstanceParams(PARAMS).length - 1), "epoch must end the body"],
    [
      "a body with a trailing byte",
      () => {
        const body = encodeInstanceParams(PARAMS);
        const out = new Uint8Array(body.length + 1);
        out.set(body);
        return out;
      },
      "epoch must end the body",
    ],
    [
      "a length past 2^32",
      () => {
        const body = encodeInstanceParams(PARAMS);
        new DataView(body.buffer).setUint32(8, 1, true);
        return body;
      },
      "crs: u64 at offset 4 exceeds 2^32 (hi=1)",
    ],
    [
      "a variant that is not UTF-8",
      () => encodeInstanceParams({ ...PARAMS, variant: "\u00e9" }).map((b) => (b === 0xc3 ? 0xff : b)),
      "variant is not UTF-8",
    ],
  ] as const)("refuses %s as DecodeError", (_what, body, message) => {
    const e = caught(() => decodeInstanceParams(body()));
    expect(RavenError.is(e, "DecodeError"), String(e)).toBe(true);
    expect((e as RavenError).message).toContain(message);
  });
});

describe("fetchInstanceParams", () => {
  let node: MockServer;

  beforeAll(async () => {
    node = await startMockServer();
  });
  afterAll(async () => {
    await node.close();
  });
  afterEach(() => {
    node.reset();
  });

  it("GETs the instance's params route, escaping the id, and decodes the body", async () => {
    node.route(
      (req) => req.method === "GET",
      (_req, _body, res) => {
        writeBinary(res, encodeInstanceParams(PARAMS));
        return true;
      },
    );
    const params = await fetchInstanceParams({ endpoint: `${node.url}/`, instanceId: "ppoi paths/0" });
    expect(params.crsBincode).toEqual(PARAMS.crsBincode);
    expect(params.epoch).toBe(PARAMS.epoch);
    expect(node.requests.map((r) => [r.method, r.url, r.body.length])).toEqual([
      ["GET", "/v1/instance/ppoi%20paths%2F0/params", 0],
    ]);
    expect(node.requests[0].headers.authorization).toBeUndefined();
  });

  it("sends the credential only when one is given", async () => {
    node.route(
      () => true,
      (_req, _body, res) => {
        writeBinary(res, encodeInstanceParams(PARAMS));
        return true;
      },
    );
    await fetchInstanceParams({ endpoint: node.url, instanceId: "ppoi-paths-ofac-0", bearerToken: "t0ken" });
    expect(node.requests[0].headers.authorization).toBe("Bearer t0ken");
  });

  it("reports a non-2xx answer as ServerError with its status and URL", async () => {
    node.route(
      () => true,
      (_req, _body, res) => {
        writeError(res, 503, "not ready");
        return true;
      },
    );
    const e = await fetchInstanceParams({ endpoint: node.url, instanceId: "ppoi-paths-ofac-3" }).catch((x: unknown) => x);
    expect(RavenError.is(e, "ServerError"), String(e)).toBe(true);
    expect((e as RavenError).context).toEqual({
      url: `${node.url}/v1/instance/ppoi-paths-ofac-3/params`,
      status: 503,
    });
  });

  it("reports an unreadable body with the URL it came from", async () => {
    node.route(
      () => true,
      (_req, _body, res) => {
        writeBinary(res, encodeInstanceParams(PARAMS, EXPECTED_WIRE_SCHEMA_VERSION + 1));
        return true;
      },
    );
    const e = await fetchInstanceParams({ endpoint: node.url, instanceId: "a" }).catch((x: unknown) => x);
    expect(RavenError.is(e, "StaleAdapter"), String(e)).toBe(true);
    expect((e as RavenError).context).toMatchObject({
      url: `${node.url}/v1/instance/a/params`,
      serverWireSchemaVersion: EXPECTED_WIRE_SCHEMA_VERSION + 1,
    });
  });

  it("reports a failed request and a missed deadline as Network", async () => {
    const refused = await fetchInstanceParams({
      endpoint: node.url,
      instanceId: "a",
      fetchImpl: async () => {
        throw new TypeError("fetch failed");
      },
    }).catch((x: unknown) => x);
    expect(RavenError.is(refused, "Network"), String(refused)).toBe(true);

    const stalled = await fetchInstanceParams({
      endpoint: node.url,
      instanceId: "a",
      requestTimeoutMs: 20,
      fetchImpl: () => new Promise<Response>(() => undefined),
    }).catch((x: unknown) => x);
    expect(RavenError.is(stalled, "Network"), String(stalled)).toBe(true);
  });
});
