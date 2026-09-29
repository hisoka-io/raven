// No call path puts plaintext BC bytes on the wire. Asserts only the OUTGOING direction; a
// proof's response decode is allowed to fail (the fixture's rows are not path rows).

import { afterEach, beforeAll, describe, expect, it, afterAll } from "vitest";

import { RavenPOINodeInterface, paddedBatchLength } from "../src/index";
import type { ClientPirContext } from "../src/index";

import { loadFixture, makeClientPirContext } from "./helpers/fixture";
import { encodeBatchResponseNodes, encodedBatchCount } from "./helpers/auth_path_stub";
import { forestConfig } from "./helpers/forest";
import { startMockServer, writeBinary, type MockServer } from "./helpers/mock_server";
import { commitmentAt, mountPrefixChannel } from "./helpers/prefix_channel";
import {
  assertNoCommitmentsAnywhere,
  assertNoCommitmentsInPirRequests,
} from "./helpers/private_wire";
import { EXPECTED_WIRE_SCHEMA_PREFIX } from "./helpers/wire_schema";

const TOKEN = "test-token-padded-long-enough-1234";
const MEMBERS = [commitmentAt(0), commitmentAt(1), commitmentAt(2), commitmentAt(3), commitmentAt(4)];
const NON_MEMBERS = [commitmentAt(0x77), commitmentAt(0x88), commitmentAt(0x99)];

describe("privacy across every SDK call path", () => {
  let fixture: ReturnType<typeof loadFixture>;
  let ctx: ClientPirContext;
  let server: MockServer;

  beforeAll(async () => {
    fixture = loadFixture();
    ctx = makeClientPirContext(fixture);
    server = await startMockServer();
  });

  afterAll(async () => {
    if (server) await server.close();
    if (ctx) ctx.session.free();
  });

  afterEach(() => {
    server.reset();
  });

  function sdk(): RavenPOINodeInterface {
    mountPrefixChannel(server, fixture.meta.list_key_hex, { commitments: [...MEMBERS] });
    return new RavenPOINodeInterface({
      captureWireRequests: true,
      ...forestConfig({ endpoint: server.url, listKeyHex: fixture.meta.list_key_hex, ctx }),
      bearerToken: TOKEN,
    });
  }

  it("getPOIsPerList sends no query and no body, whoever is asked about", async () => {
    const client = sdk();
    await client.getPOIsPerList(
      [fixture.meta.list_key_hex],
      [...MEMBERS, ...NON_MEMBERS].map((bc) => ({ blindedCommitment: bc, type: "Shield" as const })),
    );
    const wires = client.lastWireRequests();
    expect(wires.map((w) => w.method)).toEqual(["GET"]);
    expect(wires[0].body.length).toBe(0);
    expect(server.requests.some((r) => r.url.includes("/v1/instance/"))).toBe(false);
    assertNoCommitmentsAnywhere(wires, [...MEMBERS, ...NON_MEMBERS]);
  });

  it("getPOIMerkleProofs client-PIR path leaks no BC bytes", async () => {
    const response = fixture.responsesByIdx.get(0)!;
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, body, res) => {
        writeBinary(
          res,
          encodeBatchResponseNodes(new Array<Uint8Array>(encodedBatchCount(body)).fill(response)),
        );
        return true;
      },
    );
    const client = sdk();
    await client.getPOIMerkleProofs(fixture.meta.list_key_hex, MEMBERS).catch(() => undefined);

    // The K rows for one block travel as ONE padded batch: `assertNoCommitmentsInPirRequests`
    // compares this against the count encoded in the request body, and `toHaveLength(1)` pins
    // that there is a single request, so a regression to one batch per commitment reds both.
    const expectedQueryCount = paddedBatchLength(MEMBERS.length);
    expect(
      assertNoCommitmentsInPirRequests(client.lastWireRequests(), MEMBERS, { expectedQueryCount }),
    ).toHaveLength(1);
    expect(
      assertNoCommitmentsInPirRequests(server.requests, MEMBERS, { expectedQueryCount }),
    ).toHaveLength(1);
    const sessionOnly = server.requests.filter((request) => request.url.endsWith("/session"));
    expect(sessionOnly).toHaveLength(1);
    expect(() =>
      assertNoCommitmentsInPirRequests(sessionOnly, MEMBERS, { expectedQueryCount }),
    ).toThrow(/selected no POST query\/batch requests/);
  });

  // What the node sees of a status call must not reveal how many asked commitments are members.
  it("status requests are the same whatever share of the asked commitments are members", async () => {
    const seen = async (asked: string[]): Promise<string[]> => {
      server.reset();
      const client = sdk();
      await client.getPOIsPerList(
        [fixture.meta.list_key_hex],
        asked.map((bc) => ({ blindedCommitment: bc, type: "Shield" as const })),
      );
      return server.requests.map((r) => `${r.method} ${r.url} ${r.body.length}`);
    };
    const none = await seen(NON_MEMBERS);
    const three = await seen([...MEMBERS.slice(0, 3), ...NON_MEMBERS]);
    expect(three, "same N, different M must look the same or the requests are an oracle").toEqual(
      none,
    );
  });

  it("privacy assertion refuses empty and malformed request sets", () => {
    expect(() =>
      assertNoCommitmentsInPirRequests([], ["11".repeat(32)], {
        expectedQueryCount: 1,
      }),
    ).toThrow(/selected no POST query\/batch requests/);

    const shortBatch = new Uint8Array(9);
    shortBatch.set(EXPECTED_WIRE_SCHEMA_PREFIX);
    expect(() =>
      assertNoCommitmentsInPirRequests(
        [{ url: "/v1/instance/test/batch", method: "POST", body: shortBatch }],
        ["11".repeat(32)],
        { expectedQueryCount: 1 },
      ),
    ).toThrow(/shorter than 10-byte header/);

    expect(() =>
      assertNoCommitmentsInPirRequests(
        [{ url: "/v1/instance/test/batch", method: "POST", body: new Uint8Array(10) }],
        ["11".repeat(32)],
        { expectedQueryCount: 1 },
      ),
    ).toThrow(
      new RegExp(
        `schema prefix.*expected \\[${EXPECTED_WIRE_SCHEMA_PREFIX[0]}, ${EXPECTED_WIRE_SCHEMA_PREFIX[1]}\\]`,
      ),
    );

    const zeroCountBatch = new Uint8Array(10);
    zeroCountBatch.set(EXPECTED_WIRE_SCHEMA_PREFIX);
    expect(() =>
      assertNoCommitmentsInPirRequests(
        [{ url: "/v1/instance/test/batch", method: "POST", body: zeroCountBatch }],
        ["11".repeat(32)],
        { expectedQueryCount: 1 },
      ),
    ).toThrow(/invalid batch query count 0/);

    const undersizedBatch = new Uint8Array(10 + 31);
    undersizedBatch.set(EXPECTED_WIRE_SCHEMA_PREFIX);
    new DataView(undersizedBatch.buffer).setBigUint64(2, 1n, true);
    expect(() =>
      assertNoCommitmentsInPirRequests(
        [{ url: "/v1/instance/test/batch", method: "POST", body: undersizedBatch }],
        ["11".repeat(32)],
        { expectedQueryCount: 1 },
      ),
    ).toThrow(/query payload is 31 bytes/);

    const unevenBatch = new Uint8Array(10 + 65);
    unevenBatch.set(EXPECTED_WIRE_SCHEMA_PREFIX);
    new DataView(unevenBatch.buffer).setBigUint64(2, 2n, true);
    expect(() =>
      assertNoCommitmentsInPirRequests(
        [{ url: "/v1/instance/test/batch", method: "POST", body: unevenBatch }],
        ["11".repeat(32)],
        { expectedQueryCount: 2 },
      ),
    ).toThrow(/payload bytes do not divide/);
  });

  it("the index channel emits GETs with no body", async () => {
    mountPrefixChannel(server, fixture.meta.list_key_hex, { commitments: [] });
    const client = new RavenPOINodeInterface({
      captureWireRequests: true,
      endpoint: server.url,
      bearerToken: TOKEN,
      poiListIndexStore: false,
    });
    await client.syncPoiListIndex(fixture.meta.list_key_hex);
    const wires = client.lastWireRequests();
    expect(wires.map((w) => w.url.replace(/^.*\/v1\/poi\/[0-9a-f]+\//, ""))).toStrictEqual([
      "bc-prefixes?since=0",
    ]);
    for (const wire of wires) {
      expect(wire.method).toBe("GET");
      expect(wire.body.length).toBe(0);
    }
  });
});
