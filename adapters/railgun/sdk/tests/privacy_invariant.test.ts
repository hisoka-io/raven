// End-to-end privacy invariant against the real wasm and the Rust-emitted fixture: a proof
// request carries only encrypted queries, KB-scale so a degenerate passthrough cannot pass, and a
// status question sends no query at all.

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { RavenPOINodeInterface, type ClientPirContext } from "../src/index";

import { encodeBatchResponseNodes } from "./helpers/auth_path_stub";
import { loadFixture, makeClientPirContext, type LoadedFixture } from "./helpers/fixture";
import { forestConfig } from "./helpers/forest";
import { startMockServer, type MockServer } from "./helpers/mock_server";
import { commitmentAt, mountPrefixChannel } from "./helpers/prefix_channel";
import {
  assertNoCommitmentsAnywhere,
  assertNoCommitmentsInPirRequests,
  injectCommitment,
} from "./helpers/private_wire";
import { EXPECTED_WIRE_SCHEMA_PREFIX } from "./helpers/wire_schema";

const TOKEN = "test-token-must-be-at-least-16";
const MEMBERS = [commitmentAt(0), commitmentAt(1), commitmentAt(2), commitmentAt(3), commitmentAt(4)];

describe("RavenPOINodeInterface privacy invariant", () => {
  let fixture: LoadedFixture;
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

  beforeEach(() => {
    server.reset();
    mountPrefixChannel(server, fixture.meta.list_key_hex, { commitments: [...MEMBERS] });
    // The fixture's rows are status-shaped, so no proof completes; what was sent is the subject.
    server.route(
      (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
      (_req, _body, res) => {
        res.writeHead(200, {
          "content-type": "application/octet-stream",
          "x-raven-freshness": "lag_blocks=1 applied_height=100 epoch=1 confidence=0.99",
        });
        res.end(Buffer.from(encodeBatchResponseNodes([fixture.responsesByIdx.get(0)!])));
        return true;
      },
    );
  });

  function sdk(): RavenPOINodeInterface {
    return new RavenPOINodeInterface({
      captureWireRequests: true,
      ...forestConfig({ endpoint: server.url, listKeyHex: fixture.meta.list_key_hex, ctx }),
      bearerToken: TOKEN,
    });
  }

  it("getPOIMerkleProofs sends only encrypted queries that carry no commitment", async () => {
    const client = sdk();
    await client.getPOIMerkleProofs(fixture.meta.list_key_hex, MEMBERS).catch(() => undefined);

    const wireRequests = client.lastWireRequests();
    const inspected = assertNoCommitmentsInPirRequests(wireRequests, MEMBERS, {
      expectedQueryCount: 8,
    });
    expect(inspected).toHaveLength(1);
    // A real encrypted query is KB-scale; a plaintext commitment list would be ~80 B each.
    expect(inspected[0].request.body.length).toBeGreaterThan(8 * 1024);
    assertNoCommitmentsAnywhere(wireRequests, MEMBERS);
    const registration = server.requests.find((request) => request.url.endsWith("/session"));
    expect(registration!.body.length).toBeGreaterThan(1024);
    // The WASM stamps this prefix, so this compares against the linked Rust binary.
    expect(registration!.body.subarray(0, 2)).toEqual(new Uint8Array(EXPECTED_WIRE_SCHEMA_PREFIX));

    // Server-side cross-check guards against the SDK capturing the wrong body.
    expect(
      assertNoCommitmentsInPirRequests(server.requests, MEMBERS, { expectedQueryCount: 8 }),
    ).toHaveLength(1);

    const prefixedLeak = injectCommitment(inspected[0], MEMBERS[0], "prefixed-ascii");
    expect(() =>
      assertNoCommitmentsInPirRequests([prefixedLeak], MEMBERS, { expectedQueryCount: 8 }),
    ).toThrow(/contains 0x-prefixed ASCII blinded commitment/);
  });

  it("getPOIsPerList answers members and non-members with no query and no commitment sent", async () => {
    const client = sdk();
    const nonMembers = [commitmentAt(0x77), commitmentAt(0x78)];
    const asked = [MEMBERS[0], MEMBERS[3], ...nonMembers];

    const got = await client.getPOIsPerList(
      [fixture.meta.list_key_hex],
      asked.map((blindedCommitment) => ({ blindedCommitment, type: "Shield" as const })),
    );

    expect(asked.map((bc) => got[bc][fixture.meta.list_key_hex])).toEqual([
      "Valid",
      "Valid",
      "Missing",
      "Missing",
    ]);
    expect(server.requests.map((request) => `${request.method} ${request.url}`)).toEqual([
      `GET /v1/poi/${fixture.meta.list_key_hex}/bc-prefixes?since=0`,
    ]);
    assertNoCommitmentsAnywhere(client.lastWireRequests(), asked);
    assertNoCommitmentsAnywhere(server.requests, asked);
  });
});
