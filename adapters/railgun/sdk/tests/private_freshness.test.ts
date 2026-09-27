// Every private reply carries `X-Raven-Freshness`, and a reply below the caller's confidence
// floor is refused. There is no private way to re-ask, and asking anyone in the clear would name
// the note, so a stale path is refused and nothing goes anywhere else.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { RavenError, RavenPOINodeInterface, type StaleDataContext } from "../src/index";
import { encodeBatchResponseNodes, stubCtx } from "./helpers/auth_path_stub";
import { forestConfig } from "./helpers/forest";
import { startMockServer, writeBinary, type MockServer } from "./helpers/mock_server";
import {
  PATH10_ROW_BYTES,
  path10Root,
  path10Siblings,
  path10Slot,
} from "./helpers/path10_row";
import { assertNoCommitmentsAnywhere, assertNoCommitmentsInPirRequests, STUB_QUERY_BYTES } from "./helpers/private_wire";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "ab".repeat(32);
const BC_HEX = "00".repeat(31) + "01";
const PATH10_NODES = path10Siblings(0xab);
const PATH10_ROOT = path10Root(BC_HEX, PATH10_NODES, 0);

const POLICY_ROWS = [
  { label: "fresh", confidence: 0.99, endpoint: false, verdict: "private" },
  { label: "floor equality", confidence: 0.5, endpoint: true, verdict: "private" },
  { label: "stale without upstream", confidence: 0.1, endpoint: false, verdict: "stale" },
  { label: "stale with upstream configured", confidence: 0.1, endpoint: true, verdict: "stale" },
] as const;

describe("private response freshness", () => {
  let adapter: MockServer;
  let upstream: MockServer;

  beforeAll(async () => {
    adapter = await startMockServer();
    upstream = await startMockServer();
  });

  afterAll(async () => {
    await adapter.close();
    await upstream.close();
  });

  afterEach(() => {
    adapter.reset();
    upstream.reset();
  });

  function servePath(freshness: string | null): void {
    adapter.route(
      (req) => req.url?.endsWith("/batch") ?? false,
      (_req, _body, res) => {
        const payload = encodeBatchResponseNodes([path10Slot({ bcHex: BC_HEX, nodes: PATH10_NODES })]);
        if (freshness === null) {
          res.writeHead(200, { "content-type": "application/octet-stream" });
          res.end(Buffer.from(payload));
        } else {
          writeBinary(res, payload, { "x-raven-freshness": freshness });
        }
        return true;
      },
    );
  }

  function sdk(options: { floor?: number; upstream?: boolean } = {}): RavenPOINodeInterface {
    return new RavenPOINodeInterface({
      ...forestConfig({
        endpoint: adapter.url,
        listKeyHex: LIST_KEY_HEX,
        ctx: { ...stubCtx(), entrySize: PATH10_ROW_BYTES },
        placed: [[BC_HEX, 0]],
        // Every path-10 fold requires a pinned root.
        pins: new Map([[0, PATH10_ROOT]]),
      }),
      bearerToken: TOKEN,
      ...(options.floor === undefined ? {} : { freshnessConfidenceFloor: options.floor }),
      ...(options.upstream === true ? { upstreamFallbackEndpoint: upstream.url } : {}),
    });
  }

  async function outcome(client: RavenPOINodeInterface): Promise<{ returned?: unknown; thrown?: unknown }> {
    try {
      return { returned: await client.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]) };
    } catch (thrown) {
      return { thrown };
    }
  }

  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, -0.01, 1.01])(
    "rejects invalid confidence floor %s before I/O",
    (floor) => {
      let thrown: unknown;
      try {
        new RavenPOINodeInterface({
          endpoint: adapter.url,
          bearerToken: TOKEN,
          freshnessConfidenceFloor: floor,
        });
      } catch (error) {
        thrown = error;
      }
      expect(RavenError.is(thrown, "InvalidQuery")).toBe(true);
      expect(String((thrown as Error).message)).toMatch(/freshnessConfidenceFloor.*finite.*\[0,1\]/);
      expect(adapter.requests).toHaveLength(0);
      expect(upstream.requests).toHaveLength(0);
    },
  );

  it.each([
    { floor: 0, confidence: 0.1 },
    { floor: 1, confidence: 1 },
  ])("accepts boundary floor $floor and keeps equality private", async ({ floor, confidence }) => {
    servePath(`lag_blocks=0 applied_height=10 epoch=1 confidence=${confidence}`);
    const { returned } = await outcome(sdk({ floor, upstream: true }));
    expect(returned).toMatchObject([{ leaf: BC_HEX, root: PATH10_ROOT }]);
    expect(upstream.requests).toHaveLength(0);
  });

  it.each(POLICY_ROWS)("t2-auth-path: $label", async (row) => {
    servePath(`lag_blocks=999 applied_height=10 epoch=1 confidence=${row.confidence}`);
    const { returned, thrown } = await outcome(sdk({ floor: 0.5, upstream: row.endpoint }));

    if (row.verdict === "stale") {
      expect(returned).toBeUndefined();
      expect(RavenError.is(thrown, "StaleData")).toBe(true);
      if (RavenError.is(thrown, "StaleData")) {
        const context: StaleDataContext = thrown.context;
        expect(context).toEqual({
          operation: "t2-auth-path",
          lagBlocks: 999,
          appliedHeight: 10,
          epoch: 1,
          confidence: 0.1,
          confidenceFloor: 0.5,
        });
      }
    } else {
      expect(returned).toMatchObject([{ leaf: BC_HEX, root: PATH10_ROOT }]);
    }
    expect(upstream.requests).toHaveLength(0);
    expect(
      assertNoCommitmentsInPirRequests(adapter.requests, [BC_HEX], {
        expectedQueryCount: 1,
        expectedQueryBytes: STUB_QUERY_BYTES,
      }),
    ).toHaveLength(1);
    assertNoCommitmentsAnywhere(adapter.requests, [BC_HEX]);
  });

  it.each([
    { label: "absent", header: null, kind: "StaleAdapter" as const },
    { label: "malformed", header: "confidence=not-a-number", kind: "DecodeError" as const },
  ])("t2-auth-path: $label freshness fails closed", async ({ header, kind }) => {
    servePath(header);
    const { returned, thrown } = await outcome(sdk({ upstream: true }));
    expect(returned).toBeUndefined();
    expect(RavenError.is(thrown, kind)).toBe(true);
    expect(upstream.requests).toHaveLength(0);
  });
});
