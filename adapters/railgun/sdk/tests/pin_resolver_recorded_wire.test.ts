// The pin resolver and the interface driven over answers a public PPOI aggregator actually gave,
// saved verbatim under fixtures/ppoi-aggregator/. Each request the SDK sends must equal the
// recorded request byte for byte before the recorded answer is returned, so this pins the wire
// contract in both directions with no network: the stubbed hosts are `.invalid`, which cannot
// resolve, and anything else may only reach the in-process mock node.

import { readFileSync } from "node:fs";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  LEAVES_PER_PPOI_BLOCK,
  PIN_TAIL_WINDOW,
  RavenError,
  RavenPOINodeInterface,
  UpstreamPinResolver,
  type ClientPirContext,
  type MerkleProof,
} from "../src/index";
import { TOKEN, stubCtx } from "./helpers/auth_path_stub";
import { startMockServer, type MockServer } from "./helpers/mock_server";
import { PATH10_ROW_BYTES, mountPath10Route } from "./helpers/path10_row";
import { EXPECTED_WIRE_SCHEMA_VERSION } from "./helpers/wire_schema";

const AGGREGATOR = "https://aggregator.invalid";
const OTHER_UPSTREAM = "https://upstream.invalid";
const MAINNET = 1;
const TXID_VERSION = "V2_PoseidonMerkle";
const OFAC_LIST_KEY = "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";
const UNSERVED_LIST_KEY = `${"00".repeat(31)}c2`;
const BLOCK0_LAST_INDEX = LEAVES_PER_PPOI_BLOCK - 1;
const STALE_FRESHNESS = "lag_blocks=999 applied_height=10 epoch=1 confidence=0.10";

const FIXTURES = new URL("./fixtures/ppoi-aggregator/", import.meta.url);

function recorded(name: string): string {
  return readFileSync(new URL(name, FIXTURES), "utf8");
}

interface Exchange {
  readonly request: string;
  readonly response: string;
  readonly status: number;
}

function exchange(name: string, status = 200): Exchange {
  return {
    request: recorded(`${name}.request.json`),
    response: recorded(`${name}.response.json`),
    status,
  };
}

const BLOCK0_POINT = exchange("01-ppoi_poi_events");
const TAIL_POINT = exchange("02-ppoi_poi_events");
const NODE_STATUS = exchange("03-ppoi_node_status");
const TAIL_EVENTS = exchange("04-ppoi_poi_events");
const UNSERVED_LIST = exchange("09-ppoi_poi_events", 400);

const BLOCK0_ROOT = (
  JSON.parse(BLOCK0_POINT.response) as { result: { validatedMerkleroot: string }[] }
).result[0].validatedMerkleroot;
const BLOCK0_PROOF = (
  JSON.parse(recorded("08-ppoi_merkle_proofs.response.json")) as { result: MerkleProof[] }
).result[0];
const BLOCK0_LAST_BC = BLOCK0_PROOF.leaf.replace(/^0x/, "");
const BLOCK0_SIBLINGS = BLOCK0_PROOF.elements.map((element) => element.replace(/^0x/, ""));
const LIST_STATUS = (
  JSON.parse(NODE_STATUS.response) as {
    result: {
      forNetwork: {
        Ethereum: {
          listStatuses: Record<
            string,
            { historicalMerklerootsLength: number; latestHistoricalMerkleroot: string }
          >;
        };
      };
    };
  }
).result.forNetwork.Ethereum.listStatuses[OFAC_LIST_KEY];

type Host = (body: string) => Response;

/** Answers each request with the next recorded exchange, once it matches the recording exactly. */
function replayHost(script: readonly Exchange[], faults: string[]): Host & { left(): number } {
  const queue = [...script];
  const host = (body: string): Response => {
    const next = queue.shift();
    if (next === undefined) {
      faults.push(`no recorded exchange left for ${body}`);
      throw new TypeError("replay exhausted");
    }
    if (body !== next.request) {
      faults.push(`sent ${body}\nrecorded ${next.request}`);
      throw new TypeError("request differs from the recording");
    }
    return new Response(next.response, {
      status: next.status,
      headers: { "content-type": "application/json; charset=utf-8" },
    });
  };
  return Object.assign(host, { left: () => queue.length });
}

interface Wire {
  readonly fetch: typeof fetch;
  readonly sent: (origin: string) => string[];
}

function stubWire(hosts: Readonly<Record<string, Host>>, faults: string[]): Wire {
  const sent = new Map<string, string[]>();
  const impl: typeof fetch = async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const origin = Object.keys(hosts).find((candidate) => url.startsWith(candidate));
    if (origin === undefined) {
      if (!url.startsWith("http://127.0.0.1:")) {
        faults.push(`request to an unstubbed host: ${url}`);
        throw new TypeError("unstubbed host");
      }
      return fetch(input, init);
    }
    const body = typeof init?.body === "string" ? init.body : "";
    sent.set(origin, [...(sent.get(origin) ?? []), body]);
    return hosts[origin](body);
  };
  return { fetch: impl, sent: (origin) => sent.get(origin) ?? [] };
}

function resolverOver(wire: Wire): UpstreamPinResolver {
  return new UpstreamPinResolver({
    endpoint: AGGREGATOR,
    fetchImpl: wire.fetch,
    chainType: 0,
    chainId: MAINNET,
    txidVersion: TXID_VERSION,
  });
}

describe("pin resolution over recorded aggregator answers", () => {
  let faults: string[];

  beforeAll(() => {
    faults = [];
  });
  afterEach(() => {
    expect(faults).toEqual([]);
    faults.length = 0;
  });

  it("decodes the frozen block-0 answer from its one request, then asks nothing more", async () => {
    const aggregator = replayHost([BLOCK0_POINT], faults);
    const wire = stubWire({ [AGGREGATOR]: aggregator }, faults);
    const resolver = resolverOver(wire);

    const first = await resolver.resolve(OFAC_LIST_KEY, 0);
    const again = await resolver.resolve(OFAC_LIST_KEY, 0);

    expect([...first.roots]).toEqual([BLOCK0_ROOT]);
    expect(first.window).toEqual({
      startIndex: BLOCK0_LAST_INDEX,
      endIndex: BLOCK0_LAST_INDEX,
      frozen: true,
    });
    expect([...again.roots]).toEqual([BLOCK0_ROOT]);
    expect(wire.sent(AGGREGATOR)).toEqual([BLOCK0_POINT.request]);
    expect(aggregator.left()).toBe(0);
  });

  it("reads the filling tail block from a window that ends at the recorded tip", async () => {
    const aggregator = replayHost([BLOCK0_POINT, TAIL_POINT, NODE_STATUS, TAIL_EVENTS], faults);
    const wire = stubWire({ [AGGREGATOR]: aggregator }, faults);
    const resolver = resolverOver(wire);
    const tip = LIST_STATUS.historicalMerklerootsLength - 1;
    const tailBlock = Math.floor(tip / LEAVES_PER_PPOI_BLOCK);

    await resolver.resolve(OFAC_LIST_KEY, 0);
    const tail = await resolver.resolve(OFAC_LIST_KEY, tailBlock);

    const events = (
      JSON.parse(TAIL_EVENTS.response) as { result: { validatedMerkleroot: string }[] }
    ).result;
    expect(tail.window).toEqual({ startIndex: tip - (PIN_TAIL_WINDOW - 1), endIndex: tip, frozen: false });
    expect(tail.roots.size).toBe(PIN_TAIL_WINDOW);
    expect(tail.roots).toEqual(new Set(events.map((event) => event.validatedMerkleroot)));
    expect(tail.roots.has(LIST_STATUS.latestHistoricalMerkleroot)).toBe(true);
    expect(aggregator.left()).toBe(0);
  });

  it("refuses a list the aggregator does not serve, keeping the server's refusal kind", async () => {
    const aggregator = replayHost([UNSERVED_LIST], faults);
    const resolver = resolverOver(stubWire({ [AGGREGATOR]: aggregator }, faults));

    let thrown: unknown;
    try {
      await resolver.resolve(UNSERVED_LIST_KEY, 0);
    } catch (error) {
      thrown = error;
    }

    expect(RavenError.is(thrown, "ServerError"), String(thrown)).toBe(true);
    expect(String((thrown as Error).message)).toContain("-32602");
    expect(aggregator.left()).toBe(0);
  });

  describe("through the interface, with the aggregator inherited from upstreamFallbackEndpoint", () => {
    let adapter: MockServer;

    beforeAll(async () => {
      adapter = await startMockServer();
    });
    afterAll(async () => {
      await adapter.close();
    });
    afterEach(() => {
      adapter.reset();
    });

    function servePath(siblings: readonly string[], freshness?: string): void {
      mountPath10Route(adapter, {
        bcHex: BLOCK0_LAST_BC,
        nodes: siblings.map((hex) => new Uint8Array(Buffer.from(hex, "hex"))),
        schemaVersion: EXPECTED_WIRE_SCHEMA_VERSION,
        freshness,
      });
    }

    function sdkOver(wire: Wire, extra: Record<string, unknown> = {}): RavenPOINodeInterface {
      const pathCtx: ClientPirContext = { ...stubCtx(), entrySize: PATH10_ROW_BYTES };
      return new RavenPOINodeInterface({
        endpoint: adapter.url,
        bearerToken: TOKEN,
        useClientPir: true,
        chainId: MAINNET,
        clientPirContexts: new Map([[`t2Path:${OFAC_LIST_KEY}`, pathCtx]]),
        bcToIdxMaps: new Map([[OFAC_LIST_KEY, new Map([[BLOCK0_LAST_BC, BLOCK0_LAST_INDEX]])]]),
        upstreamFallbackEndpoint: AGGREGATOR,
        fetchImpl: wire.fetch,
        ...extra,
      });
    }

    it("verifies a served path against the recorded root, never asking the node for it", async () => {
      servePath(BLOCK0_SIBLINGS);
      const aggregator = replayHost([BLOCK0_POINT], faults);
      const wire = stubWire({ [AGGREGATOR]: aggregator }, faults);

      const [proof] = await sdkOver(wire).getPOIMerkleProofs(OFAC_LIST_KEY, [BLOCK0_LAST_BC]);

      expect(proof.root).toBe(BLOCK0_ROOT);
      expect(wire.sent(AGGREGATOR)).toEqual([BLOCK0_POINT.request]);
      expect(wire.sent(AGGREGATOR).some((body) => body.includes(BLOCK0_LAST_BC))).toBe(false);
      for (const request of adapter.requests) {
        expect(request.url).toMatch(/\/session$|^\/v1\/instance\/[^/]+\/batch$/);
      }
    });

    it("refuses a path one sibling off, naming the frozen window it checked", async () => {
      const forged = [...BLOCK0_SIBLINGS];
      forged[8] = `${forged[8].slice(0, -1)}${forged[8].endsWith("0") ? "1" : "0"}`;
      servePath(forged);
      const aggregator = replayHost([BLOCK0_POINT], faults);
      const wire = stubWire({ [AGGREGATOR]: aggregator }, faults);

      let thrown: unknown;
      try {
        await sdkOver(wire).getPOIMerkleProofs(OFAC_LIST_KEY, [BLOCK0_LAST_BC]);
      } catch (error) {
        thrown = error;
      }

      expect(RavenError.is(thrown, "DecodeError"), String(thrown)).toBe(true);
      expect(String((thrown as Error).message)).toContain(
        `${BLOCK0_LAST_INDEX}..${BLOCK0_LAST_INDEX} (frozen block)`,
      );
      expect(wire.sent(AGGREGATOR)).toEqual([BLOCK0_POINT.request]);
    });

    // The recorded upstream proof, in upstream's own spelling, on the stale fallback: it reaches
    // the wallet only because its fold equals a root from a party other than the one that sent it.
    it("verifies the recorded upstream proof on the stale fallback against a separate pin source", async () => {
      servePath(BLOCK0_SIBLINGS, STALE_FRESHNESS);
      const aggregator = replayHost([BLOCK0_POINT], faults);
      const upstream: Host = (body) => {
        const request = JSON.parse(body) as { id: number; method: string };
        expect(request.method).toBe("ppoi_merkle_proofs");
        return new Response(
          JSON.stringify({ jsonrpc: "2.0", result: [BLOCK0_PROOF], id: request.id }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      };
      const wire = stubWire({ [AGGREGATOR]: aggregator, [OTHER_UPSTREAM]: upstream }, faults);

      const proofs = await sdkOver(wire, {
        upstreamFallbackEndpoint: OTHER_UPSTREAM,
        privateStalePolicy: "allow-upstream-disclosure",
        pinUpstream: AGGREGATOR,
      }).getPOIMerkleProofs(OFAC_LIST_KEY, [BLOCK0_LAST_BC]);

      expect(proofs).toEqual([BLOCK0_PROOF]);
      expect(wire.sent(OTHER_UPSTREAM)).toHaveLength(1);
      expect(wire.sent(AGGREGATOR)).toEqual([BLOCK0_POINT.request]);
    });
  });
});
