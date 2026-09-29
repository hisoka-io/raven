// The pin resolver against a real PPOI aggregator. The auth path is served by a local stand-in
// for the Raven node and the root must come from the aggregator, so the two are never one
// party. Live blocks skip unless RAVEN_PIN_UPSTREAM names an aggregator, so offline lanes make
// no network calls.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  LEAVES_PER_PPOI_BLOCK,
  PIN_TAIL_WINDOW,
  RavenError,
  RavenPOINodeInterface,
  UpstreamPinResolver,
  type ClientPirContext,
} from "../src/index";
import { foldMerkleRoot } from "../src/poseidon";
import { TOKEN, encodeBatchResponseNodes, stubCtx } from "./helpers/auth_path_stub";
import { startMockServer, type MockServer } from "./helpers/mock_server";
import { indexHolding } from "./helpers/prefix_channel";

const UPSTREAM = process.env.RAVEN_PIN_UPSTREAM;
const liveIt = UPSTREAM !== undefined && UPSTREAM !== "" ? it : it.skip;

const MAINNET = 1;
const TXID_VERSION = "V2_PoseidonMerkle";
const OFAC_LIST_KEY = "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";
const BLOCK0_LAST_INDEX = LEAVES_PER_PPOI_BLOCK - 1;
const ROW_BYTES = 512;
const ADDENDUM_BYTES = 160;

// Block 0 of this list is full, so its root and the path to its last leaf can never change:
// read once from upstream (ppoi_poi_events at leaf 65,535, ppoi_merkle_proofs for that leaf),
// they stay true. The offline test below proves the fixture is self-consistent.
const BLOCK0_ROOT = "277a7808c8aaeb2fa649a601111f77e3c863f891d18636e9c419df16a0ec0006";
const BLOCK0_LAST_BC = "0d0b88e7806abc65c51606290c4236119f7f0eb90235307090dbb924dacc4de6";
const BLOCK0_LAST_SIBLINGS = [
  "046aee147ac2a1b731b525f131ee1af88d5b1db3882ff6bc5729d90ee125b3e7",
  "13fbb4c3444a122738d318df6fc1646744e69b39750ff13831c176a4bfbff3ad",
  "1f5d68d45c8df72e5f1b76473a4577fd3471fc8d5dc29fab5197bcf61e144bd1",
  "1be9b9d2934faa51f91318d415e20f2df6d13fd8a1e29e12abc8872f9d56a359",
  "20ae4f945688927fbcc994b08241613e7a0a1d4f569c124a8c8a93f7098e215a",
  "29b3b153559766a522eff6ed72a473a866a75e176371772bac22dbba02678240",
  "2a78246e0210d03b58bbcba7ea8afa86e31960f5c9f1a0eb771aad662cee2443",
  "1c39a02f084c642956b8d3d58ba8b5dd363d6e3afe119f488eef410aa979852e",
  "2c67714018c1c5bda7f69ae18ddb4de2df66ececebae61a6286dab389256371b",
  "2bb858afe049ad9c0c5bee61b8b02471a359aec25f988faff84dfbef98d07837",
  "0a29a827b7c4df6ddf6abdd0aab7d2ae32175b49db40435bd71fd61f3b83564e",
  "0abee33479c75a53fb9f4ef41ed2536c4c73e0a2c445ae805b85f1fd0fb25176",
  "12b80d7fb029bf2752bc47deabbabda00bb06d9fa3b537f37edc8e756bbc3165",
  "02dcc4c75eba47ebd60f501ad1ed9e05a9338f32d79f0720c04d937a71ff1c35",
  "02270d3aaa837f14437b7997242ebd5632492d7b29f98ec3fda66d0811d9557d",
  "0a301771ed21d54d3079a916d62e0bb2a9c19fbaf86ab4e40803d35a6b7be4b6",
];

interface SentRequest {
  readonly url: string;
  readonly body: string;
}

function recordingFetch(log: SentRequest[]): typeof fetch {
  return async (input, init) => {
    const body = typeof init?.body === "string" ? init.body : "";
    log.push({ url: String(input), body });
    return fetch(input, init);
  };
}

function servedSlot(siblings: readonly string[]): Uint8Array {
  const row = new Uint8Array(ROW_BYTES);
  row.set(Buffer.from(BLOCK0_LAST_BC, "hex"), 0);
  row.set(new TextEncoder().encode("RVP2"), 34);
  for (let level = 0; level < 11; level += 1) {
    row.set(Buffer.from(siblings[level], "hex"), 38 + level * 32);
  }
  const slot = new Uint8Array(ROW_BYTES + ADDENDUM_BYTES);
  slot.set(row, 0);
  for (let level = 0; level < 5; level += 1) {
    slot.set(Buffer.from(siblings[11 + level], "hex"), ROW_BYTES + level * 32);
  }
  return slot;
}

function mountRowRoute(server: MockServer, siblings: readonly string[]): void {
  server.route(
    (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
    (_req, _body, res) => {
      res.writeHead(200, {
        "content-type": "application/octet-stream",
        "x-raven-epoch": "1",
        "x-raven-schema-version": "8",
        "x-raven-freshness": "lag_blocks=0 applied_height=0 epoch=1 confidence=1",
      });
      res.end(Buffer.from(encodeBatchResponseNodes([servedSlot(siblings)])));
      return true;
    },
  );
}

// Only `upstreamFallbackEndpoint` names the aggregator: no pin-specific field is set, so this
// is the inherited default a wallet gets from the configuration it already has.
function liveSdk(adapter: MockServer, log: SentRequest[]): RavenPOINodeInterface {
  const pathCtx: ClientPirContext = { ...stubCtx(), entrySize: ROW_BYTES };
  return new RavenPOINodeInterface({
    endpoint: adapter.url,
    bearerToken: TOKEN,
    chainId: MAINNET,
    clientPirContexts: new Map([[`t2Path:${MAINNET}:${OFAC_LIST_KEY}`, pathCtx]]),
    clientPirInstanceLabels: new Map([[`t2Path:${MAINNET}:${OFAC_LIST_KEY}:0`, "ppoi-paths-ofac-0"]]),
    poiListIndexes: new Map([
      [`${MAINNET}:${OFAC_LIST_KEY}`, indexHolding([[BLOCK0_LAST_BC, BLOCK0_LAST_INDEX]])],
    ]),
    poiListIndexStore: false,
    upstreamFallbackEndpoint: UPSTREAM,
    fetchImpl: recordingFetch(log),
  });
}

async function rawRpc(method: string, params: Record<string, unknown>): Promise<unknown> {
  const res = await fetch(UPSTREAM as string, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", method, params, id: 1 }),
    signal: AbortSignal.timeout(30_000),
  });
  const decoded = (await res.json()) as { result?: unknown; error?: unknown };
  if (decoded.error !== undefined && decoded.error !== null) {
    throw new Error(`${method}: ${JSON.stringify(decoded.error)}`);
  }
  return decoded.result;
}

async function listLength(): Promise<number> {
  const status = (await rawRpc("ppoi_node_status", {})) as {
    forNetwork: { Ethereum: { listStatuses: Record<string, { historicalMerklerootsLength: number }> } };
  };
  return status.forNetwork.Ethereum.listStatuses[OFAC_LIST_KEY].historicalMerklerootsLength;
}

describe("pin resolution against a live PPOI aggregator", () => {
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

  it("the frozen block-0 fixture folds to its recorded root", () => {
    expect(foldMerkleRoot(BLOCK0_LAST_BC, BLOCK0_LAST_SIBLINGS, BigInt(BLOCK0_LAST_INDEX))).toBe(
      BLOCK0_ROOT,
    );
  });

  liveIt("verifies a served path against the root upstream certifies, never asking the node", async () => {
    mountRowRoute(adapter, BLOCK0_LAST_SIBLINGS);
    const log: SentRequest[] = [];
    const sdk = liveSdk(adapter, log);

    const [proof] = await sdk.getPOIMerkleProofs(OFAC_LIST_KEY, [BLOCK0_LAST_BC]);

    expect(proof.root).toBe(BLOCK0_ROOT);
    const toUpstream = log.filter((r) => r.url.startsWith(UPSTREAM as string));
    expect(toUpstream.map((r) => JSON.parse(r.body).method)).toEqual(["ppoi_poi_events"]);
    expect(toUpstream.every((r) => !r.body.includes(BLOCK0_LAST_BC))).toBe(true);
    for (const req of adapter.requests) {
      expect(req.url).toMatch(
        /\/session$|^\/v1\/instance\/[^/]+\/batch$|^\/v1\/poi\/[0-9a-f]{64}\/bc-prefixes\?since=0$/,
      );
    }
  });

  liveIt("refuses a tampered path, naming the frozen window it checked", async () => {
    const forged = [...BLOCK0_LAST_SIBLINGS];
    forged[7] = forged[7].replace(/^./, (c) => (c === "0" ? "1" : "0"));
    mountRowRoute(adapter, forged);
    const sdk = liveSdk(adapter, []);

    let thrown: unknown;
    try {
      await sdk.getPOIMerkleProofs(OFAC_LIST_KEY, [BLOCK0_LAST_BC]);
    } catch (e) {
      thrown = e;
    }
    expect(RavenError.is(thrown, "DecodeError"), `got ${String(thrown)}`).toBe(true);
    expect(String((thrown as Error).message)).toContain(
      `${BLOCK0_LAST_INDEX}..${BLOCK0_LAST_INDEX} (frozen block)`,
    );
  });

  // The tail window is anchored on historicalMerklerootsLength - 1, which is only right if the
  // count is the tip: nothing may sit at or past it.
  liveIt("resolves the filling tail block from a window that ends at upstream's tip", async () => {
    const length = await listLength();
    const tailBlock = Math.floor((length - 1) / LEAVES_PER_PPOI_BLOCK);
    const resolver = new UpstreamPinResolver({
      endpoint: UPSTREAM as string,
      fetchImpl: fetch,
      chainType: 0,
      chainId: MAINNET,
      txidVersion: TXID_VERSION,
    });

    const resolved = await resolver.resolve(OFAC_LIST_KEY, tailBlock);

    expect(resolved.roots.size).toBeGreaterThan(0);
    expect(resolved.window.endIndex).toBeGreaterThanOrEqual(length - 1);
    expect(Math.floor(resolved.window.startIndex / LEAVES_PER_PPOI_BLOCK)).toBe(tailBlock);
    expect(resolved.window.endIndex - resolved.window.startIndex + 1).toBeLessThanOrEqual(PIN_TAIL_WINDOW);

    const beyond = (await rawRpc("ppoi_poi_events", {
      chainType: "0",
      chainID: String(MAINNET),
      txidVersion: TXID_VERSION,
      listKey: OFAC_LIST_KEY,
      startIndex: resolved.window.endIndex + 1,
      endIndex: resolved.window.endIndex + 500,
    })) as { signedPOIEvent: { index: number } }[];
    const after = await listLength();
    for (const row of beyond) {
      expect(row.signedPOIEvent.index).toBeLessThan(after);
    }
  });
});
