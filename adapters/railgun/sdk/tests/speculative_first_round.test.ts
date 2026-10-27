// Once an index this node confirmed places every commitment, a proof's first batch goes out beside
// the index's tail read instead of after it: a held row never moves while the list keeps its
// epoch. Its replies are read only after the tail lands, and discarded unread when the tail shows
// the index moved, so no proof ever comes from a position the current index does not vouch for.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { RavenPOINodeInterface, hexToBytes, type RavenConfig } from "../src/index";
import { encodeBatchResponseNodes } from "./helpers/auth_path_stub";
import { forestConfig } from "./helpers/forest";
import { startMockServer, type MockServer } from "./helpers/mock_server";
import { PATH10_ROW_BYTES, path10Slot } from "./helpers/path10_row";
import { ppoiTree } from "./helpers/ppoi_tree";
import {
  batchTargets,
  commitmentAt,
  mountPrefixChannel,
  targetNamingCtx,
  type MockList,
} from "./helpers/prefix_channel";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "cd".repeat(32);
const TAIL_DELAY_MS = 600;

/** Request order and timing on the mock node, by kind. */
interface Seen {
  kind: "prefix" | "batch" | "tail-answered";
  at: number;
  targets?: number[];
}

/** Serves `list` on the prefix channel, its tail answered `tailDelay` ms late, and rows from
 *  whatever tree `rowsOf()` names when each batch lands. */
function mount(
  server: MockServer,
  list: MockList,
  rowsOf: () => readonly string[],
  seen: Seen[],
  tailDelay: () => number,
): void {
  server.route(
    (req) => (req.url ?? "").includes("/bc-prefixes"),
    (_req, _body, _res) => {
      seen.push({ kind: "prefix", at: performance.now() });
      return false;
    },
  );
  const channel: MockServer = {
    ...server,
    route: (match, handler) =>
      server.route(match, async (req, body, res) => {
        const delay = tailDelay();
        if (delay > 0) await new Promise((resolve) => setTimeout(resolve, delay));
        seen.push({ kind: "tail-answered", at: performance.now() });
        return handler(req, body, res);
      }),
  };
  mountPrefixChannel(channel, LIST_KEY_HEX, list);
  server.route(
    (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
    (_req, body, res) => {
      const rows = rowsOf();
      const tree = ppoiTree(rows);
      const targets = batchTargets(body);
      seen.push({ kind: "batch", at: performance.now(), targets });
      const slots = targets.map((target) =>
        path10Slot({
          bcHex: rows[target],
          nodes: tree.proofs[target].elements.map((node) => hexToBytes(node)),
        }),
      );
      res.writeHead(200, {
        "content-type": "application/octet-stream",
        "x-raven-freshness": "lag_blocks=0 applied_height=0 epoch=1 confidence=1",
      });
      res.end(Buffer.from(encodeBatchResponseNodes(slots)));
      return true;
    },
  );
}

function client(server: MockServer, extra: Partial<RavenConfig> = {}): RavenPOINodeInterface {
  return new RavenPOINodeInterface({
    ...forestConfig({
      endpoint: server.url,
      listKeyHex: LIST_KEY_HEX,
      ctx: targetNamingCtx(PATH10_ROW_BYTES),
    }),
    bearerToken: TOKEN,
    ...extra,
  });
}

const pinned = (rows: readonly string[]): Partial<RavenConfig> => ({
  ppoiPinnedRoots: new Map([[`1:${LIST_KEY_HEX}:0`, ppoiTree(rows).root]]),
});

describe("a proof's first batch and the index tail", () => {
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

  it("go out together once a confirmed index places the commitment", async () => {
    const list: MockList = { commitments: [0, 1, 2, 3].map(commitmentAt) };
    const seen: Seen[] = [];
    let delay = 0;
    mount(server, list, () => list.commitments, seen, () => delay);
    const sdk = client(server, pinned(list.commitments));
    await sdk.syncPoiListIndex(LIST_KEY_HEX);
    // Seats the session, so the timed call is the proof alone.
    await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [commitmentAt(1)]);
    seen.length = 0;
    delay = TAIL_DELAY_MS;

    const started = performance.now();
    const [proof] = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [commitmentAt(2)]);
    const elapsed = performance.now() - started;

    expect(proof.leaf).toBe(commitmentAt(2));
    const answered = seen.find((s) => s.kind === "tail-answered");
    const batch = seen.find((s) => s.kind === "batch");
    expect(answered && batch, JSON.stringify(seen)).toBeTruthy();
    // The batch lands while the tail is still held back, so the call costs one delay, not two.
    expect(batch!.at).toBeLessThan(answered!.at);
    expect(elapsed).toBeLessThan(TAIL_DELAY_MS * 2);
    expect(sdk.indexCounters()).toMatchObject({ speculativeRounds: 2, speculativeRoundsDiscarded: 0 });
  });

  it("stay in order for a commitment the held index does not place", async () => {
    const list: MockList = { commitments: [0, 1, 2].map(commitmentAt) };
    const seen: Seen[] = [];
    let delay = 0;
    mount(server, list, () => list.commitments, seen, () => delay);
    const sdk = client(server, pinned([...list.commitments, commitmentAt(3)]));
    await sdk.syncPoiListIndex(LIST_KEY_HEX);
    list.commitments.push(commitmentAt(3));
    seen.length = 0;
    delay = TAIL_DELAY_MS;

    const [proof] = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [commitmentAt(3)]);

    expect(proof.leaf).toBe(commitmentAt(3));
    const answered = seen.find((s) => s.kind === "tail-answered")!;
    const batch = seen.find((s) => s.kind === "batch")!;
    expect(batch.at).toBeGreaterThan(answered.at);
    expect(sdk.indexCounters()).toMatchObject({ speculativeRounds: 0 });
  });

  it("discard the first replies unread when the tail shows the list was replaced", async () => {
    const before = [0, 1, 2, 3].map(commitmentAt);
    const list: MockList = { commitments: [...before], epoch: 0 };
    const seen: Seen[] = [];
    let delay = 0;
    mount(server, list, () => list.commitments, seen, () => delay);
    // The reseeded list holds the commitment two rows later, under another epoch.
    const after = [commitmentAt(7), commitmentAt(8), commitmentAt(0), commitmentAt(1), commitmentAt(2)];
    const sdk = client(server, pinned(after));
    await sdk.syncPoiListIndex(LIST_KEY_HEX);
    list.commitments = after;
    list.epoch = 1;
    seen.length = 0;
    delay = TAIL_DELAY_MS;

    const [proof] = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [commitmentAt(2)]);

    expect(proof.leaf).toBe(commitmentAt(2));
    expect(BigInt(`0x${proof.indices}`)).toBe(4n);
    const batches = seen.filter((s) => s.kind === "batch");
    expect(batches).toHaveLength(2);
    // Control: the first batch asked the held position, whose row now carries another
    // commitment. Read, it would have refused the proof as a forged row.
    expect(batches[0].targets).toContain(2);
    expect(after[2]).not.toBe(commitmentAt(2));
    expect(batches[1].targets).toContain(4);
    expect(sdk.indexCounters()).toMatchObject({ speculativeRounds: 1, speculativeRoundsDiscarded: 1 });
  });

  it("keep the first replies when the tail read fails, as an ordered call would have asked them", async () => {
    const list: MockList = { commitments: [0, 1, 2, 3].map(commitmentAt) };
    const seen: Seen[] = [];
    mount(server, list, () => list.commitments, seen, () => 0);
    const sdk = client(server, pinned(list.commitments));
    await sdk.syncPoiListIndex(LIST_KEY_HEX);
    list.failStatus = 503;
    seen.length = 0;

    const [proof] = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [commitmentAt(1)]);

    expect(proof.leaf).toBe(commitmentAt(1));
    expect(seen.filter((s) => s.kind === "batch")).toHaveLength(1);
    expect(sdk.indexCounters()).toMatchObject({ speculativeRounds: 1, speculativeRoundsDiscarded: 0 });
  });
});
