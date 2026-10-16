// Client-side time per sync step in the wasm: key build, batch build and open, the tree work
// of a sync at large pool sizes, the feed scan and a path; and Howl's two discovery rounds
// through the source end to end against a local node, cold and again with no new rows.
// Interleaved samples, load recorded.
// Runs when HOWL_BENCH=1 and HOWL_NODE_BIN names the node binary.
import { randomBytes } from "node:crypto";
import { existsSync, writeFileSync } from "node:fs";
import { loadavg } from "node:os";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bigintField, fetchTransport, PrefixFeed, RavenHowlSource } from "../src/index.js";
import { LocalChain } from "./helpers/chain.js";
import { fixture, walletTags, wasm } from "./helpers/fixture.js";

const BIN = process.env.HOWL_NODE_BIN ?? "";
const run = process.env.HOWL_BENCH === "1" && BIN !== "" && existsSync(BIN);
const ROUNDS = Number(process.env.HOWL_BENCH_ROUNDS ?? 40);

function scalars(count: number): Uint8Array {
  const out = new Uint8Array(randomBytes(count * 32));
  for (let i = 0; i < count; i++) out[i * 32]! &= 0x0f;
  return out;
}

function summary(samples: number[]) {
  const sorted = [...samples].sort((a, b) => a - b);
  const at = (q: number) => sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))]!;
  return {
    n: sorted.length,
    median: +at(0.5).toFixed(2),
    p90: +at(0.9).toFixed(2),
    worst: +sorted[sorted.length - 1]!.toFixed(2),
  };
}

describe.skipIf(!run)("client time", () => {
  let chain: LocalChain;
  let params: Uint8Array;
  const samples = new Map<string, number[]>();
  const time = <T>(name: string, f: () => T): T => {
    const start = performance.now();
    const out = f();
    const took = performance.now() - start;
    samples.set(name, [...(samples.get(name) ?? []), took]);
    return out;
  };

  beforeAll(async () => {
    chain = await LocalChain.start();
    await chain.mineFixture(0, fixture.blocks.length);
    await chain.startNode(BIN);
    await chain.caughtUp();
    params = new Uint8Array(await (await fetch(`${chain.nodeUrl}/howl/v1/params`)).arrayBuffer());
  });

  afterAll(async () => {
    await chain?.stop();
  });

  it("measures", async () => {
    const load = { before: loadavg() };
    // one session client for batches, as a wallet holds one per session
    const session = new wasm.HowlClient(params);
    const seat = await fetch(`${chain.nodeUrl}/howl/v1/session`, { method: "POST", body: new Uint8Array(session.sessionBody()) });
    session.installSession(new Uint8Array(await seat.arrayBuffer()));

    // a tree of about a million leaves: 976 full blocks and a newest block that grows
    const big = new wasm.HowlTree();
    big.appendUpper(scalars(976));
    let newest = scalars(400);
    big.setNewest(976, newest);
    let n = 976 * 1024 + 400;
    const big10 = new wasm.HowlTree();
    big10.appendUpper(scalars(9_765));
    big10.setNewest(9_765, scalars(400));
    const feed = new PrefixFeed();
    feed.append(0, new Uint8Array(randomBytes(1_000_000 * 6)));
    const tags = Array.from({ length: 100 }, () => new Uint8Array(randomBytes(32)));

    const everyTag = fixture.wallets.flatMap((w) => walletTags(w)).map((t) => bigintField.fromBytes(t));
    const notes = new Set(fixture.wallets.flatMap((w) => w.owned_leaves)).size;
    const discover = async (src: RavenHowlSource<bigint>) => {
      const first = await src.probeFirst(everyTag);
      const rest = first.flatMap((f) =>
        Array.from({ length: Math.max(0, f.occurrenceCount - 1) }, (_, i) => ({ tag: f.tag, occurrence: i + 1 })),
      );
      await src.fetchOccurrences(rest);
    };
    const timed = async (name: string, f: () => Promise<void>) => {
      const start = performance.now();
      await f();
      samples.set(name, [...(samples.get(name) ?? []), performance.now() - start]);
    };

    for (let round = 0; round < ROUNDS; round++) {
      const src = new RavenHowlSource({ transport: fetchTransport(chain.nodeUrl), wasm, field: bigintField });
      await timed(`discovery of ${notes} notes, cold (end to end, local node)`, () => discover(src));
      await timed(`discovery of ${notes} notes, no new rows (end to end, local node)`, () => discover(src));
      src.close();
      const client = time("key build (new client, fresh secret)", () => new wasm.HowlClient(params));
      client.free();
      for (const k of [1, 16]) {
        const positions = Uint32Array.from({ length: k }, (_, i) => 1 + ((round * 7 + i * 13) % 159));
        const batch = time(`batch build, ${k} slot(s)`, () => session.buildBatch(positions, 160));
        const answer = await fetch(`${chain.nodeUrl}/howl/v1/notes`, { method: "POST", body: new Uint8Array(batch.body) });
        expect(answer.status).toBe(200);
        const bytes = new Uint8Array(await answer.arrayBuffer());
        const cells = time(`open, ${k} slot(s)`, () => session.openNotes(batch, bytes));
        expect(cells.cells.length).toBe(256 * k);
        cells.free();
        batch.free();
      }
      // a sync step at ~10^6 leaves: 17 new leaves in the newest block, then the root
      const grown = new Uint8Array(newest.length + 17 * 32);
      grown.set(newest);
      grown.set(scalars(17), newest.length);
      newest = grown.length >= 1024 * 32 ? scalars(1) : grown;
      n = 976 * 1024 + newest.length / 32;
      time("sync tree work at 1.0e6 leaves (17 new leaves + root)", () => {
        big.setNewest(976, newest);
        return big.root(n);
      });
      time("sync tree work at 1.0e7 leaves (root only)", () => big10.root(9_765 * 1024 + 400));
      time("path at 1.0e6 leaves (newest block)", () => big.path(n - 1, n));
      time("feed scan, 1e6 rows x 100 tags", () => feed.matches(tags));
    }
    session.free();
    load.before = load.before;
    const report = {
      when: new Date().toISOString(),
      rounds: ROUNDS,
      load: { before: load.before, after: loadavg() },
      ms: Object.fromEntries([...samples].map(([k, v]) => [k, summary(v)])),
    };
    // eslint-disable-next-line no-console
    console.log(JSON.stringify(report, null, 2));
    if (process.env.HOWL_BENCH_OUT) writeFileSync(process.env.HOWL_BENCH_OUT, JSON.stringify(report, null, 2));
  });
});
