// The package against a running node binary following a local chain that replays the fixture.
// Runs when HOWL_NODE_BIN names the node binary and `anvil` is on the PATH.
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  bigintField,
  fetchTransport,
  RavenHowlSource,
  type HowlBatchHandle,
  type HowlClientHandle,
  type HowlNoteRecord,
  type HowlTransport,
  type HowlWasm,
  type KeyMode,
} from "../src/index.js";
import { countAfter, LocalChain } from "./helpers/chain.js";
import { chainRoots, fixture, hex, unhex, walletTags, wasm, type FixtureLog } from "./helpers/fixture.js";

const BIN = process.env.HOWL_NODE_BIN ?? "";
const live = BIN !== "" && existsSync(BIN);
const HALF = Math.floor(fixture.blocks.length / 2);

/** A transport that records every path asked for and the bytes moved. */
function recorded(url: string): HowlTransport & { paths: string[]; down: number[] } {
  const inner = fetchTransport(url);
  const paths: string[] = [];
  const down: number[] = [];
  return {
    paths,
    down,
    get: async (path) => {
      const ex = await inner.get(path);
      paths.push(`GET ${path}`);
      down.push(ex.body.length);
      return ex;
    },
    post: async (path, body) => {
      const ex = await inner.post(path, body);
      paths.push(`POST ${path}`);
      down.push(ex.body.length);
      return ex;
    },
  };
}

const big = (bytes: Uint8Array): bigint => bigintField.fromBytes(bytes);

/** The wasm, recording the targets and slot order of every batch built through it. */
function spied(): { wasm: HowlWasm; plans: { targets: number[]; slots: number[] }[] } {
  const plans: { targets: number[]; slots: number[] }[] = [];
  const note = (batch: HowlBatchHandle): HowlBatchHandle => {
    plans.push({ targets: [...batch.targets], slots: [...batch.realSlots] });
    return batch;
  };
  const Client = function (this: unknown, params: Uint8Array): HowlClientHandle {
    const inner = new wasm.HowlClient(params);
    return new Proxy(inner, {
      get(target, key) {
        if (key === "buildBatch") {
          return (p: Uint32Array, n: number) => note(target.buildBatch(p, n));
        }
        if (key === "buildBatchAt") {
          return (t: Uint32Array, s: Uint32Array, n: number) => note(target.buildBatchAt(t, s, n));
        }
        const value = Reflect.get(target, key, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
  } as unknown as HowlWasm["HowlClient"];
  return { wasm: { ...wasm, HowlClient: Client, HowlTree: wasm.HowlTree }, plans };
}

function source(chain: LocalChain, keyMode: KeyMode) {
  const transport = recorded(chain.nodeUrl);
  return { transport, source: new RavenHowlSource({ transport, wasm, field: bigintField, keyMode }) };
}

function expectFixtureCell(record: HowlNoteRecord<bigint>): void {
  const want = unhex(fixture.leaves[record.leafIndex]!.cell!);
  expect(hex(record.commitmentPrefix)).toBe(hex(want.subarray(6, 22)));
  expect(record.ephemeralPkX).toBe(big(want.subarray(22, 54)));
  expect(record.cekWrap).toBe(big(want.subarray(54, 86)));
  record.ciphertextKept.forEach((w, i) => expect(w).toBe(big(want.subarray(86 + 32 * i, 118 + 32 * i))));
}

/** Howl's two rounds over the compatibility shape: every note of every tag, by position. */
async function discover(src: RavenHowlSource<bigint>, tags: bigint[]): Promise<Map<number, HowlNoteRecord<bigint>>> {
  const found = new Map<number, HowlNoteRecord<bigint>>();
  const first = await src.probeFirst(tags);
  const rest = first.flatMap((f) =>
    Array.from({ length: Math.max(0, f.occurrenceCount - 1) }, (_, i) => ({ tag: f.tag, occurrence: i + 1 })),
  );
  for (const f of first) if (f.occurrenceCount > 0) found.set(f.record.leafIndex, f.record);
  const more = await src.fetchOccurrences(rest);
  expect(more.length).toBe(rest.length);
  for (const r of more) if (r !== null) found.set(r.leafIndex, r);
  return found;
}

describe.skipIf(!live)("against a running node", () => {
  let chain: LocalChain;
  const roots = chainRoots();
  const tagsOf = (label: string) =>
    walletTags(fixture.wallets.find((w) => w.label === label)!).map((t) => big(t));
  const owned = (label: string, below: number) =>
    fixture.wallets.find((w) => w.label === label)!.owned_leaves.filter((p) => p < below).sort((a, b) => a - b);

  let halfway = "";

  beforeAll(async () => {
    chain = await LocalChain.start();
    await chain.mineFixture(0, HALF);
    halfway = await chain.rpc("evm_snapshot");
    await chain.startNode(BIN);
    await chain.caughtUp();
  });

  afterAll(async () => {
    await chain?.stop();
  });

  it("wallets find exactly their notes at every step, by session and inline", async () => {
    const wallets = fixture.wallets.map((w, i) => ({
      label: w.label,
      ...source(chain, i % 2 === 0 ? "session" : "inline"),
    }));
    const half = countAfter[HALF - 1]!;
    for (const w of wallets) {
      const found = await discover(w.source, tagsOf(w.label));
      expect([...found.keys()].sort((a, b) => a - b), w.label).toEqual(owned(w.label, half));
      found.forEach(expectFixtureCell);
      expect(w.source.state.leafCount).toBe(half);
    }
    // the chain moves on; each wallet downloads only the rows past its cursor
    for (let i = HALF; i < fixture.blocks.length; i += 11) {
      await chain.mineFixture(i, Math.min(i + 11, fixture.blocks.length));
      await chain.caughtUp();
      for (const w of wallets) {
        const before = w.source.state.leafCount;
        const mark = w.transport.paths.length;
        const found = await discover(w.source, tagsOf(w.label));
        expect(w.transport.paths[mark]).toBe(`GET /howl/v1/sync?since=${before}&upper=0`);
        expect(w.source.state.leafCount).toBe(chain.leafCount);
        expect(w.source.state.block).toBe(await chain.head());
        expect([...found.keys()].sort((a, b) => a - b)).toEqual(owned(w.label, chain.leafCount));
        found.forEach(expectFixtureCell);
      }
    }
    for (const w of wallets) {
      expect(hex(w.source.state.root)).toBe(fixture.root.slice(2));
      const sessions = w.transport.paths.filter((p) => p === "POST /howl/v1/session").length;
      expect(sessions, w.label).toBe(w.source === wallets[0]!.source ? 1 : 0);
    }
  });

  it("serves the discovery contract's shape: feed segments, positional reads and blocks", async () => {
    const { source: src } = source(chain, "session");
    const feed = await src.fetchTagPrefixes(0);
    expect([feed.base, feed.next, feed.end]).toEqual([0, 160, { total: 160, block: await chain.head() }]);
    expect(hex(feed.prefixes)).toBe(fixture.leaves.map((l) => l.prefix.slice(2)).join(""));
    const tail = await src.fetchTagPrefixes(150);
    expect([tail.base, tail.next, tail.prefixes.length]).toEqual([150, 160, 60]);
    await expect(src.fetchTagPrefixes(161)).rejects.toMatchObject({ kind: "Stale", status: 409 });

    const positions = [159, 1, 77, 3, 3, 120];
    const records = await src.fetchNotes(positions);
    expect(records.map((r) => r.leafIndex)).toEqual(positions);
    records.forEach(expectFixtureCell);
    expect(src.lastRead).toEqual({ leafCount: 160, block: await chain.head() });
    // more than the ladder cap is split over batches
    const many = Array.from({ length: 40 }, (_, i) => i + 1);
    expect((await src.fetchNotes(many)).map((r) => r.leafIndex)).toEqual(many);
    await expect(src.fetchNotes([160])).rejects.toThrow(/past the 160 leaves/);

    const block = await src.fetchLeafBlock(0);
    expect(block.map((l) => l)).toEqual(fixture.leaves.map((l) => BigInt(l.commitment)));
    expect(await src.fetchLeafBlock(1)).toEqual([]);
  });

  it("calls made together run one at a time and share one session", async () => {
    const { source: src, transport } = source(chain, "session");
    const tags = tagsOf("bob");
    const [synced, notes, first, witness] = await Promise.all([
      src.sync(),
      src.fetchNotes([5, 6, 7]),
      src.probeFirst(tags),
      src.merkleWitness(5),
    ]);
    expect(synced.leafCount).toBe(160);
    expect(notes.map((r) => r.leafIndex)).toEqual([5, 6, 7]);
    expect(first.length).toBe(tags.length);
    expect(witness.root).toBe(BigInt(fixture.root));
    expect(transport.paths.filter((p) => p === "POST /howl/v1/session").length).toBe(1);
  });

  it("builds every owned note's path at chosen counts, folding to the chain's root there", async () => {
    const { source: src } = source(chain, "session");
    await src.sync();
    let checked = 0;
    for (const w of fixture.wallets) {
      for (const index of w.owned_leaves) {
        for (const n of new Set([index + 1, Math.max(index + 1, 100), 160])) {
          const witness = await src.merkleWitness(index, n);
          expect(witness.siblings.length).toBe(32);
          expect(witness.root, `${index} at ${n}`).toBe(BigInt(`0x${roots.get(n)}`));
          expect(witness.leaf).toBe(BigInt(fixture.leaves[index]!.commitment));
          checked += 1;
        }
      }
    }
    expect(checked).toBeGreaterThan(60);
  });

  it("a session that expires on the node is replaced under a new secret", async () => {
    const url = await chain.startNode(BIN, { ttlSecs: 1 });
    await chain.caughtUp(chain.leafCount, url);
    const transport = recorded(url);
    const spy = spied();
    const src = new RavenHowlSource({ transport, wasm: spy.wasm, field: bigintField });
    expect((await src.fetchNotes([1]))[0]!.leafIndex).toBe(1);
    await new Promise((r) => setTimeout(r, 2_500));
    const records = await src.fetchNotes([2, 3, 4]);
    expect(records.map((r) => r.leafIndex)).toEqual([2, 3, 4]);
    records.forEach(expectFixtureCell);
    const posts = transport.paths.filter((p) => p.startsWith("POST"));
    expect(posts).toEqual([
      "POST /howl/v1/session",
      "POST /howl/v1/notes",
      "POST /howl/v1/notes",
      "POST /howl/v1/session",
      "POST /howl/v1/notes",
    ]);
    // the read sent again under the new session asks for the same rows in the same slots
    expect(spy.plans.length).toBe(3);
    expect(spy.plans[2]).toEqual(spy.plans[1]);
    expect(spy.plans[1]!.targets.length).toBe(4);
  });

  it("a read the node refused with 410 at will is sent again with the same rows and slots", async () => {
    const inner = recorded(chain.nodeUrl);
    let refused = 0;
    const transport: HowlTransport = {
      get: inner.get,
      post: async (path, body) => {
        if (path === "/howl/v1/notes" && refused++ === 0) return { status: 410, body: new Uint8Array(0) };
        return inner.post(path, body);
      },
    };
    const spy = spied();
    const src = new RavenHowlSource({ transport, wasm: spy.wasm, field: bigintField });
    const records = await src.fetchNotes([4, 90, 151]);
    expect(records.map((r) => r.leafIndex)).toEqual([4, 90, 151]);
    records.forEach(expectFixtureCell);
    expect(spy.plans.length).toBe(2);
    expect(spy.plans[1]).toEqual(spy.plans[0]);
    expect(inner.paths.filter((p) => p === "POST /howl/v1/session").length).toBe(2);
  });

  it("cells read once are not read again: a second probe with no new rows sends no batch", async () => {
    const { source: src, transport } = source(chain, "session");
    const tags = tagsOf("bob");
    const first = await discover(src, tags);
    expect(first.size).toBeGreaterThan(0);
    const mark = transport.paths.length;
    const second = await discover(src, tags);
    expect([...second.keys()]).toEqual([...first.keys()]);
    expect(transport.paths.slice(mark)).toEqual([`GET /howl/v1/sync?since=${src.state.leafCount}&upper=0`]);
  });

  it("a tag with no match gets a well-formed record that opens to nothing", async () => {
    const { source: src } = source(chain, "session");
    const absent = big(new Uint8Array(32).fill(0x0a));
    const [hit] = tagsOf("alice");
    const [miss, found] = await src.probeFirst([absent, hit!]);
    expect(miss!.occurrenceCount).toBe(0);
    expect(miss!.record).toEqual({
      layoutVersion: 1,
      recordKind: 1,
      leafIndex: 0,
      commitmentPrefix: new Uint8Array(16),
      ephemeralPkX: 0n,
      cekWrap: 0n,
      ciphertextKept: [0n, 0n, 0n, 0n, 0n],
    });
    expect(found!.occurrenceCount).toBeGreaterThan(0);
    expect(found!.record.leafIndex).toBeGreaterThan(0);
  });

  it("a stored snapshot resumes at its cursor and downloads only newer rows", async () => {
    const { source: first } = source(chain, "session");
    await first.sync();
    const stored = first.snapshot();
    const transport = recorded(chain.nodeUrl);
    const resumed = new RavenHowlSource({ transport, wasm, field: bigintField, snapshot: stored });
    expect(resumed.state.leafCount).toBe(stored.leafCount);
    const result = await resumed.sync();
    expect(transport.paths).toEqual([`GET /howl/v1/sync?since=${stored.leafCount}&upper=0`]);
    expect(result.rowsAdded).toBe(0);
    const tampered = { ...stored, root: new Uint8Array(32) };
    expect(() => new RavenHowlSource({ transport, wasm, field: bigintField, snapshot: tampered })).toThrow(/root/);
  });

  it("an answer that does not hash to its own root is refused", async () => {
    const inner = recorded(chain.nodeUrl);
    const lying: HowlTransport = {
      post: inner.post,
      get: async (path) => {
        const ex = await inner.get(path);
        if (!path.startsWith("/howl/v1/sync") || ex.status !== 200) return ex;
        const body = ex.body.slice();
        body[body.length - 1]! ^= 1;
        return { status: ex.status, body };
      },
    };
    const src = new RavenHowlSource({ transport: lying, wasm, field: bigintField });
    await expect(src.sync()).rejects.toMatchObject({ kind: "Protocol" });
  });

  // Both forks start where the first half of the fixture ends; each wallet held more than that.
  const forkStart = countAfter[HALF - 1]!;
  const aliceTag = () => unhex(fixture.wallets[0]!.self_keys.find((k) => k.even_y)!.x);
  let other = "";
  let lastFork: ReturnType<typeof forkLogs> | null = null;

  async function refork(from: string, count: number) {
    await chain.rpc("evm_revert", from);
    const again = (await chain.rpc("evm_snapshot")) as string;
    await chain.rpc("evm_setAutomine", false);
    chain.leafCount = forkStart;
    const kept = fixture.leaves.slice(0, forkStart).map((l) => unhex(l.commitment));
    const fork = forkLogs(kept, count, aliceTag(), 7);
    lastFork = fork;
    for (const block of fork.blocks) await chain.mine(block.logs, block.leafCount);
    await chain.mine([], fork.leafCount);
    await chain.caughtUp(fork.leafCount);
    return { fork, again };
  }

  async function expectFork(src: RavenHowlSource<bigint>, fork: ReturnType<typeof forkLogs>) {
    const result = await src.sync();
    expect(result.rewoundTo).toBe(0);
    expect(src.state.leafCount).toBe(fork.leafCount);
    expect(src.state.block).toBe(await chain.head());
    expect(hex(src.state.root)).toBe(hex(fork.root));
    const alice = tagsOf("alice");
    const after = src.matches(alice).map((m) => m.position);
    expect(after.filter((p) => p >= forkStart)).toEqual([fork.taggedAt]);
    expect(after.filter((p) => p < forkStart)).toEqual(owned("alice", forkStart));
    const witness = await src.merkleWitness(fork.taggedAt);
    expect(witness.root).toBe(big(fork.root));
    const [record] = await src.fetchNotes([fork.taggedAt]);
    expect(record!.leafIndex).toBe(fork.taggedAt);
    // the fork's cell, not one kept from before the rewind
    expect(hex(record!.commitmentPrefix)).toBe(hex(fork.leaves[fork.taggedAt]!.subarray(0, 16)));
  }

  it("a shorter fork below the cursor is found, rewound and read again", async () => {
    const { source: src } = source(chain, "session");
    await src.sync();
    expect(src.state.leafCount).toBe(160);
    // a cell read before the fork, at the position the fork's tagged note takes
    await src.fetchNotes([forkStart + 7]);
    const { fork, again } = await refork(halfway, 30);
    other = again;
    expect(fork.leafCount).toBeLessThan(160);
    await expectFork(src, fork);
  });

  it("a longer fork that passes the cursor is found by the leaves under it", async () => {
    const { source: src } = source(chain, "session");
    await src.sync();
    const held = src.state.leafCount;
    const { fork } = await refork(other, 120);
    expect(fork.leafCount).toBeGreaterThan(held);
    await expectFork(src, fork);
  });

  it("a chain that only gets shorter is followed without waiting for a new leaf", async () => {
    const base = lastFork!;
    const tip = (await chain.rpc("evm_snapshot")) as string;
    const grown = forkLogs(base.leaves, 4, aliceTag(), -1);
    for (const block of grown.blocks) await chain.mine(block.logs, block.leafCount);
    await chain.caughtUp(grown.leafCount);
    const { source: src } = source(chain, "session");
    await src.sync();
    expect(src.state.leafCount).toBe(grown.leafCount);
    const grownBlock = src.state.block;

    // the block that added the leaves is dropped; the chain goes on with empty blocks
    await chain.rpc("evm_revert", tip);
    await chain.rpc("evm_setAutomine", false);
    chain.leafCount = base.leafCount;
    while ((await chain.head()) <= grownBlock) await chain.mine([], base.leafCount);
    await chain.caughtUp(base.leafCount);

    const result = await src.sync();
    expect(result.rewoundTo).toBeDefined();
    expect(src.state.leafCount).toBe(base.leafCount);
    expect(src.state.block).toBe(await chain.head());
    expect(hex(src.state.root)).toBe(hex(base.root));
  });
});

/** Fork blocks of `count` new notes after `kept`, one of them under `tag`, with true roots. */
function forkLogs(kept: Uint8Array[], count: number, tag: Uint8Array, taggedOffset: number) {
  const leaves = [...kept];
  const word = (n: number) => "0x" + n.toString(16).padStart(64, "0");
  const scalar = () => {
    const b = new Uint8Array(randomBytes(32));
    b[0]! &= 0x0f;
    return b;
  };
  const blocks: { logs: FixtureLog[]; leafCount: number }[] = [];
  let taggedAt = -1;
  let root: Uint8Array = new Uint8Array(32);
  for (let start = 0; start < count; start += 6) {
    const logs: FixtureLog[] = [];
    for (let k = start; k < Math.min(start + 6, count); k++) {
      const index = leaves.length;
      const commitment = scalar();
      leaves.push(commitment);
      const all = new Uint8Array(leaves.length * 32);
      leaves.forEach((l, i) => all.set(l, i * 32));
      root = wasm.treeRoot(leaves.length, new Uint8Array(0), all);
      const own = k === taggedOffset ? tag : scalar();
      if (k === taggedOffset) taggedAt = index;
      logs.push({
        log_index: logs.length,
        address: fixture.pool,
        topics: [fixture.topics.LeafInserted!, word(index)],
        data: "0x" + hex(commitment) + hex(root),
      });
      let data = "0x" + hex(own);
      for (let w = 0; w < 7; w++) data += hex(scalar());
      logs.push({
        log_index: logs.length,
        address: fixture.pool,
        topics: [fixture.topics.NewNote!, word(index), "0x" + hex(commitment)],
        data,
      });
    }
    blocks.push({ logs, leafCount: leaves.length });
  }
  return { blocks, leafCount: leaves.length, root, taggedAt, leaves };
}

