// What a wallet decides from the feed and the cells: every matched row is read, position 0 is
// never read, and a cell that opens is held to the verified tree's leaf. Runs where live.test.ts does.
import { existsSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  bigintField,
  fetchTransport,
  HowlError,
  RavenHowlSource,
  type HowlNoteRecord,
  type HowlTransport,
} from "../src/index.js";
import { LocalChain } from "./helpers/chain.js";
import { fixture, hex, unhex, wasm } from "./helpers/fixture.js";

const BIN = process.env.HOWL_NODE_BIN ?? "";
const live = BIN !== "" && existsSync(BIN);

function recorded(url: string): HowlTransport & { paths: string[] } {
  const inner = fetchTransport(url);
  const paths: string[] = [];
  return {
    paths,
    get: async (path) => (paths.push(`GET ${path}`), inner.get(path)),
    post: async (path, body) => (paths.push(`POST ${path}`), inner.post(path, body)),
  };
}

const commitment = (p: number): bigint => BigInt(fixture.leaves[p]!.commitment);
const prefixOf = (p: number): string => hex(unhex(fixture.leaves[p]!.commitment).subarray(0, 16));

describe.skipIf(!live)("wallet-side integrity against a running node", () => {
  let chain: LocalChain;
  let url = "";

  beforeAll(async () => {
    chain = await LocalChain.start();
    await chain.mineFixture(0, fixture.blocks.length);
    url = await chain.startNode(BIN);
    await chain.caughtUp();
  });

  afterAll(async () => {
    await chain?.stop();
  });

  it("a row of another note that matches a tag's six bytes first does not hide the tag's own note", async () => {
    // Rows 39 and 129 share their six bytes. A tag with those low bytes and other high bytes
    // stands for a wallet whose note is at 129, while row 39 belongs to another note.
    const real = 129;
    const shared = unhex(fixture.leaves[real]!.prefix);
    const tagBytes = new Uint8Array(32).fill(0x11);
    tagBytes.set(shared, 26);
    const tag = bigintField.fromBytes(tagBytes);
    // only the tag's own note opens for this wallet
    const opens = (r: HowlNoteRecord<bigint>): boolean => hex(r.commitmentPrefix) === prefixOf(real);

    const transport = recorded(url);
    const src = new RavenHowlSource({ transport, wasm, field: bigintField });
    await src.sync();
    expect(src.matches([tag]).map((m) => m.position)).toEqual([39, real]);
    const [first] = await src.probeFirst([tag]);
    expect(first!.occurrenceCount).toBe(2);
    expect(first!.positions).toEqual([39, real]);
    expect(first!.records.map((r) => r.leafIndex)).toEqual([39, real]);
    // control: the first record alone makes the tag look free
    expect(opens(first!.record)).toBe(false);
    expect(first!.records.some(opens)).toBe(true);
    // round 2 is answered from the cells round 1 read
    const mark = transport.paths.length;
    const [second] = await src.fetchOccurrences([{ tag, occurrence: 1 }]);
    expect(second!.leafIndex).toBe(real);
    expect(transport.paths.slice(mark)).toEqual([]);
    // the synced feed view gives the same positions, with no request
    const view = src.feed;
    expect(view.length).toBe(fixture.leaves.length);
    expect(view.matches([tagBytes]).map((m) => m.position)).toEqual([39, real]);
    expect("truncate" in view || "append" in view).toBe(false);
    expect(transport.paths.slice(mark)).toEqual([]);
    src.close();
  });

  it("position 0 is never read", async () => {
    const transport = recorded(url);
    const src = new RavenHowlSource({ transport, wasm, field: bigintField, keyMode: "inline" });
    await expect(src.fetchNotes([0])).rejects.toThrow(/genesis filler/);
    await expect(src.fetchNotes([5, 0])).rejects.toThrow(/genesis filler/);
    expect(transport.paths.filter((p) => p.startsWith("POST"))).toEqual([]);
    // control: the same call without 0 reads
    expect((await src.fetchNotes([5]))[0]!.leafIndex).toBe(5);
    expect(transport.paths.filter((p) => p.startsWith("POST"))).toEqual(["POST /howl/v1/notes"]);
  });

  it("a note that opens is held to the verified tree's leaf at its position", async () => {
    const src = new RavenHowlSource({ transport: fetchTransport(url), wasm, field: bigintField });
    const [record] = await src.fetchNotes([77]);
    // the true commitment passes
    expect(await src.confirmNote(record!, commitment(77))).toBe("confirmed");
    // a phantom: a cell whose note opens, with the right prefix, but is not the tree's leaf
    const forged = commitment(77) ^ 1n;
    await expect(src.confirmNote(record!, forged)).rejects.toMatchObject({ kind: "Protocol" });
    await expect(src.confirmNote(record!, forged)).rejects.toThrow(/another commitment/);
    // a cell placed at another position than its note's
    const moved = { ...record!, leafIndex: 78 };
    await expect(src.confirmNote(moved, commitment(77))).rejects.toBeInstanceOf(HowlError);
    // a commitment that does not even carry the record's prefix
    await expect(src.confirmNote(record!, commitment(78))).rejects.toThrow(/prefix/);
    // every leaf of the chain passes, in the full block and in none held before
    for (const p of [1, 100, 159]) {
      const [r] = await src.fetchNotes([p]);
      await src.confirmNote(r!, commitment(p));
    }
    await expect(src.confirmNote({ ...record!, leafIndex: 0 }, commitment(0))).rejects.toThrow(/genesis/);
    src.close();
  });

  it("a witness at an older count carries the newest verified block", async () => {
    const src = new RavenHowlSource({ transport: fetchTransport(url), wasm, field: bigintField });
    const { block } = await src.sync();
    const older = await src.merkleWitness(10, 20);
    const newest = await src.merkleWitness(10);
    expect([older.block, newest.block]).toEqual([block, block]);
    expect(older.root).not.toBe(newest.root);
  });
});

describe("refusals a wallet may retry", () => {
  it("a node over its rate (429) is Busy and retryable, like a full queue (503); a 400 is not", async () => {
    const refusing = (status: number): HowlTransport => {
      const ex = async () => ({ status, body: new Uint8Array() });
      return { get: ex, post: ex };
    };
    const kindOf = async (status: number): Promise<[string, boolean, number | undefined]> => {
      const src = new RavenHowlSource({ transport: refusing(status), wasm, field: bigintField });
      const e = await src.fetchTagPrefixes(0).then(
        () => null,
        (e: unknown) => e,
      );
      expect(e).toBeInstanceOf(HowlError);
      const err = e as HowlError;
      return [err.kind, err.retryable, err.status];
    };
    expect(await kindOf(429)).toEqual(["Busy", true, 429]);
    expect(await kindOf(503)).toEqual(["Busy", true, 503]);
    expect(await kindOf(400)).toEqual(["Refused", false, 400]);
  });
});
