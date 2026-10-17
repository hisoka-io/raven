// Offline known-answer tests: the wasm against answers the fixture node served, the fixture
// chain Howl's code produced, and the sizes the native suite pins.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { decodeCell, KIND, PrefixFeed, bigintField, tagPrefix } from "../src/index.js";
import { chainRoots, fixture, fixtureFile, hex, unhex, walletTags, wasm } from "./helpers/fixture.js";

// SHA-256 of each route's answer on the fixture chain, as the node's own suite pins them.
const NODE_PINS: Record<string, string> = {
  "params.bin": "47c144e937dd62769c92892c199acc69de0066f2d4bb78444e875235839a0d9c",
  "prefixes-0.bin": "49a44d2ab56fbdfc5f57ba713e98e6a7c76a0904ad38534d9a2b18f8da4f2edc",
  "prefixes-150.bin": "939f311abfd55b30d2ca5bb1e95df34bf520537ab85b3ac35c7e63967ac17bc9",
  "block-0.bin": "75769077eb6fb0a94b116e5f616c188fbbc60f88242999f3103263bd54fbf83b",
  "upper-0.bin": "b6c0471f1b3a5d03ff436b385fe587cd3504396cf3cac691a437915151e7a7bd",
  "sync-100-0.bin": "6dc751b78d9b2a24800ba1efa0354be06413ee148253f3dc5eee86e6e687f49f",
  "stale-161.bin": "984447469cff283a66b0b9ccc21f491dd67427f7aeef21304cdcd7670eb68014",
};

const feedRows = (from: number, to: number): string =>
  fixture.leaves
    .slice(from, to)
    .map((l) => l.prefix.slice(2))
    .join("");

const LAST_BLOCK = fixture.blocks[fixture.blocks.length - 1]!.number;

describe("answers the fixture node served", () => {
  it("are the bytes the node's suite pins", () => {
    for (const [file, digest] of Object.entries(NODE_PINS)) {
      expect(createHash("sha256").update(fixtureFile(file)).digest("hex"), file).toBe(digest);
    }
  });

  it("decode to the fixture's feed, leaves and root", () => {
    const feed = wasm.decodeAnswer(fixtureFile("prefixes-0.bin"));
    expect([feed.kind, feed.leafCount, feed.block, feed.base, feed.next]).toEqual([
      KIND.prefixes,
      160,
      LAST_BLOCK,
      0,
      160,
    ]);
    expect(hex(feed.root)).toBe(fixture.root.slice(2));
    expect(hex(feed.rows)).toBe(feedRows(0, 160));

    const tail = wasm.decodeAnswer(fixtureFile("prefixes-150.bin"));
    expect([tail.base, tail.next, hex(tail.rows)]).toEqual([150, 160, feedRows(150, 160)]);

    const block = wasm.decodeAnswer(fixtureFile("block-0.bin"));
    expect([block.kind, block.blockIndex]).toEqual([KIND.block, 0]);
    expect(hex(block.blockLeaves)).toBe(fixture.leaves.map((l) => l.commitment.slice(2)).join(""));

    const upper = wasm.decodeAnswer(fixtureFile("upper-0.bin"));
    expect([upper.kind, upper.upperBase, upper.upperNext, upper.upperNodes.length]).toEqual([KIND.upper, 0, 0, 0]);

    const sync = wasm.decodeAnswer(fixtureFile("sync-100-0.bin"));
    expect([sync.kind, sync.base, sync.next, sync.blockIndex]).toEqual([KIND.sync, 100, 160, 0]);
    expect(hex(sync.rows)).toBe(feedRows(100, 160));
    expect(hex(sync.blockLeaves)).toBe(hex(block.blockLeaves));

    const stale = wasm.decodeAnswer(fixtureFile("stale-161.bin"));
    expect([stale.kind, stale.leafCount, stale.block]).toEqual([KIND.stale, 160, LAST_BLOCK]);

    const params = wasm.decodeAnswer(fixtureFile("params.bin"));
    expect([params.kind, params.paramSet, params.ladderCap, params.sessionTtlSecs]).toEqual([KIND.params, 1, 16, 3600]);
  });

  it("refuses an answer whose parts disagree with its header", () => {
    const bytes = fixtureFile("block-0.bin");
    const fewer = bytes.slice();
    // leaf count 100 in the header, 160 leaves in the body
    new DataView(fewer.buffer).setBigUint64(8, 100n, false);
    expect(() => wasm.decodeAnswer(fewer)).toThrow(/carries 160 leaves/);
    const version = bytes.slice();
    version[1] = 2;
    expect(() => wasm.decodeAnswer(version)).toThrow(/wire version/);
    const set = bytes.slice();
    set[3] = 3;
    expect(() => wasm.decodeAnswer(set)).toThrow(/parameter set/);
    expect(() => wasm.decodeAnswer(bytes.subarray(0, bytes.length - 1))).toThrow();
    expect(() => wasm.decodeAnswer(new Uint8Array([...bytes, 0]))).toThrow(/past the end/);
  });
});

describe("the private-read client", () => {
  const params = fixtureFile("params.bin");

  it("draws a new secret per client and resends one key", () => {
    const a = new wasm.HowlClient(params);
    const b = new wasm.HowlClient(params);
    try {
      expect(a.sessionBody().length).toBe(46_256);
      expect(hex(a.sessionBody())).toBe(hex(a.sessionBody()));
      expect(hex(a.sessionBody())).not.toBe(hex(b.sessionBody()));
      expect(a.hasSession).toBe(false);
      expect(a.ladderCap).toBe(16);
    } finally {
      a.free();
      b.free();
    }
  });

  it("pads to the ladder and pins the inline sizes the native suite pins", () => {
    for (const [real, slots] of [
      [1, 1],
      [2, 2],
      [3, 4],
      [5, 8],
      [9, 16],
      [16, 16],
    ] as const) {
      const client = new wasm.HowlClient(params);
      try {
        const batch = client.buildBatch(new Uint32Array(real).fill(7), 160);
        expect(batch.slots).toBe(slots);
        expect(batch.targets.length).toBe(slots);
        expect(batch.realSlots.length).toBe(real);
        expect(batch.body.length).toBe(24 + 46_244 + 15_477 * slots);
        // the key the batch carries is the session key, byte for byte
        expect(hex(batch.body.subarray(8, 8 + 46_252))).toBe(hex(client.sessionBody().subarray(4)));
        batch.free();
        // the key goes out inline once per client
        expect(() => client.buildBatch(new Uint32Array([7]), 160)).toThrow(/new client per request/);
      } finally {
        client.free();
      }
    }
  });

  it("refuses what it cannot read", () => {
    const client = new wasm.HowlClient(params);
    try {
      expect(() => client.buildBatch(new Uint32Array([]), 160)).toThrow(/1 to 16/);
      expect(() => client.buildBatch(new Uint32Array(17), 160)).toThrow(/1 to 16/);
      expect(() => client.buildBatch(new Uint32Array([160]), 160)).toThrow(/not below/);
      expect(() => client.buildBatch(new Uint32Array([1]), 1.5)).toThrow(/whole number/);
      expect(() => client.installSession(fixtureFile("block-0.bin"))).toThrow(/session answer/);
      const batch = client.buildBatch(new Uint32Array([1]), 160);
      expect(() => client.openNotes(batch, fixtureFile("stale-161.bin"))).toThrow(/behind/);
      batch.free();
    } finally {
      client.free();
    }
    const other = params.slice();
    // entry bytes 512
    new DataView(other.buffer).setUint32(56, 512, false);
    expect(() => new wasm.HowlClient(other)).toThrow(/256/);
    expect(() => new wasm.HowlClient(fixtureFile("sync-100-0.bin"))).toThrow(/params answer/);
  });
});

describe("tree arithmetic", () => {
  const roots = chainRoots();
  const leaves = fixture.leaves.map((l) => unhex(l.commitment));
  const all = new Uint8Array(leaves.length * 32);
  leaves.forEach((l, i) => all.set(l, i * 32));

  it("folds every leaf at every count to the chain's root at that count", () => {
    expect(roots.size).toBe(160);
    let folds = 0;
    for (let n = 1; n <= leaves.length; n++) {
      const tail = all.subarray(0, n * 32);
      expect(hex(wasm.treeRoot(n, new Uint8Array(0), tail)), `root at ${n}`).toBe(roots.get(n));
      for (const index of new Set([0, 1, n - 2, n - 1, (n * 7) % n].filter((i) => i >= 0 && i < n))) {
        const path = wasm.merklePath(index, n, new Uint8Array(0), tail, all);
        const siblings = path.subarray(0, 32 * 32);
        expect(hex(path.subarray(32 * 32))).toBe(roots.get(n));
        expect(hex(wasm.foldPath(leaves[index]!, index, siblings)), `${index} at ${n}`).toBe(roots.get(n));
        folds += 1;
      }
    }
    expect(folds).toBeGreaterThan(600);
  });

  it("refuses a path for another leaf, a count past the leaves and a right child at an empty level", () => {
    const tail = all.subarray(0, 160 * 32);
    const path = wasm.merklePath(5, 160, new Uint8Array(0), tail, all).subarray(0, 32 * 32);
    expect(hex(wasm.foldPath(leaves[6]!, 5, path))).not.toBe(roots.get(160));
    expect(() => wasm.merklePath(5, 161, new Uint8Array(0), tail, all)).toThrow(/needed/);
    expect(() => wasm.merklePath(160, 160, new Uint8Array(0), tail, all)).toThrow(/not below/);
    const lone = wasm.merklePath(159, 160, new Uint8Array(0), tail, all).subarray(0, 32 * 32);
    // leaf 159 is a right child at level 0; zero that sibling and the fold must refuse
    const broken = lone.slice();
    broken.fill(0, 0, 32);
    expect(() => wasm.foldPath(leaves[159]!, 159, broken)).toThrow(/right child/);
  });

  it("blockNode of a partial block is the carried node treeRoot builds", () => {
    expect(hex(wasm.blockNode(all))).toBe(roots.get(160));
  });
});

describe("cells and the feed", () => {
  it("decodes every fixture cell at its position and refuses a moved one", () => {
    let notes = 0;
    for (const leaf of fixture.leaves) {
      if (leaf.cell === null) continue;
      const cell = unhex(leaf.cell);
      const record = decodeCell(cell, leaf.leaf_index, bigintField);
      expect(record.leafIndex).toBe(leaf.leaf_index);
      expect(hex(record.commitmentPrefix)).toBe(leaf.commitment.slice(2, 34));
      expect(record.recordKind).toBe(leaf.kind === "memo" ? 1 : 0);
      expect(record.ciphertextKept.length).toBe(5);
      expect(() => decodeCell(cell, leaf.leaf_index + 1, bigintField)).toThrow(/leaf index/);
      notes += 1;
    }
    expect(notes).toBe(159);
    const padded = unhex(fixture.leaves[1]!.cell!);
    padded[250] = 1;
    expect(() => decodeCell(padded, 1, bigintField)).toThrow(/padding/);
  });

  it("finds each fixture wallet's notes and nothing else", () => {
    const feed = new PrefixFeed();
    feed.append(0, wasm.decodeAnswer(fixtureFile("prefixes-0.bin")).rows);
    for (const wallet of fixture.wallets) {
      const tags = walletTags(wallet);
      const positions = [...new Set(feed.matches(tags).map((m) => m.position))];
      expect(positions, wallet.label).toEqual([...wallet.owned_leaves].sort((a, b) => a - b));
    }
    expect(feed.matches([new Uint8Array(32)])).toEqual([]);
    expect(hex(tagPrefix(unhex(fixture.leaves[1]!.tag!)))).toBe(fixture.leaves[1]!.prefix.slice(2));
    expect(() => feed.append(100, new Uint8Array(6))).toThrow(/start at 100/);
  });
});

// Produced by Howl's own wallet code (tests/howl.test.ts regenerates and compares them where a
// Howl checkout is present): its key derivation for each fixture wallet and its decode of each cell.
interface Vectors {
  wallets: {
    label: string;
    sk_view: string;
    self_keys: { index: number; x: string; even_y: boolean }[];
    incoming_keys: { index: number; x: string; even_y: boolean }[];
  }[];
  cells: {
    leaf_index: number;
    layout_version: number;
    record_kind: number;
    commitment_prefix: string;
    ephemeral_pk_x: string;
    cek_wrap: string;
    ciphertext_kept: string[];
  }[];
}

describe("vectors pinned from Howl's own wallet code", () => {
  const vectors = JSON.parse(
    readFileSync(new URL("./fixtures/howl-vectors.json", import.meta.url), "utf8"),
  ) as Vectors;
  const word = (v: bigint) => "0x" + v.toString(16).padStart(64, "0");

  it("Howl's key derivation gives the fixture wallets' keys", () => {
    expect(vectors.wallets.map((w) => w.label)).toEqual(fixture.wallets.map((w) => w.label));
    vectors.wallets.forEach((v, i) => {
      const w = fixture.wallets[i]!;
      expect(v.sk_view, w.label).toBe(w.sk_view);
      expect(v.self_keys, w.label).toEqual(w.self_keys);
      expect(v.incoming_keys, w.label).toEqual(w.incoming_keys);
    });
  });

  it("Howl's decode of every cell is this package's", () => {
    const cells = fixture.leaves.filter((l) => l.cell !== null);
    expect(vectors.cells.length).toBe(cells.length);
    vectors.cells.forEach((v, i) => {
      const r = decodeCell(unhex(cells[i]!.cell!), cells[i]!.leaf_index, bigintField);
      expect(
        {
          leaf_index: r.leafIndex,
          layout_version: r.layoutVersion,
          record_kind: r.recordKind,
          commitment_prefix: "0x" + hex(r.commitmentPrefix),
          ephemeral_pk_x: word(r.ephemeralPkX),
          cek_wrap: word(r.cekWrap),
          ciphertext_kept: r.ciphertextKept.map(word),
        },
        `cell ${v.leaf_index}`,
      ).toEqual(v);
    });
  });
});

/** The fixture's params answer as a set-2 node sends it: set id 2 and no key material. */
function setTwoParams(): Uint8Array {
  const set1 = fixtureFile("params.bin");
  // header, then entry bytes, rows per shard, ladder cap and lifetime: 56 + 14 bytes
  const out = new Uint8Array(56 + 14 + 4);
  out.set(set1.subarray(0, 56 + 14));
  out[3] = 2;
  return out;
}

describe("the private-read client on parameter set 2", () => {
  const params = setTwoParams();

  it("follows the set the node names, with its own key sizes", () => {
    expect(wasm.decodeAnswer(params).paramSet).toBe(2);
    const a = new wasm.HowlClient(params);
    const b = new wasm.HowlClient(params);
    try {
      expect(a.paramSet).toBe(2);
      expect(a.sessionBody().length).toBe(4 + 15_360);
      expect([...a.sessionBody().subarray(0, 4)]).toEqual([0, 1, 0, 2]);
      expect(hex(a.sessionBody())).toBe(hex(a.sessionBody()));
      expect(hex(a.sessionBody())).not.toBe(hex(b.sessionBody()));
      for (const [real, slots] of [
        [1, 1],
        [3, 4],
        [9, 16],
      ] as const) {
        const client = new wasm.HowlClient(params);
        try {
          const batch = client.buildBatch(new Uint32Array(real).fill(7), 160);
          expect(batch.slots).toBe(slots);
          expect(batch.body.length).toBe(4 + 1 + 15_360 + 2 + 7_460 * slots);
          // source 2, then the session key byte for byte
          expect(batch.body[4]).toBe(2);
          expect(hex(batch.body.subarray(5, 5 + 15_360))).toBe(hex(client.sessionBody().subarray(4)));
          batch.free();
          expect(() => client.buildBatch(new Uint32Array([7]), 160)).toThrow(/new client per request/);
        } finally {
          client.free();
        }
      }
    } finally {
      a.free();
      b.free();
    }
  });

  it("refuses key material the set fixes, and answers of the other set", () => {
    const withCrs = new Uint8Array(params.length + 1);
    withCrs.set(params);
    new DataView(withCrs.buffer).setUint32(56 + 14, 1, false);
    expect(() => new wasm.HowlClient(withCrs)).toThrow(/key material/);
    const client = new wasm.HowlClient(params);
    try {
      const batch = client.buildBatch(new Uint32Array([1]), 160);
      // a set-1 answer to a set-2 client's request
      expect(() => client.openNotes(batch, fixtureFile("stale-161.bin"))).toThrow(/parameter set 1/);
      batch.free();
    } finally {
      client.free();
    }
  });
});
