// Howl's wallet ports over the source: discovery passes through, and a witness is keyed by the
// note's commitment and refused for a note the wallet did not find, another leaf, or a root the
// pool does not know.
import { describe, expect, it } from "vitest";
import {
  bigintField,
  discoverySource,
  missRecord,
  RavenHowlSource,
  witnessSource,
  type DiscoveryReads,
  type MerkleWitness,
} from "../src/index.js";
import { hex, wasm } from "./helpers/fixture.js";
import { Pool, served } from "./helpers/pool.js";

describe("Howl's DiscoverySource", () => {
  it("forwards the three calls and their answers unchanged", async () => {
    const calls: string[] = [];
    const record = missRecord(bigintField);
    const reads: DiscoveryReads<bigint> = {
      probeFirst: async (tags) => {
        calls.push(`probe ${tags.join(",")}`);
        return tags.map((tag) => ({ tag, record, occurrenceCount: 0, positions: [], records: [] }));
      },
      fetchOccurrences: async (requests) => {
        calls.push(`occurrences ${requests.length}`);
        return requests.map(() => null);
      },
      fetchLeafBlock: async (b) => {
        calls.push(`block ${b}`);
        return [BigInt(b)];
      },
    };
    const port = discoverySource(reads);
    expect(await port.probeFirst([3n, 4n])).toEqual([
      { tag: 3n, record, occurrenceCount: 0, positions: [], records: [] },
      { tag: 4n, record, occurrenceCount: 0, positions: [], records: [] },
    ]);
    expect(await port.fetchOccurrences([{ tag: 3n, occurrence: 1 }])).toEqual([null]);
    expect(await port.fetchLeafBlock(2)).toEqual([2n]);
    expect(calls).toEqual(["probe 3,4", "occurrences 1", "block 2"]);
    expect(Object.keys(port).sort()).toEqual(["fetchLeafBlock", "fetchOccurrences", "probeFirst"]);
  });
});

describe("Howl's MerkleWitnessSource", () => {
  const pool = new Pool(1_100, new Map());
  const commitment = (p: number): bigint => bigintField.fromBytes(pool.leaves.slice(p * 32, (p + 1) * 32));
  const known = (root: bigint): boolean => hex(bigintField.toBytes(root)) === hex(pool.root);

  function port(found: Map<bigint, number>, isKnownRoot = async (root: bigint) => known(root)) {
    const source = new RavenHowlSource({ transport: served(pool, new Set()), wasm, field: bigintField });
    const seen: [MerkleWitness<bigint>, boolean][] = [];
    const ws = witnessSource({
      source,
      field: bigintField,
      leafIndexOf: (c) => found.get(c),
      isKnownRoot,
      observe: (w, k) => {
        seen.push([w, k]);
      },
    });
    return { ws, seen };
  }

  it("builds the path of a found note from its commitment, folding to the pool's root", async () => {
    const { ws, seen } = port(new Map([[commitment(100), 100]]));
    const w = await ws.witnessFor(commitment(100));
    expect(w.leafIndex).toBe(100);
    expect(w.siblings.length).toBe(32);
    const siblings = new Uint8Array(32 * 32);
    w.siblings.forEach((s, i) => siblings.set(bigintField.toBytes(s), i * 32));
    expect(hex(wasm.foldPath(bigintField.toBytes(commitment(100)), 100, siblings))).toBe(hex(pool.root));
    expect(hex(bigintField.toBytes(w.root))).toBe(hex(pool.root));
    expect(seen.map(([x, k]) => [x.leafIndex, x.leafCount, k])).toEqual([[100, 1_100, true]]);
  });

  it("refuses a commitment the wallet did not find", async () => {
    const { ws, seen } = port(new Map());
    await expect(ws.witnessFor(commitment(100))).rejects.toThrow(/not a note this wallet found/);
    expect(seen).toEqual([]);
  });

  it("refuses a tree leaf that is not the commitment", async () => {
    // the wallet's map points the note at a neighbour's position
    const { ws, seen } = port(new Map([[commitment(101), 100]]));
    await expect(ws.witnessFor(commitment(101))).rejects.toMatchObject({ kind: "Protocol", message: /another commitment/ });
    expect(seen).toEqual([]);
  });

  it("refuses a root the pool does not know, after showing it to the observer", async () => {
    const { ws, seen } = port(new Map([[commitment(100), 100]]), async () => false);
    await expect(ws.witnessFor(commitment(100))).rejects.toMatchObject({ kind: "Protocol", message: /not known to the pool/ });
    expect(seen.map(([x, k]) => [x.leafIndex, k])).toEqual([[100, false]]);
  });
});
