// The README's table of sizes on the wire, held to what the wasm builds. Upload sizes are measured
// here; the download sizes are the ones the node and live suites pin (9,874 and 9,212 B per slot,
// 58 B of header and count).
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { fixtureFile, wasm } from "./helpers/fixture.js";

interface SetSizes {
  key: number;
  slotUp: number;
  slotDown: number;
  framingUp: number;
  framingDown: number;
  inline: number;
}

const SIZES: Record<1 | 2, SetSizes> = {
  1: { key: 46_256, slotUp: 15_477, slotDown: 9_874, framingUp: 24, framingDown: 58, inline: 46_244 },
  2: { key: 4 + 15_394, slotUp: 7_460, slotDown: 9_212, framingUp: 15, framingDown: 58, inline: 15_386 },
};

/** The fixture's params answer as a set-2 node sends it (as in kat.test.ts). */
function params(set: 1 | 2): Uint8Array {
  const set1 = fixtureFile("params.bin");
  if (set === 1) return set1;
  const out = new Uint8Array(56 + 14 + 4 + 2);
  out.set(set1.subarray(0, 56 + 14));
  out[3] = 2;
  out.set([0, 0, 0, 2, 0, 2], 56 + 14);
  return out;
}

const n = (v: number): string => v.toLocaleString("en-US");

/** The cells of the README row that starts with `label`, past the label. */
function row(readme: string, label: string): string[] {
  const line = readme.split("\n").find((l) => l.startsWith(`| ${label} |`));
  if (line === undefined) throw new Error(`the README has no "${label}" row`);
  return line.split("|").slice(2, -1).map((c) => c.trim());
}

describe("the README's sizes on the wire", () => {
  const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");

  for (const set of [1, 2] as const) {
    it(`parameter set ${set}: the wasm builds the uploads the table states`, () => {
      const s = SIZES[set];
      const client = new wasm.HowlClient(params(set));
      try {
        expect(client.paramSet).toBe(set);
        expect(client.sessionBody().length).toBe(s.key);
      } finally {
        client.free();
      }
      for (const slots of [1, 4, 16]) {
        const c = new wasm.HowlClient(params(set));
        try {
          const batch = c.buildBatch(new Uint32Array(slots).fill(7), 160);
          expect(batch.body.length).toBe(s.framingUp + s.inline + s.slotUp * slots);
          batch.free();
        } finally {
          c.free();
        }
      }
    });
  }

  it("states every size the suites pin", () => {
    const col = (set: 1 | 2) => set - 1;
    for (const set of [1, 2] as const) {
      const s = SIZES[set];
      expect(row(readme, "Session key upload (once per session)")[col(set)]).toBe(n(s.key));
      expect(row(readme, "Private read, per slot of a batch, session mode")[col(set)]).toBe(
        `${n(s.slotUp)} up, ${n(s.slotDown)} down`,
      );
      expect(row(readme, "Batch framing")[col(set)]).toBe(`${n(s.framingUp)} up, ${n(s.framingDown)} down`);
      expect(row(readme, "Key carried inline")[col(set)]).toBe(`${n(s.inline)} more per request`);
    }
  });
});
