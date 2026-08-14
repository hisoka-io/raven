// TypeScript half of the cross-language Poseidon KAT.
//
// The oracle is a SINGLE file, read by both languages from its one canonical location:
// `adapters/railgun/poseidon/tests/fixtures/poseidon_parity.txt`. This test and
// `adapters/railgun/poseidon/tests/parity_kat.rs` open the same bytes on disk, and neither
// regenerates it. A KAT that regenerates on failure re-blesses the divergence it exists to
// catch, and two copies of the oracle can drift while each side stays green against its own.
//
// This matters because the SDK folds auth-path siblings into a root IN TYPESCRIPT and
// verifies it against a root the CHAIN produced via the Rust IMT. Any divergence means a
// wallet either rejects a valid path or accepts one against a root nobody holds - and
// until now nothing anywhere compared the two implementations.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { foldMerkleRoot, hashLeftRight } from "../src/poseidon";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE = readFileSync(
  join(HERE, "..", "..", "poseidon", "tests", "fixtures", "poseidon_parity.txt"),
  "utf8",
);

function rows(tag: string): string[][] {
  return FIXTURE.split("\n")
    .filter((l) => !l.startsWith("#") && l.trim() !== "")
    .map((l) => l.trim().split(/\s+/))
    .filter((f) => f[0] === tag);
}

describe("poseidon cross-language parity", () => {
  it("the fixture is the full vector set", () => {
    expect(rows("zero")).toHaveLength(1);
    expect(rows("h").length).toBeGreaterThanOrEqual(256);
    expect(rows("f").length).toBeGreaterThanOrEqual(64);
  });

  it("hashLeftRight matches the Rust merkle_node on every vector", () => {
    for (const [i, c] of rows("h").entries()) {
      const [, left, right, want] = c;
      expect(hashLeftRight(left, right), `vector ${i}`).toBe(want);
    }
  });

  it("foldMerkleRoot reproduces every Rust root", () => {
    for (const [i, c] of rows("f").entries()) {
      const leaf = c[1];
      const siblings = c.slice(2, 18);
      const indices = BigInt(c[18]);
      const want = c[19];
      expect(siblings).toHaveLength(16);
      expect(foldMerkleRoot(leaf, siblings, indices), `fold ${i}`).toBe(want);
    }
  });

  it("the fold is order-sensitive, so the test can actually fail", () => {
    // Guards the guard: if hashLeftRight ignored argument order, every vector above
    // would pass under a broken implementation.
    const c = rows("h")[0];
    expect(hashLeftRight(c[2], c[1])).not.toBe(c[3]);
  });
});

describe("padTo64 must not silently truncate", () => {
  const VALID = "01".repeat(32);

  it("an over-long input is refused, not silently shortened", () => {
    // 66 chars: one byte too many. Keeping the LAST 64 drops the first byte and hashes a
    // DIFFERENT field element with no error - the caller gets a plausible root for input
    // it never supplied.
    const tooLong = `aa${VALID}`;
    expect(() => hashLeftRight(tooLong, VALID)).toThrow(/64/);
  });

  it("a short input is still zero-padded, which is the documented contract", () => {
    expect(() => hashLeftRight("01", VALID)).not.toThrow();
    expect(hashLeftRight("01", VALID)).toBe(
      hashLeftRight("01".padStart(64, "0"), VALID),
    );
  });

  it("a 0x prefix is still stripped before the length check", () => {
    expect(hashLeftRight(`0x${VALID}`, VALID)).toBe(hashLeftRight(VALID, VALID));
  });

  it("non-hex characters are refused rather than reaching the hasher", () => {
    expect(() => hashLeftRight(`zz${VALID.slice(2)}`, VALID)).toThrow();
  });

  it("foldMerkleRoot refuses an over-long sibling", () => {
    expect(() => foldMerkleRoot(VALID, [`bb${VALID}`], 0n)).toThrow(/64/);
  });
});
