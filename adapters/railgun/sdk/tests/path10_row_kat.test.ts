import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const row = Uint8Array.from(
  Buffer.from(
    readFileSync(new URL("./fixtures/path10_row.hex", import.meta.url), "utf8").trim(),
    "hex",
  ),
);

describe("PPOI v2 path-10 Rust wire KAT", () => {
  it("decodes the pinned 512-byte row at the TypeScript boundary", () => {
    expect(row).toHaveLength(512);
    expect(Buffer.from(row.slice(0, 32)).toString("hex")).toBe(
      "00".repeat(16) + "11".repeat(16),
    );
    expect(row[32]).toBe(0);
    expect(row[33]).toBe(0);
    expect(new TextDecoder().decode(row.slice(34, 38))).toBe("RVP2");
    expect(row.slice(38, 390)).toHaveLength(11 * 32);
    expect(row.slice(38, 390).some((byte) => byte !== 0)).toBe(true);
    expect(row.slice(390).every((byte) => byte === 0)).toBe(true);
  });
});
