/** Unit tests for the SDK's exported helper primitives. */

import { describe, expect, it } from "vitest";

import {
  containsByteSequence,
  hexToBytes,
  bytesToHex,
  decodeClientPirQueryBundle,
  statusByteToPOIStatus,
  PATH_RECORD_BYTES,
  TREE_DEPTH,
} from "../src/index";

describe("hex helpers", () => {
  it("bytesToHex round-trips through hexToBytes", () => {
    const cases = ["", "00", "ff", "deadbeef", "0123456789abcdef".repeat(8)];
    for (const c of cases) {
      const bytes = hexToBytes(c);
      const back = bytesToHex(bytes);
      expect(back).toBe(c);
    }
  });

  it("hexToBytes accepts 0x-prefixed input", () => {
    expect(Array.from(hexToBytes("0xdeadbeef"))).toEqual([0xde, 0xad, 0xbe, 0xef]);
  });

  it("hexToBytes accepts 0X-prefixed input (case-insensitive)", () => {
    expect(Array.from(hexToBytes("0XDEADBEEF"))).toEqual([0xde, 0xad, 0xbe, 0xef]);
  });

  it("hexToBytes rejects odd-length input", () => {
    expect(() => hexToBytes("abc")).toThrow(/odd-length/);
  });

  it("hexToBytes rejects invalid hex characters", () => {
    expect(() => hexToBytes("zz")).toThrow(/invalid hex pair/);
  });

  it("bytesToHex emits lowercase only", () => {
    expect(bytesToHex(new Uint8Array([0xab, 0xcd, 0xef]))).toBe("abcdef");
  });
});

describe("hexToBytes DEFECT DH-L0-8: non-hex input is silently accepted and mangled", () => {
  // CHARACTERIZATION PINS, not endorsements. `Number.parseInt(pair, 16)` returns a
  // number (not NaN) for any pair whose FIRST character parses — so only the
  // both-chars-invalid class ('zz', the single case the old test covered) is refused.
  // hexToBytes is the front door for every blinded commitment the wallet supplies
  // (client-pir.ts decodeStatusRow BC binding): a typo'd BC does not error, it decodes
  // to DIFFERENT bytes, the SDK looks up a different index, and a confident verdict
  // about the wrong commitment comes back. THE INVERSION A FIX MUST MAKE: every case
  // below must THROW (e.g. validate with /^[0-9a-fA-F]*$/ before decoding) — see the
  // it.fails trigger test underneath. Fix is owner-reserved (public-API throw surface).
  it("DEFECT: '4z' decodes to [0x04] instead of throwing", () => {
    expect(Array.from(hexToBytes("4z"))).toEqual([0x04]);
  });

  it("DEFECT: '1g2h' decodes to [0x01, 0x02] instead of throwing", () => {
    expect(Array.from(hexToBytes("1g2h"))).toEqual([0x01, 0x02]);
  });

  it("DEFECT: '+1' decodes to [0x01] — parseInt accepts a sign", () => {
    expect(Array.from(hexToBytes("+1"))).toEqual([0x01]);
  });

  it("DEFECT: ' 1' decodes to [0x01] — parseInt accepts leading whitespace", () => {
    expect(Array.from(hexToBytes(" 1"))).toEqual([0x01]);
  });

  // RED until the DH-L0-8 fix lands in src/client-pir.ts hexToBytes. Trigger: when
  // hexToBytes validates its input (owner ruling on refusal semantics), this flips from
  // expected-fail to fail and forces the un-marking plus deletion of the pins above.
  it.fails("hexToBytes rejects every string containing a non-hex character", () => {
    for (const bad of ["4z", "1g2h", "+1", " 1"]) {
      expect(() => hexToBytes(bad), `input ${JSON.stringify(bad)}`).toThrow(/invalid hex/);
    }
    // Seeded xorshift32 sweep: even-length strings over a mixed alphabet; any string
    // with a character outside [0-9a-fA-F] must throw. No new devDependency.
    const alphabet = "0123456789abcdefABCDEFghzZ+ .-_!";
    let s = 0x9e3779b9 | 0;
    const next = (): number => {
      s ^= s << 13;
      s ^= s >>> 17;
      s ^= s << 5;
      return (s >>> 0) % alphabet.length;
    };
    for (let i = 0; i < 512; i += 1) {
      const len = 2 * (1 + ((next() >>> 0) % 4));
      let str = "";
      for (let j = 0; j < len; j += 1) {
        str += alphabet[next()];
      }
      if (/^[0-9a-fA-F]*$/.test(str)) continue;
      expect(() => hexToBytes(str), `input ${JSON.stringify(str)}`).toThrow(/invalid hex/);
    }
  });
});

describe("path record constants", () => {
  it("PATH_RECORD_BYTES pins the per-leaf path record to 16 levels x 32 B = 512", () => {
    // Wire-relevant: PerLeafPath/PerListPath PIR cells are exactly this many bytes
    // (engine pir_table PATH_RECORD_BYTES); a drift silently misaligns every path row.
    expect(PATH_RECORD_BYTES).toBe(512);
    expect(PATH_RECORD_BYTES).toBe(TREE_DEPTH * 32);
  });
});

describe("containsByteSequence", () => {
  it("empty needle always matches", () => {
    expect(containsByteSequence(new Uint8Array(0), new Uint8Array(0))).toBe(true);
    expect(containsByteSequence(new Uint8Array([1, 2, 3]), new Uint8Array(0))).toBe(true);
  });

  it("needle longer than haystack never matches", () => {
    expect(
      containsByteSequence(new Uint8Array([1]), new Uint8Array([1, 2])),
    ).toBe(false);
  });

  it("matches at the start", () => {
    const haystack = new Uint8Array([1, 2, 3, 4, 5]);
    const needle = new Uint8Array([1, 2]);
    expect(containsByteSequence(haystack, needle)).toBe(true);
  });

  it("matches at the end", () => {
    const haystack = new Uint8Array([1, 2, 3, 4, 5]);
    const needle = new Uint8Array([4, 5]);
    expect(containsByteSequence(haystack, needle)).toBe(true);
  });

  it("matches in the middle", () => {
    const haystack = new Uint8Array([1, 2, 3, 4, 5]);
    const needle = new Uint8Array([3, 4]);
    expect(containsByteSequence(haystack, needle)).toBe(true);
  });

  it("rejects partial overlapping matches", () => {
    const haystack = new Uint8Array([1, 2, 3, 5]);
    const needle = new Uint8Array([3, 4]);
    expect(containsByteSequence(haystack, needle)).toBe(false);
  });

  it("matches a long needle", () => {
    const haystack = new Uint8Array(1000).fill(0xab);
    const needle = new Uint8Array(500).fill(0xab);
    expect(containsByteSequence(haystack, needle)).toBe(true);
  });

  it("rejects when only one byte differs", () => {
    const haystack = new Uint8Array(100).fill(0xab);
    haystack[42] = 0xcd;
    const needle = new Uint8Array(100).fill(0xab);
    expect(containsByteSequence(haystack, needle)).toBe(false);
  });
});

describe("statusByteToPOIStatus", () => {
  it("maps 0 -> Valid", () => {
    expect(statusByteToPOIStatus(0)).toBe("Valid");
  });
  it("maps 1 -> ShieldBlocked", () => {
    expect(statusByteToPOIStatus(1)).toBe("ShieldBlocked");
  });
  it("maps 2 -> ProofSubmitted", () => {
    expect(statusByteToPOIStatus(2)).toBe("ProofSubmitted");
  });
  it("maps 3 -> Missing", () => {
    expect(statusByteToPOIStatus(3)).toBe("Missing");
  });
  // PINS A SILENT DOWNGRADE, not a design choice. Any byte outside 0..3 is a row the SDK
  // does not understand, and it is answered with a real verdict instead of an error. A future
  // status the server adds -- or a corrupted byte a shorter row cannot bind -- reads as
  // "no record", which is the non-blocking answer. Raising a DecodeError here is the fix.
  it("maps every unknown byte to Missing instead of refusing the row", () => {
    for (const b of [4, 5, 99, 128, 255]) {
      expect(statusByteToPOIStatus(b), `byte ${b}`).toBe("Missing");
    }
  });
});

describe("decodeClientPirQueryBundle round-trip", () => {
  it("decodes a 0-len/0-len bundle", () => {
    const buf = new Uint8Array(16);
    const bundle = decodeClientPirQueryBundle(buf);
    expect(bundle.clientStateBincode.length).toBe(0);
    expect(bundle.queryBytes.length).toBe(0);
  });

  it("decodes a small state + query bundle", () => {
    const state = new Uint8Array([1, 2, 3, 4]);
    const query = new Uint8Array([5, 6, 7, 8, 9, 10]);
    const buf = new Uint8Array(8 + state.length + 8 + query.length);
    new DataView(buf.buffer).setUint32(0, state.length, true);
    buf.set(state, 8);
    new DataView(buf.buffer).setUint32(8 + state.length, query.length, true);
    buf.set(query, 8 + state.length + 8);
    const bundle = decodeClientPirQueryBundle(buf);
    expect(Array.from(bundle.clientStateBincode)).toEqual(Array.from(state));
    expect(Array.from(bundle.queryBytes)).toEqual(Array.from(query));
  });

  it("decoded slices are defensive copies (not views into the source)", () => {
    const state = new Uint8Array([1, 2, 3, 4]);
    const query = new Uint8Array([5, 6, 7, 8]);
    const buf = new Uint8Array(8 + state.length + 8 + query.length);
    new DataView(buf.buffer).setUint32(0, state.length, true);
    buf.set(state, 8);
    new DataView(buf.buffer).setUint32(8 + state.length, query.length, true);
    buf.set(query, 8 + state.length + 8);
    const bundle = decodeClientPirQueryBundle(buf);
    buf.fill(0xff);
    // decoded slices are copies, unaffected by the source mutation
    expect(bundle.clientStateBincode[0]).toBe(1);
    expect(bundle.queryBytes[0]).toBe(5);
  });
});
