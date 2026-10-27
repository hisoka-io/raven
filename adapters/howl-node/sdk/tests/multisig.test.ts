// The multisig adaptor and signing-session helpers against a running node replaying the fixture.
// The keys here stand in for Howl's: a fixture wallet's tags play one member's self ephemerals and
// the group's receiving addresses, and a cell "opens" to its chain note only under the tag the
// note was filed under, as decryption would. tests/howl.test.ts runs the same code on a FROST
// group with Howl's own keys, notes and scanner.
import { existsSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  bigintField,
  checkSigningSession,
  fetchTransport,
  MultisigRavenScan,
  openSigningSession,
  RavenHowlSource,
  SigningSessionRefused,
  type MultisigChainEvent,
  type MultisigEventScanner,
  type MultisigKeys,
  type MultisigTagSource,
  type SigningSession,
} from "../src/index.js";
import { countAfter, LocalChain } from "./helpers/chain.js";
import { chainRoots, fixture, wasm, type FixtureLog } from "./helpers/fixture.js";

const BIN = process.env.HOWL_NODE_BIN ?? "";
const live = BIN !== "" && existsSync(BIN);
const WINDOW = 16;
const big = (text: string) => BigInt(text);
const word = (data: string, i: number) => "0x" + data.slice(2 + 64 * i, 2 + 64 * (i + 1));

interface ChainNote {
  kind: "note" | "memo";
  commitment: string;
  tag: string;
  ephemeralX: string;
  cekWrap?: string;
  words: string[];
}

/** Every NewNote and NewPrivateMemo of the fixture, by leaf index. */
const chainNotes: Map<number, ChainNote> = (() => {
  const out = new Map<number, ChainNote>();
  const logs: FixtureLog[] = fixture.blocks.flatMap((b) => b.logs);
  for (const log of logs) {
    const index = Number(BigInt(log.topics[1] ?? "0x0"));
    if (log.topics[0] === fixture.topics.NewNote) {
      const words = Array.from({ length: 7 }, (_, i) => word(log.data, 1 + i));
      out.set(index, { kind: "note", commitment: log.topics[2]!, tag: word(log.data, 0), ephemeralX: word(log.data, 0), words });
    } else if (log.topics[0] === fixture.topics.NewPrivateMemo) {
      const words = Array.from({ length: 7 }, (_, i) => word(log.data, 2 + i));
      out.set(index, {
        kind: "memo",
        commitment: log.topics[2]!,
        tag: log.topics[3]!,
        ephemeralX: word(log.data, 0),
        cekWrap: word(log.data, 1),
        words,
      });
    }
  }
  return out;
})();

const alice = fixture.wallets.find((w) => w.label === "alice")!;
const MEMBER = 7n;

/** Alice's keys as one member's self family and the group's incoming family. `reach` stops derivation past it. */
function aliceKeys(reach = Infinity): MultisigKeys<bigint, string> {
  const unused = (i: bigint) => 0xee00_0000_0000n + i; // matches no fixture row
  return {
    async selfTag(memberId, j) {
      expect(memberId).toBe(MEMBER);
      const k = alice.self_keys[Number(j)];
      if (Number(j) >= reach) return null;
      if (k === undefined) return { tag: unused(j), secret: "none" };
      return k.even_y ? { tag: big(k.x), secret: k.x } : null;
    },
    async incomingAt(from) {
      for (const k of alice.incoming_keys) {
        if (BigInt(k.index) >= from && k.even_y && k.index < reach) return { index: BigInt(k.index), tag: big(k.x), secret: k.x };
      }
      const past = BigInt(Math.max(Number(from), alice.incoming_keys.length));
      return { index: past, tag: unused(1000n + past), secret: "none" };
    },
    async open(record, source, secret) {
      const note = chainNotes.get(record.leafIndex);
      const kind = source.family === "self" ? "note" : "memo";
      // opens only under the key it was filed under; any other key gives noise
      if (note === undefined || note.kind !== kind || secret === "none" || big(note.tag) !== big(secret)) {
        return [{ words: Array(7).fill(1n), commitment: BigInt(record.leafIndex) * 31n + 5n }];
      }
      return [
        { words: Array(7).fill(2n), commitment: 9n }, // a wrong compliance key version
        { words: note.words.map(big), commitment: big(note.commitment) },
      ];
    },
  };
}

/** Howl's scanner stand-in: accepts every event and records the windows it was asked for. */
function sink(): MultisigEventScanner<MultisigChainEvent> & { events: MultisigChainEvent[]; grows: number[] } {
  const events: MultisigChainEvent[] = [];
  const grows: number[] = [];
  return {
    events,
    grows,
    readNote: async (e) => (events.push(e), e),
    ensureSelfLookahead: async (w) => (grows.push(w), false),
    ensureIncomingLookahead: async (w) => (grows.push(w), false),
  };
}

const ownedBy = (s: MultisigTagSource) => (s.family === "self" ? s.j : s.index);

describe.skipIf(!live)("multisig over a running node", () => {
  let chain: LocalChain;
  const roots = chainRoots();

  beforeAll(async () => {
    chain = await LocalChain.start();
    await chain.mineFixture(0, fixture.blocks.length);
    await chain.startNode(BIN);
    await chain.caughtUp();
  });

  afterAll(async () => {
    await chain?.stop();
  });

  const src = () => new RavenHowlSource({ transport: fetchTransport(chain.nodeUrl), wasm, field: bigintField });

  it("finds every note of both families, past the first window, as the chain's own events", async () => {
    const source = src();
    const scanner = sink();
    const scan = new MultisigRavenScan({
      source,
      field: bigintField,
      keys: aliceKeys(),
      scanner,
      memberIds: [MEMBER],
      selfWindow: WINDOW,
      incomingWindow: WINDOW,
    });
    const result = await scan.scan();
    expect(result.found.map((f) => f.leafIndex)).toEqual([...alice.owned_leaves].sort((a, b) => a - b));
    expect(result.unopened).toEqual([]);
    expect(result.refused).toEqual([]);
    // the far notes are reached only by growing the windows
    expect(result.rounds).toBeGreaterThan(1);
    expect(result.found.some((f) => f.source.family === "self" && ownedBy(f.source) >= BigInt(WINDOW))).toBe(true);
    expect(new Set(result.found.map((f) => f.source.family))).toEqual(new Set(["self", "incoming"]));
    expect(scanner.grows.every((w) => w === WINDOW)).toBe(true);
    for (const f of result.found) {
      const chainNote = chainNotes.get(f.leafIndex)!;
      const e = f.event;
      expect(e.args.leafIndex).toBe(BigInt(f.leafIndex));
      expect(e.args.commitment).toBe(chainNote.commitment);
      expect(e.args.packedCiphertext).toEqual(chainNote.words);
      expect(e.args.ephemeralX).toBe(big(chainNote.ephemeralX));
      if (chainNote.kind === "note") {
        expect(e.type).toBe("NEW_NOTE");
        expect(e.args.tag).toBeUndefined();
      } else {
        expect(e.type).toBe("NEW_MEMO");
        expect(e.args.tag).toBe(big(chainNote.tag));
        expect(e.args.cekWrap).toBe(big(chainNote.cekWrap!));
      }
      expect(f.check).toBe("confirmed"); // all 160 leaves sit in the newest block, which a sync holds
    }
    // a second scan finds the same notes in one round: the windows already cover them
    const again = await scan.scan();
    expect(again.found.map((f) => f.leafIndex)).toEqual(result.found.map((f) => f.leafIndex));
    expect(again.rounds).toBe(1);
    source.close();
  });

  it("planted: keys that stop at the first window miss exactly the far notes", async () => {
    const source = src();
    const full = await new MultisigRavenScan({
      source,
      field: bigintField,
      keys: aliceKeys(),
      scanner: sink(),
      memberIds: [MEMBER],
      selfWindow: WINDOW,
      incomingWindow: WINDOW,
    }).scan();
    const cut = await new MultisigRavenScan({
      source,
      field: bigintField,
      keys: aliceKeys(WINDOW),
      scanner: sink(),
      memberIds: [MEMBER],
      selfWindow: WINDOW,
      incomingWindow: WINDOW,
    }).scan();
    const far = full.found.filter((f) => ownedBy(f.source) >= BigInt(WINDOW)).map((f) => f.leafIndex);
    expect(far.length).toBeGreaterThan(0);
    expect(cut.found.map((f) => f.leafIndex)).toEqual(full.found.map((f) => f.leafIndex).filter((p) => !far.includes(p)));
    source.close();
  });

  it("planted: a cell that opens to another commitment, or that the scanner rejects, is not found", async () => {
    const source = src();
    const keys = aliceKeys();
    const target = alice.owned_leaves[0]!;
    const lying: MultisigKeys<bigint, string> = {
      ...keys,
      open: async (record, s, secret) =>
        record.leafIndex === target ? [{ words: Array(7).fill(3n), commitment: 4n }] : keys.open(record, s, secret),
    };
    const a = await new MultisigRavenScan({
      source,
      field: bigintField,
      keys: lying,
      scanner: sink(),
      memberIds: [MEMBER],
      selfWindow: WINDOW,
      incomingWindow: WINDOW,
    }).scan();
    expect(a.found.map((f) => f.leafIndex)).not.toContain(target);
    expect(a.unopened).toEqual([target]);

    const picky = sink();
    const choosy = { ...picky, readNote: async (e: MultisigChainEvent) => (e.args.leafIndex === BigInt(target) ? null : e) };
    const b = await new MultisigRavenScan({
      source,
      field: bigintField,
      keys,
      scanner: choosy,
      memberIds: [MEMBER],
      selfWindow: WINDOW,
      incomingWindow: WINDOW,
    }).scan();
    expect(b.refused).toEqual([target]);
    expect(b.found.map((f) => f.leafIndex)).not.toContain(target);
    source.close();
  });

  it("a row of the other record kind under a matching tag is not opened", async () => {
    const bob = fixture.wallets.find((w) => w.label === "bob")!;
    const bobSelf = bob.self_keys.find((k) => k.even_y && bob.owned_leaves.some((p) => chainNotes.get(p)?.tag === k.x))!;
    const bobLeaf = bob.owned_leaves.find((p) => chainNotes.get(p)?.tag === bobSelf.x)!;
    expect(chainNotes.get(bobLeaf)!.kind).toBe("note");
    const keys = aliceKeys();
    // one of the group's receiving addresses shares its tag with a self note of another wallet
    const colliding: MultisigKeys<bigint, string> = {
      ...keys,
      incomingAt: async (from) => (from === 0n ? { index: 0n, tag: big(bobSelf.x), secret: bobSelf.x } : keys.incomingAt(from)),
    };
    const source = src();
    const result = await new MultisigRavenScan({
      source,
      field: bigintField,
      keys: colliding,
      scanner: sink(),
      memberIds: [MEMBER],
      selfWindow: WINDOW,
      incomingWindow: WINDOW,
    }).scan();
    expect(result.unopened).toEqual([]);
    expect(result.found.map((f) => f.leafIndex)).not.toContain(bobLeaf);
    source.close();
  });

  it("refuses windows Howl's scanner would refuse", () => {
    const options = { source: src(), field: bigintField, keys: aliceKeys(), scanner: sink(), memberIds: [MEMBER] };
    expect(() => new MultisigRavenScan({ ...options, selfWindow: 15 })).toThrow(RangeError);
    expect(() => new MultisigRavenScan({ ...options, incomingWindow: 1.5 })).toThrow(RangeError);
    expect(() => new MultisigRavenScan({ ...options, memberIds: [] })).toThrow(RangeError);
  });

  describe("signing session", () => {
    const owned = (indices: number[]) =>
      new Map(indices.map((i) => [i, big(fixture.leaves[i]!.commitment)] as const));
    const spend = [alice.owned_leaves[1]!, alice.owned_leaves[4]!];
    const pinned = countAfter[Math.floor(fixture.blocks.length / 2) + 3]!;

    it("each signer re-folds its own path to the coordinator's root at the pinned count", async () => {
      const coordinator = src();
      const { session, witnesses } = await openSigningSession(coordinator, spend, pinned);
      expect(session.leafCount).toBe(pinned);
      expect(session.root.toString(16).padStart(64, "0")).toBe(roots.get(pinned));
      expect(witnesses.map((w) => w.root)).toEqual([session.root, session.root]);
      // two signers on their own clients, each holding a newer tree than the session's
      for (let s = 0; s < 2; s++) {
        const signer = src();
        await signer.sync();
        expect(signer.state.leafCount).toBeGreaterThan(pinned);
        const mine = await checkSigningSession(signer, bigintField, session, owned(spend));
        expect(mine.map((w) => [w.leafIndex, w.leafCount, w.root])).toEqual(spend.map((i) => [i, pinned, session.root]));
        signer.close();
      }
      // with no count the session is at the newest verified count, read once
      const newest = await openSigningSession(coordinator, spend);
      expect(newest.session.leafCount).toBe(coordinator.state.leafCount);
      coordinator.close();
    });

    it("planted: a mismatched root, a leaf the signer did not find, a substituted leaf and a count past the chain are refused", async () => {
      const coordinator = src();
      const { session } = await openSigningSession(coordinator, spend, pinned);
      const signer = src();
      const refusal = async (s: SigningSession<bigint>, own = owned(spend)) => {
        const e = await checkSigningSession(signer, bigintField, s, own).then(
          () => null,
          (x: unknown) => x,
        );
        expect(e).toBeInstanceOf(SigningSessionRefused);
        return (e as SigningSessionRefused).reason;
      };
      // the root at another count, as a coordinator replaying an older session would send
      expect(await refusal({ ...session, root: big("0x" + roots.get(pinned - 1)!) })).toBe("root");
      expect(await refusal({ ...session, root: session.root ^ 1n })).toBe("root");
      expect(await refusal({ ...session, leafCount: pinned + 1 })).toBe("root");
      expect(await refusal(session, owned([spend[0]!]))).toBe("unknown-note");
      const swapped = { ...session, notes: [{ leafIndex: spend[0]!, leaf: 12345n }, session.notes[1]!] };
      expect(await refusal(swapped)).toBe("unknown-note");
      expect(await refusal(swapped, new Map([[spend[0]!, 12345n], [spend[1]!, session.notes[1]!.leaf]]))).toBe("leaf");
      expect(await refusal({ ...session, leafCount: 1_000_000 })).toBe("count");
      // and the honest session still passes on the same client
      await expect(checkSigningSession(signer, bigintField, session, owned(spend))).resolves.toHaveLength(2);
      await expect(openSigningSession(coordinator, [])).rejects.toThrow(RangeError);
      await expect(openSigningSession(coordinator, [spend[0]!, spend[0]!])).rejects.toThrow(RangeError);
      signer.close();
      coordinator.close();
    });
  });
});
