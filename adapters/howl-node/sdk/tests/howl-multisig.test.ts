// Multisig on Howl's own code, read from a built Howl checkout named by HOWL_REPO: a 2-of-3 FROST
// group from Howl's simulated ceremony (a test-only entry point), multisig notes of both families
// built and encrypted by Howl's functions and logged on a local chain the node follows, found by
// every member through the adaptor into Howl's own MultisigScanner, then a signing session that
// each signer checks against its own path before the group signs. Runs where a Howl checkout and
// the node binary are present; tests/multisig.test.ts covers the adaptor in CI.
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  checkSigningSession,
  fetchTransport,
  MultisigRavenScan,
  openSigningSession,
  RavenHowlSource,
  SigningSessionRefused,
  type FieldCodec,
  type HowlNoteRecord,
  type MultisigKeys,
  type MultisigTagSource,
} from "../src/index.js";
import { LocalChain } from "./helpers/chain.js";
import { fixture, wasm, type FixtureLog } from "./helpers/fixture.js";

const REPO = process.env.HOWL_REPO ?? "";
const DIST = join(REPO, "packages/wallets/dist");
const BIN = process.env.HOWL_NODE_BIN ?? "";
const live =
  REPO !== "" &&
  ["index.js", "frost/index.js", "unsafe-sim/index.js"].every((f) => existsSync(join(DIST, f))) &&
  BIN !== "" &&
  existsSync(BIN);

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Any = any;
const WINDOW = 16;
const word = (v: bigint) => v.toString(16).padStart(64, "0");
const topic = (v: bigint) => "0x" + word(v);

interface Planted {
  leafIndex: number;
  family: "self" | "incoming";
  index: bigint;
  memberId?: bigint;
  commitment: Any;
  value: bigint;
  multisig: boolean;
}

describe.skipIf(!live)("multisig with a FROST group on Howl's code", () => {
  for (const paramSet of [2, 1]) describe(`parameter set ${paramSet}`, () => {
    let howl: Any;
    let frost: Any;
    let sim: Any;
    let Fr: Any;
    let field: FieldCodec<Any>;
    let chain: LocalChain;
    let account: Any;
    let v: Any;
    let compliancePk: Any;
    let owner: Any;
    let members: bigint[];
    const planted: Planted[] = [];
    let tree: Any;
    let logIndex = 0;

    /** Howl's own key functions as the adaptor's hooks; `reach` stops derivation past it (planted control). */
    const keysFor = (reach = Infinity): MultisigKeys<Any, Any> => ({
      async selfTag(memberId, j) {
        if (Number(j) >= reach) return null;
        const { eph, ephPub } = await frost.deriveSelfEph(v, memberId, j);
        return howl.isEvenY(ephPub) ? { tag: new Fr(ephPub[0]), secret: eph } : null;
      },
      async incomingAt(from) {
        const k = await frost.multisigIncomingKeyAt(v, from);
        if (Number(k.index) >= reach) return { index: k.index, tag: new Fr(0n), secret: null };
        return { index: k.index, tag: new Fr(k.viewPub[0]), secret: k.viewKey };
      },
      async open(record: HowlNoteRecord<Any>, source: MultisigTagSource, secret: Any) {
        if (secret === null) return [];
        try {
          const cek =
            source.family === "self"
              ? howl.deriveCek(secret, compliancePk)
              : await frost.memberReadIncoming(record.cekWrap, secret, howl.recoverEvenY(record.ephemeralPkX.toBigInt()));
          const words = await howl.reconstructCiphertext(record, cek, owner);
          const pt = await howl.demDecrypt(cek, words);
          const commitment = await howl.leaf({
            noteVersion: pt[0],
            assetId: pt[1],
            noteType: pt[2],
            conditionsHash: pt[3],
            value: pt[4].toBigInt(),
            owner: pt[5],
            psi: await howl.computePsi(cek),
            parents: pt[6],
          });
          return [{ words, commitment }];
        } catch {
          // a wrong key decrypts to noise, whose value fails the u128 range check
          return [];
        }
      },
    });

    const scannerFor = () =>
      frost.MultisigScanner.create({
        v,
        gpk: account.gpk,
        compliancePk,
        memberIds: members,
        selfWindow: WINDOW,
        incomingWindow: WINDOW,
      });

    const source = () => new RavenHowlSource({ transport: fetchTransport(chain.nodeUrl), wasm, field });

    /** A note's leaf, tree insert and logs, built and encrypted by Howl's functions. */
    async function note(
      cek: Any,
      value: bigint,
      noteType: bigint,
      describing: (leafIndex: number, commitment: Any, words: Any[]) => FixtureLog,
    ): Promise<{ logs: FixtureLog[]; commitment: Any; leafIndex: number }> {
      const plaintext = [howl.NOTE_VERSION, new Fr(0xa11ce5n), new Fr(noteType), new Fr(0n), new Fr(value), owner, new Fr(0n)];
      const words = await howl.demEncrypt(cek, plaintext);
      const commitment = await howl.leaf({
        noteVersion: plaintext[0],
        assetId: plaintext[1],
        noteType: plaintext[2],
        conditionsHash: plaintext[3],
        value,
        owner,
        psi: await howl.computePsi(cek),
        parents: plaintext[6],
      });
      const leafIndex = tree.nextLeafIndex;
      const root = await tree.insert(commitment);
      const inserted: FixtureLog = {
        log_index: logIndex++,
        address: fixture.pool,
        topics: [fixture.topics.LeafInserted!, topic(BigInt(leafIndex))],
        data: "0x" + word(commitment.toBigInt()) + word(root.toBigInt()),
      };
      return { logs: [inserted, describing(leafIndex, commitment, words)], commitment, leafIndex };
    }

    async function selfNote(memberId: bigint, j: bigint, value: bigint, noteType = 1n) {
      const { eph, ephPub } = await frost.deriveSelfEph(v, memberId, j);
      expect(howl.isEvenY(ephPub)).toBe(true);
      const out = await note(howl.deriveCek(eph, compliancePk), value, noteType, (leafIndex, commitment, words) => ({
        log_index: logIndex++,
        address: fixture.pool,
        topics: [fixture.topics.NewNote!, topic(BigInt(leafIndex)), topic(commitment.toBigInt())],
        data: "0x" + word(ephPub[0]) + words.map((w: Any) => word(w.toBigInt())).join(""),
      }));
      planted.push({ leafIndex: out.leafIndex, family: "self", index: j, memberId, commitment: out.commitment, value, multisig: noteType === 1n });
      return out.logs;
    }

    async function incomingNote(index: bigint, value: bigint) {
      const k = await frost.multisigIncomingKeyAt(v, index);
      expect(k.index).toBe(index);
      let eph: Any;
      do eph = howl.toBjjScalar(new Fr(BigInt("0x" + randomBytes(31).toString("hex")) + 1n));
      while (!howl.isEvenY(howl.publicKey(eph)));
      const memo = await frost.buildIncomingMultisigNote(eph, compliancePk, account.gpk, k.viewPub);
      const out = await note(memo.cek, value, 1n, (leafIndex, commitment, words) => ({
        log_index: logIndex++,
        address: fixture.pool,
        topics: [fixture.topics.NewPrivateMemo!, topic(BigInt(leafIndex)), topic(commitment.toBigInt()), topic(memo.tag.toBigInt())],
        data: "0x" + word(memo.ephPub[0]) + word(memo.cekWrap.toBigInt()) + words.map((w: Any) => word(w.toBigInt())).join(""),
      }));
      planted.push({ leafIndex: out.leafIndex, family: "incoming", index, commitment: out.commitment, value, multisig: true });
      return out.logs;
    }

    /** Even-y self indices of `memberId` below `limit`, and the first at or past it. */
    async function selfIndices(memberId: bigint, limit: number) {
      const near: bigint[] = [];
      let j = 0n;
      for (; ; j++) {
        const { ephPub } = await frost.deriveSelfEph(v, memberId, j);
        if (!howl.isEvenY(ephPub)) continue;
        if (j < BigInt(limit)) near.push(j);
        else return { near, far: j };
      }
    }

    beforeAll(async () => {
      howl = await import(pathToFileURL(join(DIST, "index.js")).href);
      frost = await import(pathToFileURL(join(DIST, "frost/index.js")).href);
      sim = await import(pathToFileURL(join(DIST, "unsafe-sim/index.js")).href);
      Fr = howl.Fr;
      field = { fromBytes: (b) => Fr.fromBuffer(Buffer.from(b)), toBytes: (f) => new Uint8Array(f.toBuffer()) };
      account = await sim.frostAccountDkg(3, 2, 0xd06n);
      members = [...account.shares.keys()].sort((a: bigint, b: bigint) => (a < b ? -1 : 1));
      v = new Fr(account.viewKey);
      owner = new Fr(await frost.multisigOwner(account.gpk));
      expect(owner.equals(account.owner)).toBe(true);
      compliancePk = howl.publicKey(new Fr(0x3333n));

      tree = new howl.LeanIMT(32);
      for (const leaf of fixture.leaves) await tree.insert(Fr.fromBuffer(Buffer.from(leaf.commitment.slice(2), "hex")));
      expect(word(tree.getRoot().toBigInt())).toBe(fixture.root.slice(2));

      chain = await LocalChain.start();
      await chain.mineFixture(0, fixture.blocks.length);

      // member A: every even-y self index of the first window but the last, then the last one, so the
      // window grows to reach member B's note past it; the group's incoming addresses the same way
      const [a, b] = members as [bigint, bigint];
      const selfA = await selfIndices(a, WINDOW);
      const selfB = await selfIndices(b, WINDOW);
      const nearA = selfA.near[selfA.near.length - 1]!;
      let incomingNear = 0n;
      for (let i = 0n; ; ) {
        const k = await frost.multisigIncomingKeyAt(v, i);
        if (k.index >= BigInt(WINDOW)) break;
        incomingNear = k.index;
        i = k.index + 1n;
      }
      const incomingFar = (await frost.multisigIncomingKeyAt(v, BigInt(WINDOW))).index;
      expect(selfA.far - nearA).toBeLessThanOrEqual(BigInt(WINDOW));
      // within reach of the grown window: a long odd-y run would make the plants unreachable
      expect(incomingFar - incomingNear).toBeLessThanOrEqual(BigInt(WINDOW));

      let leaves = fixture.leaf_count;
      const block1 = [
        ...(await selfNote(a, nearA, 40n)),
        ...(await incomingNote(incomingNear, 25n)),
        ...(await selfNote(a, selfA.near[0]!, 7n, 0n)), // the group's tag, not a multisig note
      ];
      leaves += 3;
      await chain.mine(block1, leaves);
      const block2 = [
        ...(await selfNote(b, selfB.near[0]!, 11n)),
        ...(await selfNote(a, selfA.far, 12n)),
        ...(await incomingNote(incomingFar, 13n)),
      ];
      leaves += 3;
      await chain.mine(block2, leaves);
      await chain.startNode(BIN, { paramSet });
      await chain.caughtUp();
    });

    afterAll(async () => {
      await chain?.stop();
    });

    it("every member finds every group note of both families, past the first window, through Howl's scanner", async () => {
      const want = planted.filter((p) => p.multisig).map((p) => p.leafIndex).sort((x, y) => x - y);
      const refusedByHowl = planted.filter((p) => !p.multisig).map((p) => p.leafIndex);
      for (const memberId of members) {
        const src = source();
        const scanner = await scannerFor();
        const result = await new MultisigRavenScan({
          source: src,
          field,
          keys: keysFor(),
          scanner,
          memberIds: members,
          selfWindow: WINDOW,
          incomingWindow: WINDOW,
        }).scan();
        expect(result.found.map((f) => f.leafIndex), `member ${memberId}`).toEqual(want);
        expect(result.refused).toEqual(refusedByHowl);
        expect(result.unopened).toEqual([]);
        expect(result.rounds).toBeGreaterThan(1);
        for (const f of result.found) {
          const p = planted.find((x) => x.leafIndex === f.leafIndex)!;
          expect((f.view as Any).leafIndex).toBe(p.leafIndex);
          expect((f.view as Any).commitment.equals(p.commitment)).toBe(true);
          expect((f.view as Any).note.value).toBe(p.value);
          expect((f.view as Any).isIncoming).toBe(p.family === "incoming");
          expect(f.source.family).toBe(p.family);
          expect(f.check).toBe("confirmed");
        }
        // Howl counts its own refusal of a self-tagged note as unopenable; nothing else is
        expect(scanner.unopenableNoteCount).toBe(refusedByHowl.length);
        src.close();
      }
    });

    it("planted: with derivation stopped at the first window the far notes of both families are missed", async () => {
      const src = source();
      const result = await new MultisigRavenScan({
        source: src,
        field,
        keys: keysFor(WINDOW),
        scanner: await scannerFor(),
        memberIds: members,
        selfWindow: WINDOW,
        incomingWindow: WINDOW,
      }).scan();
      const far = planted.filter((p) => p.multisig && p.index >= BigInt(WINDOW));
      expect(new Set(far.map((p) => p.family))).toEqual(new Set(["self", "incoming"]));
      const found = result.found.map((f) => f.leafIndex);
      for (const p of far) expect(found).not.toContain(p.leafIndex);
      expect(found.length).toBe(planted.filter((p) => p.multisig).length - far.length);
      src.close();
    });

    it("a 2-of-3 session: each signer re-folds its own path to the session root, and the group signature binds that root", async () => {
      const cs = frost.bjjCiphersuite;
      const owned = new Map<bigint, { notes: Map<number, Any>; views: Map<number, Any>; src: RavenHowlSource<Any> }>();
      for (const memberId of members) {
        const src = source();
        const result = await new MultisigRavenScan({
          source: src,
          field,
          keys: keysFor(),
          scanner: await scannerFor(),
          memberIds: members,
          selfWindow: WINDOW,
          incomingWindow: WINDOW,
        }).scan();
        owned.set(memberId, {
          notes: new Map(result.found.map((f) => [f.leafIndex, f.commitment])),
          views: new Map(result.found.map((f) => [f.leafIndex, f.view])),
          src,
        });
      }
      const [coordinatorId, ...rest] = members as [bigint, ...bigint[]];
      const signers = rest.slice(0, 1).concat(coordinatorId); // t = 2
      const coordinator = owned.get(coordinatorId)!;
      // a join of the incoming note and a self note: two nullifiers under one root
      const spend = [planted.find((p) => p.family === "incoming")!.leafIndex, planted.find((p) => p.family === "self" && p.multisig)!.leafIndex];
      const pinned = coordinator.src.state.leafCount - 1;
      const { session } = await openSigningSession(coordinator.src, spend, pinned);
      const nullifiers = spend.map((i) => coordinator.views.get(i)!.nullifier.toBigInt());
      const message = (root: Any) =>
        frost.msgJoin({ root: root.toBigInt(), nullifierA: nullifiers[0], nullifierB: nullifiers[1], outLeaf: 0x5eedn, asset: 0xa11ce5n });

      const sign = async (s: typeof session) => {
        const commitments: Any[] = [];
        const nonces = new Map<bigint, Any>();
        for (const id of signers) {
          await checkSigningSession(owned.get(id)!.src, field, s, owned.get(id)!.notes);
          const r = await frost.commit(cs, id, account.shares.get(id), randomBytes(32), randomBytes(32));
          nonces.set(id, r.nonces);
          commitments.push(r.commitment);
        }
        const msg = frost.encodeMessage(await message(s.root));
        const R = frost.groupCommitment(cs, commitments, await frost.bindingFactors(cs, account.gpk, msg, commitments));
        const z: bigint[] = [];
        for (const id of signers) z.push(await frost.signShare(cs, id, nonces.get(id), account.shares.get(id), account.gpk, msg, commitments));
        return frost.aggregate(cs, R, z);
      };

      const sig = await sign(session);
      expect(await frost.verify(cs, account.gpk, frost.encodeMessage(await message(session.root)), sig)).toBe(true);
      // the same signature does not cover the newest root: the root is in the message
      const newest = await openSigningSession(coordinator.src, spend);
      expect(newest.session.root.equals(session.root)).toBe(false);
      expect(await frost.verify(cs, account.gpk, frost.encodeMessage(await message(newest.session.root)), sig)).toBe(false);

      // planted: a coordinator naming the newest root at the pinned count is refused by the first signer, before any commit
      const forged = { ...session, root: newest.session.root };
      const refused = await sign(forged).then(
        () => null,
        (e: unknown) => e,
      );
      expect(refused).toBeInstanceOf(SigningSessionRefused);
      expect((refused as SigningSessionRefused).reason).toBe("root");
      for (const { src } of owned.values()) src.close();
    });
  });
});
