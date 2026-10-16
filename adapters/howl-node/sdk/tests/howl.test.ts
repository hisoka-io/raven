// Cross-checks against Howl's own wallet code, read from a built Howl checkout named by HOWL_REPO:
// its key derivation gives the tags the package scans for, its codec decodes the cells the
// package decodes, its field type rides through the package's discovery shape, and its self-mint
// preflight accepts the package's answers. These run where a Howl checkout is present (locally);
// CI runs the pinned vectors in kat.test.ts, which this suite regenerates and compares.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { decodeCell, fetchTransport, RavenHowlSource, type FieldCodec } from "../src/index.js";
import { LocalChain } from "./helpers/chain.js";
import { fixture, hex, unhex, wasm } from "./helpers/fixture.js";

const REPO = process.env.HOWL_REPO ?? "";
const WALLETS = join(REPO, "packages/wallets/dist/index.js");
const REFERENCE = join(REPO, "packages/wallets/dist/reference.js");
const available = REPO !== "" && existsSync(WALLETS) && existsSync(REFERENCE);
const BIN = process.env.HOWL_NODE_BIN ?? "";
const VECTORS = fileURLToPath(new URL("./fixtures/howl-vectors.json", import.meta.url));
const live = available && BIN !== "" && existsSync(BIN);

interface Fr {
  toBuffer(): Buffer;
  toBigInt(): bigint;
  equals(other: Fr): boolean;
}

describe.skipIf(!available)("with Howl's own wallet code", () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let howl: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let Fr: any;
  let field: FieldCodec<Fr>;

  beforeAll(async () => {
    howl = await import(pathToFileURL(WALLETS).href);
    // the preflight checks records with `instanceof` against the Fr its own build imports
    Fr = howl.Fr;
    field = {
      fromBytes: (bytes) => Fr.fromBuffer(Buffer.from(bytes)),
      toBytes: (value) => new Uint8Array(value.toBuffer()),
    };
  });

  it("derives every fixture wallet's tags", async () => {
    let tags = 0;
    for (const wallet of fixture.wallets) {
      const root = Fr.fromBuffer(Buffer.from(unhex(wallet.sk_root)));
      const view = await howl.deriveViewKey(root);
      expect(hex(view.toBuffer())).toBe(wallet.sk_view.slice(2));
      for (const key of wallet.self_keys) {
        const pub = howl.publicKey(await howl.deriveSelfEphemeral(view, BigInt(key.index)));
        expect(pub[0]).toBe(BigInt(key.x));
        expect(howl.isEvenY(pub)).toBe(key.even_y);
        tags += 1;
      }
      for (const key of wallet.incoming_keys) {
        const pub = howl.publicKey(await howl.deriveIncomingKey(view, BigInt(key.index)));
        expect(pub[0]).toBe(BigInt(key.x));
        expect(howl.isEvenY(pub)).toBe(key.even_y);
        tags += 1;
      }
    }
    expect(tags).toBeGreaterThan(40);
  });

  it("produces the pinned vectors the offline suite checks", async () => {
    const big = (f: Fr) => "0x" + hex(new Uint8Array(f.toBuffer()));
    const wallets = [];
    for (const wallet of fixture.wallets) {
      const view = await howl.deriveViewKey(Fr.fromBuffer(Buffer.from(unhex(wallet.sk_root))));
      const keys = async (list: { index: number }[], derive: (v: Fr, i: bigint) => Promise<Fr>) => {
        const out = [];
        for (const { index } of list) {
          const pub = howl.publicKey(await derive(view, BigInt(index)));
          out.push({ index, x: "0x" + pub[0].toString(16).padStart(64, "0"), even_y: howl.isEvenY(pub) });
        }
        return out;
      };
      wallets.push({
        label: wallet.label,
        sk_view: big(view),
        self_keys: await keys(wallet.self_keys, howl.deriveSelfEphemeral),
        incoming_keys: await keys(wallet.incoming_keys, howl.deriveIncomingKey),
      });
    }
    const cells = fixture.leaves
      .filter((leaf) => leaf.cell !== null)
      .map((leaf) => {
        const r = howl.decodeHowlNoteRecord(unhex(leaf.cell!));
        return {
          leaf_index: r.leafIndex,
          layout_version: r.layoutVersion,
          record_kind: r.recordKind,
          commitment_prefix: "0x" + hex(r.commitmentPrefix),
          ephemeral_pk_x: big(r.ephemeralPkX),
          cek_wrap: big(r.cekWrap),
          ciphertext_kept: r.ciphertextKept.map(big),
        };
      });
    const produced = JSON.stringify({ wallets, cells }) + "\n";
    if (process.env.HOWL_WRITE_VECTORS === "1") writeFileSync(VECTORS, produced);
    expect(produced).toBe(readFileSync(VECTORS, "utf8"));
  });

  it("decodes every fixture cell as Howl's codec does", () => {
    for (const leaf of fixture.leaves) {
      if (leaf.cell === null) continue;
      const cell = unhex(leaf.cell);
      const ours = decodeCell(cell, leaf.leaf_index, field);
      const theirs = howl.decodeHowlNoteRecord(cell);
      expect([ours.layoutVersion, ours.recordKind, ours.leafIndex]).toEqual([
        theirs.layoutVersion,
        theirs.recordKind,
        theirs.leafIndex,
      ]);
      expect(hex(ours.commitmentPrefix)).toBe(hex(theirs.commitmentPrefix));
      expect(ours.ephemeralPkX.equals(theirs.ephemeralPkX)).toBe(true);
      expect(ours.cekWrap.equals(theirs.cekWrap)).toBe(true);
      ours.ciphertextKept.forEach((w, i) => expect(w.equals(theirs.ciphertextKept[i])).toBe(true));
      // and Howl's encoder gives back the cell the node serves
      expect(hex(howl.encodeHowlNoteRecord(ours))).toBe(hex(cell));
    }
  });

  describe.skipIf(!live)("over a running node", () => {
    let chain: LocalChain;
    beforeAll(async () => {
      chain = await LocalChain.start();
      await chain.mineFixture(0, fixture.blocks.length);
      await chain.startNode(BIN);
      await chain.caughtUp();
    });
    afterAll(async () => {
      await chain?.stop();
    });

    it("answers Howl's two rounds with Howl's field type, for tags Howl derived", async () => {
      for (const wallet of fixture.wallets) {
        const view = await howl.deriveViewKey(Fr.fromBuffer(Buffer.from(unhex(wallet.sk_root))));
        const tags: Fr[] = [];
        for (const key of wallet.self_keys) {
          const pub = howl.publicKey(await howl.deriveSelfEphemeral(view, BigInt(key.index)));
          if (howl.isEvenY(pub)) tags.push(new Fr(pub[0]));
        }
        for (const key of wallet.incoming_keys) {
          const pub = howl.publicKey(await howl.deriveIncomingKey(view, BigInt(key.index)));
          if (howl.isEvenY(pub)) tags.push(new Fr(pub[0]));
        }
        const src = new RavenHowlSource({ transport: fetchTransport(chain.nodeUrl), wasm, field });
        const first = await src.probeFirst(tags);
        expect(first.map((f) => f.tag)).toEqual(tags);
        const rest = first.flatMap((f) =>
          Array.from({ length: Math.max(0, f.occurrenceCount - 1) }, (_, i) => ({ tag: f.tag, occurrence: i + 1 })),
        );
        const more = await src.fetchOccurrences(rest);
        const records = [
          ...first.filter((f) => f.occurrenceCount > 0).map((f) => f.record),
          ...more.filter((r) => r !== null),
        ];
        expect(records.map((r) => r.leafIndex).sort((a, b) => a - b)).toEqual(
          [...wallet.owned_leaves].sort((a, b) => a - b),
        );
        for (const record of records) {
          expect(hex(howl.encodeHowlNoteRecord(record))).toBe(fixture.leaves[record.leafIndex]!.cell!);
        }
        src.close();
      }
    });

    it("feeds Howl's self-mint preflight a record on every miss, so it issues a mint", async () => {
      const { KeyRepository } = await import(pathToFileURL(REFERENCE).href);
      const account = await howl.DarkAccount.fromMnemonic(
        "test test test test test test test test test test test junk",
      );
      const owner = await howl.pubkeyOwner(await account.getSelfSpendPub());
      const keys = new KeyRepository(account, new howl.InMemoryEphemeralCounterStore());
      const compliance = howl.publicKey(new Fr(0x3333n));
      const src = new RavenHowlSource({ transport: fetchTransport(chain.nodeUrl), wasm, field });
      const preflight = new howl.SelfMintPreflight({
        allocator: { next: () => keys.nextSelfEphemeral() },
        discovery: src,
        history: howl.completeComplianceHistory({
          genesisPk: compliance,
          rotations: [],
          currentPk: compliance,
          currentVersion: 1,
        }),
        ownerCommitment: owner,
        domain: {
          chainId: BigInt(fixture.chain_id),
          poolAddress: fixture.pool,
          deploymentAnchor: 1n,
        },
      });
      const issued = await preflight.take(2);
      expect(issued.length).toBe(2);
      src.close();
    });
  });
});
