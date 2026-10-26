// One source kept across a restart of its node: under the other parameter set, or re-seeded from
// the chain on a new data directory under the same set. Runs where live.test.ts does.
import { existsSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  bigintField,
  fetchTransport,
  HowlError,
  RavenHowlSource,
  type HowlTransport,
  type KeyMode,
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
    get: async (path) => {
      paths.push(`GET ${path}`);
      return inner.get(path);
    },
    post: async (path, body) => {
      paths.push(`POST ${path}`);
      return inner.post(path, body);
    },
  };
}

function expectCell(src: RavenHowlSource<bigint>, records: Awaited<ReturnType<RavenHowlSource<bigint>["fetchNotes"]>>): void {
  for (const r of records) {
    const want = unhex(fixture.leaves[r.leafIndex]!.cell!);
    expect(hex(r.commitmentPrefix), `leaf ${r.leafIndex}`).toBe(hex(want.subarray(6, 22)));
  }
  expect(src.lastRead?.leafCount).toBe(fixture.leaves.length);
}

describe.skipIf(!live)("a source across a restart of its node", () => {
  let chain: LocalChain;

  beforeAll(async () => {
    chain = await LocalChain.start();
    await chain.mineFixture(0, fixture.blocks.length);
  });

  afterAll(async () => {
    await chain?.stop();
  });

  // [from set, to set, data after the restart, whether the node then serves other material]
  const cases = [
    [1, 2, "same", true],
    [2, 1, "same", true],
    [1, 1, "new", true],
    [2, 2, "new", false],
    [1, 1, "same", false],
    [2, 2, "same", false],
  ] as const;
  for (const [from, to, data, changed] of cases) {
    for (const keyMode of ["session", "inline"] as KeyMode[]) {
      it(`set ${from} -> ${to} on the ${data} data dir, ${keyMode}`, async () => {
        const url = await chain.startNode(BIN, { paramSet: from });
        await chain.caughtUp(chain.leafCount, url);
        const transport = recorded(url);
        const src = new RavenHowlSource({ transport, wasm, field: bigintField, keyMode });
        expectCell(src, await src.fetchNotes([1, 2]));
        const before = src.snapshot();

        await chain.restartNode(url, BIN, { paramSet: to, ...(data === "new" ? { data: "-reseeded" } : {}) });
        await chain.caughtUp(chain.leafCount, url);
        const mark = transport.paths.length;
        expectCell(src, await src.fetchNotes([3, 77]));
        const asked = transport.paths.slice(mark);
        // one params read when the node serves other material; none when it does not
        expect(asked.filter((p) => p === "GET /howl/v1/params").length, asked.join("\n")).toBe(changed ? 1 : 0);
        expect(asked.length, asked.join("\n")).toBeLessThanOrEqual(6);
        // later reads go straight through
        const next = transport.paths.length;
        expectCell(src, await src.fetchNotes([120, 159]));
        expect(transport.paths.slice(next).every((p) => p.startsWith("POST"))).toBe(true);

        // the feed, the tree and the cells are chain data: they carry over unchanged
        const synced = await src.sync();
        expect(synced.rewoundTo).toBeUndefined();
        expect(synced.rowsAdded).toBe(0);
        expect(hex(synced.root)).toBe(hex(before.root));
        expect(hex(src.feed.bytes())).toBe(hex(before.rows));
        const resumed = new RavenHowlSource({ transport: fetchTransport(url), wasm, field: bigintField, keyMode, snapshot: before });
        const again = await resumed.sync();
        expect([again.rowsAdded, again.rewoundTo]).toEqual([0, undefined]);
        expectCell(resumed, await resumed.fetchNotes([5]));
        resumed.close();
        src.close();
      });
    }
  }

  it("reads the params again once, never in a loop, and says so when that did not help", async () => {
    const url = await chain.startNode(BIN);
    await chain.caughtUp(chain.leafCount, url);
    for (const changes of [true, false]) {
      const inner = recorded(url);
      let paramsRead = 0;
      const transport: HowlTransport = {
        get: async (path) => {
          const ex = await inner.get(path);
          if (path !== "/howl/v1/params" || !changes || paramsRead++ === 0) return ex;
          // every later params answer names other serving material: here another session lifetime
          const body = ex.body.slice();
          body[69]! ^= 0x01;
          return { status: ex.status, body };
        },
        post: async (path, body) =>
          path === "/howl/v1/notes"
            ? (inner.paths.push(`POST ${path}`), { status: 400, body: new TextEncoder().encode("refused") })
            : inner.post(path, body),
      };
      for (const keyMode of ["session", "inline"] as KeyMode[]) {
        paramsRead = 0;
        inner.paths.length = 0;
        const src = new RavenHowlSource({ transport, wasm, field: bigintField, keyMode });
        const error = await src.fetchNotes([1]).then(
          () => null,
          (e: unknown) => e,
        );
        expect(error).toBeInstanceOf(HowlError);
        expect((error as HowlError).kind).toBe("Refused");
        const gets = inner.paths.filter((p) => p === "GET /howl/v1/params").length;
        const notes = inner.paths.filter((p) => p === "POST /howl/v1/notes").length;
        // the first read, one read again; the batch is sent again only under other material
        expect([gets, notes], `${keyMode} changes=${changes}`).toEqual(changes ? [2, 2] : [2, 1]);
        expect((error as HowlError).message.includes("after reading the node's params again")).toBe(changes);
        src.close();
      }
    }
  });

  it("keeps the refusal when the params cannot be read again", async () => {
    const url = await chain.startNode(BIN);
    await chain.caughtUp(chain.leafCount, url);
    const inner = recorded(url);
    let paramsRead = 0;
    const transport: HowlTransport = {
      get: async (path) => {
        if (path === "/howl/v1/params" && paramsRead++ > 0) throw new TypeError("fetch failed");
        return inner.get(path);
      },
      post: async (path, body) =>
        path === "/howl/v1/notes"
          ? (inner.paths.push(`POST ${path}`), { status: 400, body: new TextEncoder().encode("refused") })
          : inner.post(path, body),
    };
    for (const keyMode of ["session", "inline"] as KeyMode[]) {
      paramsRead = 0;
      inner.paths.length = 0;
      const src = new RavenHowlSource({ transport, wasm, field: bigintField, keyMode });
      const error = await src.fetchNotes([1]).then(
        () => null,
        (e: unknown) => e,
      );
      expect(error, keyMode).toBeInstanceOf(HowlError);
      expect((error as HowlError).kind).toBe("Refused");
      expect(paramsRead, keyMode).toBe(2);
      expect(inner.paths.filter((p) => p === "POST /howl/v1/notes").length).toBe(1);
      src.close();
    }
  });
});
