// What the client does when a request gets no answer, or an answer that asks it to wait: a
// private read whose connection dies before any response is sent once more with the same bytes,
// a read that got a status is not, and a busy node's Retry-After reaches the caller.
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bigintField, fetchTransport, HowlError, MAX_RETRY_AFTER_SECONDS, RavenHowlSource, type KeyMode } from "../src/index.js";
import { neverAnswered } from "../src/http.js";
import { LocalChain } from "./helpers/chain.js";
import { fixture, hex, unhex, wasm } from "./helpers/fixture.js";

const BIN = process.env.HOWL_NODE_BIN ?? "";
const live = BIN !== "" && existsSync(BIN);

type Handler = (req: IncomingMessage, body: Buffer, res: ServerResponse) => void | Promise<void>;

async function serve(handler: Handler): Promise<{ url: string; close: () => Promise<void> }> {
  const server: Server = createServer((req, res) => {
    const parts: Buffer[] = [];
    req.on("data", (c: Buffer) => parts.push(c));
    req.on("end", () => void handler(req, Buffer.concat(parts), res));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

async function failure(call: Promise<unknown>): Promise<HowlError> {
  const e = await call.then(
    () => null,
    (e: unknown) => e,
  );
  expect(e).toBeInstanceOf(HowlError);
  return e as HowlError;
}

describe("a transport failure before any answer", () => {
  it("is marked as unanswered only when no status arrived and the time was not spent", async () => {
    const node = await serve((req, _body, res) => {
      if (req.url === "/reset") req.socket.destroy();
      else if (req.url === "/refused") res.writeHead(500).end("no");
      else if (req.url === "/cut") {
        res.writeHead(200, { "content-length": "100" });
        res.write("partial", () => req.socket.destroy());
      }
      // "/slow" never answers
    });
    try {
      const t = fetchTransport(node.url, { timeoutMs: 300 });
      const reset = await failure(t.post("/reset", new Uint8Array([1])));
      expect([reset.kind, neverAnswered(reset)]).toEqual(["Network", true]);
      expect((await t.post("/refused", new Uint8Array([1]))).status).toBe(500);
      const cut = await failure(t.get("/cut"));
      expect([cut.kind, neverAnswered(cut)]).toEqual(["Network", false]);
      const slow = await failure(t.get("/slow"));
      expect([slow.kind, neverAnswered(slow)]).toEqual(["Network", false]);
      // an error the transport did not raise is never taken for one
      expect(neverAnswered(new HowlError("Network", "elsewhere"))).toBe(false);
    } finally {
      await node.close();
    }
  });
});

describe("a busy node's Retry-After", () => {
  it("reaches the caller on 429 and 503, in seconds within the bound", async () => {
    let status = 429;
    let header: string | null = null;
    const node = await serve((_req, _body, res) => {
      res.writeHead(status, header === null ? {} : { "retry-after": header }).end("busy");
    });
    try {
      const busy = async (s: number, h: string | null): Promise<HowlError> => {
        [status, header] = [s, h];
        const src = new RavenHowlSource({ transport: fetchTransport(node.url), wasm, field: bigintField });
        return failure(src.fetchTagPrefixes(0));
      };
      const e429 = await busy(429, "2");
      expect([e429.kind, e429.status, e429.retryAfter, e429.retryable]).toEqual(["Busy", 429, 2, true]);
      const e503 = await busy(503, "1");
      expect([e503.kind, e503.status, e503.retryAfter]).toEqual(["Busy", 503, 1]);
      expect((await busy(429, "86400")).retryAfter).toBe(MAX_RETRY_AFTER_SECONDS);
      const dated = (await busy(503, new Date(Date.now() + 30_000).toUTCString())).retryAfter;
      expect(dated).toBeGreaterThanOrEqual(28);
      expect(dated).toBeLessThanOrEqual(31);
      expect((await busy(503, new Date(Date.now() - 30_000).toUTCString())).retryAfter).toBe(0);
      expect((await busy(429, null)).retryAfter).toBeUndefined();
      expect((await busy(429, "soon")).retryAfter).toBeUndefined();
      const refused = await busy(400, "5");
      expect([refused.kind, refused.retryAfter]).toEqual(["Refused", undefined]);
    } finally {
      await node.close();
    }
  });

  it("is carried by a transport of the caller's own that passes headers", async () => {
    const own = async () => ({ status: 503, body: new Uint8Array(), headers: new Headers({ "Retry-After": "3" }) });
    const src = new RavenHowlSource({ transport: { get: own, post: own }, wasm, field: bigintField });
    expect((await failure(src.fetchTagPrefixes(0))).retryAfter).toBe(3);
    // a transport that passes no headers still raises Busy, with no wait named
    const bare = async () => ({ status: 503, body: new Uint8Array() });
    const plain = new RavenHowlSource({ transport: { get: bare, post: bare }, wasm, field: bigintField });
    const e = await failure(plain.fetchTagPrefixes(0));
    expect([e.kind, e.retryAfter]).toEqual(["Busy", undefined]);
  });
});

describe.skipIf(!live)("a private read through a connection that dies", () => {
  let chain: LocalChain;
  let upstream = "";
  // how the proxy treats the next /notes requests, in order; then it forwards
  let plan: ("reset" | "refuse" | "cut")[] = [];
  const reads: string[] = [];
  // the client port of the connection each /notes request came on
  const ports: number[] = [];
  let proxy: { url: string; close: () => Promise<void> };

  beforeAll(async () => {
    chain = await LocalChain.start();
    await chain.mineFixture(0, fixture.blocks.length);
    upstream = await chain.startNode(BIN);
    await chain.caughtUp();
    proxy = await serve(async (req, body, res) => {
      if (req.url === "/howl/v1/notes") {
        reads.push(createHash("sha256").update(body).digest("hex"));
        ports.push(req.socket.remotePort ?? -1);
        const step = plan.shift();
        if (step === "reset") return void req.socket.destroy();
        if (step === "refuse") return void res.writeHead(500).end("refused");
        if (step === "cut") {
          res.writeHead(200, { "content-length": "4096" });
          return void res.write("partial", () => req.socket.destroy());
        }
      }
      const answer = await fetch(`${upstream}${req.url ?? ""}`, {
        method: req.method ?? "GET",
        ...(req.method === "POST" ? { body: new Uint8Array(body) } : {}),
        headers: { "content-type": "application/octet-stream" },
      });
      res.writeHead(answer.status).end(Buffer.from(await answer.arrayBuffer()));
    });
  });

  afterAll(async () => {
    await proxy?.close();
    await chain?.stop();
  });

  const cellOf = (p: number): string => hex(unhex(fixture.leaves[p]!.cell!).subarray(6, 22));

  for (const keyMode of ["session", "inline"] satisfies KeyMode[]) {
    it(`is sent once more, byte for byte, when no response arrived (${keyMode})`, async () => {
      const src = new RavenHowlSource({ transport: fetchTransport(proxy.url), wasm, field: bigintField, keyMode });
      await src.sync();
      reads.length = 0;
      ports.length = 0;
      plan = ["reset"];
      const [record] = await src.fetchNotes([41]);
      expect(hex(record!.commitmentPrefix)).toBe(cellOf(41));
      expect(reads).toHaveLength(2);
      expect(reads[1]).toBe(reads[0]);
      expect(ports[1]).not.toBe(ports[0]);
      // a connection that dies again is not tried a third time
      reads.length = 0;
      plan = ["reset", "reset"];
      expect((await failure(src.fetchNotes([42]))).kind).toBe("Network");
      expect(reads).toHaveLength(2);
      src.close();
    });
  }

  it("is not sent again once the node answered a status, or the answer was cut after it", async () => {
    const src = new RavenHowlSource({ transport: fetchTransport(proxy.url), wasm, field: bigintField, keyMode: "inline" });
    await src.sync();
    reads.length = 0;
    plan = ["refuse"];
    const refused = await failure(src.fetchNotes([43]));
    expect([refused.kind, refused.status]).toEqual(["Refused", 500]);
    expect(reads).toHaveLength(1);
    reads.length = 0;
    plan = ["cut"];
    expect((await failure(src.fetchNotes([43]))).kind).toBe("Network");
    expect(reads).toHaveLength(1);
    // control: the same read through a healthy connection opens
    reads.length = 0;
    expect(hex((await src.fetchNotes([43]))[0]!.commitmentPrefix)).toBe(cellOf(43));
    expect(reads).toHaveLength(1);
  });
});
