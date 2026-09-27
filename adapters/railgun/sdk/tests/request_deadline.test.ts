// A node that accepts a request and never finishes answering would hold an SDK call open for as
// long as the socket lives; the stock wallet interface gives each POI node request 60 s. A refresh
// stuck on one such call never reaches the rest of its chain.

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { RavenError, RavenPOINodeInterface } from "../src/index";
import { fetchWithDeadline } from "../src/request-deadline";

const TOKEN = "test-token-padded-long-enough-1234";
const LIST_KEY_HEX = "ab".repeat(32);
const BC_HEX = "11".repeat(32);
const DEADLINE_MS = 150;
/** Long enough for any deadline under test, short enough to fail rather than hang. */
const GUARD_MS = 3_000;

async function settledWithin<T>(call: Promise<T>): Promise<{ value?: T; error?: unknown }> {
  const guard = new Promise<never>((_resolve, reject) =>
    setTimeout(() => reject(new Error(`still pending after ${GUARD_MS} ms`)), GUARD_MS),
  );
  try {
    return { value: await Promise.race([call, guard]) };
  } catch (error) {
    return { error };
  }
}

describe("request deadline", () => {
  let server: Server;
  let url: string;

  beforeAll(async () => {
    // Headers and half a body, then nothing: the stall a deadline on headers alone would miss.
    server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json", "content-length": "64" });
      res.write('{"stalled":');
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("fails a node that stalls mid-body as Network, within the deadline", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: url,
      bearerToken: TOKEN,
      useClientPir: false,
      requestTimeoutMs: DEADLINE_MS,
    });
    const started = Date.now();
    const { error } = await settledWithin(
      sdk.getPOIsPerList([LIST_KEY_HEX], [{ blindedCommitment: BC_HEX, type: "Shield" }]),
    );
    expect(RavenError.is(error, "Network"), String(error)).toBe(true);
    expect(Date.now() - started).toBeLessThan(GUARD_MS);
  });

  it("holds for a fetch that ignores its abort signal", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: "https://raven.invalid",
      bearerToken: TOKEN,
      useClientPir: false,
      requestTimeoutMs: DEADLINE_MS,
      fetchImpl: () => new Promise<Response>(() => undefined),
    });
    const { error } = await settledWithin(sdk.fetchStatusHeader(LIST_KEY_HEX));
    expect(RavenError.is(error, "Network"), String(error)).toBe(true);
  });

  it("lets the engine-shaped status call resolve past a stalled node", async () => {
    const sdk = new RavenPOINodeInterface({
      endpoint: url,
      bearerToken: TOKEN,
      useClientPir: false,
      requestTimeoutMs: DEADLINE_MS,
    });
    const { value, error } = await settledWithin(
      sdk.getPOIsPerList("V2_PoseidonMerkle", { type: 0, id: 1 }, [LIST_KEY_HEX], [
        { blindedCommitment: BC_HEX, type: "Shield" },
      ]),
    );
    expect(error).toBeUndefined();
    expect(value).toEqual({});
  });

  it("ends on the caller's own signal where AbortSignal.any is missing", async () => {
    const any = Object.getOwnPropertyDescriptor(AbortSignal, "any");
    Object.defineProperty(AbortSignal, "any", { value: undefined, configurable: true });
    try {
      const bounded = fetchWithDeadline(() => new Promise<Response>(() => undefined), 60_000);
      const { error } = await settledWithin(
        bounded("https://raven.invalid", { signal: AbortSignal.timeout(DEADLINE_MS) }),
      );
      expect((error as Error | undefined)?.name, String(error)).toBe("TimeoutError");
    } finally {
      if (any) Object.defineProperty(AbortSignal, "any", any);
    }
  });

  it("passes the caller's abort through to the fetch it wraps", async () => {
    let seen: AbortSignal | undefined;
    const bounded = fetchWithDeadline((_input, init) => {
      seen = init?.signal ?? undefined;
      return new Promise<Response>(() => undefined);
    }, 60_000);
    const caller = new AbortController();
    const call = settledWithin(bounded("https://raven.invalid", { signal: caller.signal }));
    caller.abort(new Error("caller gave up"));
    const { error } = await call;
    expect(String(error)).toMatch(/caller gave up/);
    expect(seen?.aborted).toBe(true);
  });

  it("refuses a deadline that is not a positive timer length", () => {
    for (const requestTimeoutMs of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 31]) {
      expect(
        () => new RavenPOINodeInterface({ endpoint: url, bearerToken: TOKEN, requestTimeoutMs }),
        String(requestTimeoutMs),
      ).toThrow(/requestTimeoutMs/);
    }
  });
});
