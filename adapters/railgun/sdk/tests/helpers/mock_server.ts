/**
 * Shared mock-server helpers for the SDK test harness.
 *
 * All SDK tests run against an in-process `node:http` server so we
 * exercise the SDK's outbound HTTP layer end-to-end without binding
 * to a real RPC, real PPOI service, or a browser. The mock records
 * every request body so tests can both inspect the SDK's
 * `lastWireRequests` capture AND cross-check the bytes the server
 * actually received.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

export interface RecordedRequest {
  url: string;
  method: string;
  body: Uint8Array;
  headers: Record<string, string | string[] | undefined>;
}

export interface RouteHandler {
  (req: IncomingMessage, body: Uint8Array, res: ServerResponse): boolean | Promise<boolean>;
}

export interface MockServer {
  url: string;
  port: number;
  requests: RecordedRequest[];
  /**
   * Add a new route handler; handlers are tried in registration
   * order and the first to return `true` claims the request. If no
   * handler claims, the server returns 404.
   */
  route(matcher: (req: IncomingMessage) => boolean, handler: RouteHandler): void;
  reset(): void;
  close(): Promise<void>;
}

export async function startMockServer(): Promise<MockServer> {
  const requests: RecordedRequest[] = [];
  const handlers: { match: (req: IncomingMessage) => boolean; handler: RouteHandler }[] = [];

  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", async () => {
      const body = new Uint8Array(Buffer.concat(chunks));
      requests.push({
        url: req.url ?? "",
        method: req.method ?? "GET",
        body,
        headers: { ...req.headers },
      });
      for (const { match, handler } of handlers) {
        if (!match(req)) continue;
        const claimed = await handler(req, body, res);
        if (claimed) return;
      }
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("not found");
    });
    req.on("error", () => {
      try {
        res.writeHead(400);
        res.end();
      } catch {
        // Connection may already be closed.
      }
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  if (typeof addr === "string" || addr === null) {
    throw new Error("mock server: unexpected address shape");
  }

  const port = addr.port;
  const url = `http://127.0.0.1:${port}`;

  return {
    url,
    port,
    requests,
    route(match, handler) {
      handlers.push({ match, handler });
    },
    reset() {
      requests.length = 0;
      handlers.length = 0;
    },
    async close() {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    },
  };
}

/**
 * Helper: write a JSON 200 response with optional freshness header.
 */
export function writeJson(
  res: ServerResponse,
  payload: unknown,
  extraHeaders: Record<string, string> = {},
): void {
  res.writeHead(200, {
    "content-type": "application/json",
    ...extraHeaders,
  });
  res.end(JSON.stringify(payload));
}

/**
 * Helper: write an octet-stream 200 response with optional freshness
 * header.
 */
export function writeBinary(
  res: ServerResponse,
  bytes: Uint8Array,
  extraHeaders: Record<string, string> = {},
): void {
  res.writeHead(200, {
    "content-type": "application/octet-stream",
    ...extraHeaders,
  });
  res.end(Buffer.from(bytes));
}

/**
 * Helper: write a typed error response with status + plain text body.
 */
export function writeError(
  res: ServerResponse,
  status: number,
  message: string,
): void {
  res.writeHead(status, { "content-type": "text/plain" });
  res.end(message);
}

/**
 * Builds a 32-byte commitment-shaped buffer for tests, deterministic
 * per `tag` byte.
 */
export function makeBc(tag: number): Uint8Array {
  const out = new Uint8Array(32);
  out[0] = 0xbc;
  out[31] = tag & 0xff;
  return out;
}

export function makeBcHex(tag: number): string {
  return Array.from(makeBc(tag))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function makeListKey(tag: number): Uint8Array {
  const out = new Uint8Array(32);
  out.fill(tag & 0xff);
  return out;
}

export function makeListKeyHex(tag: number): string {
  return Array.from(makeListKey(tag))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
