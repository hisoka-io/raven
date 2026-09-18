/** In-process `node:http` mock that records every request body for the SDK test harness. */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

export interface RecordedRequest {
  url: string;
  method: string;
  body: Uint8Array;
  headers: Record<string, string | string[] | undefined>;
}

export interface JsonRpcRequest {
  jsonrpc: string;
  method: string;
  params: Record<string, unknown>;
  id: number;
}

export interface RouteHandler {
  (req: IncomingMessage, body: Uint8Array, res: ServerResponse): boolean | Promise<boolean>;
}

export interface MockServer {
  url: string;
  port: number;
  requests: RecordedRequest[];
  /** Register a handler; tried in order, first to return `true` claims the request, else 404. */
  route(matcher: (req: IncomingMessage) => boolean, handler: RouteHandler): void;
  /** Override the otherwise automatic successful session-handshake response. */
  routeSession(handler: RouteHandler): void;
  reset(): void;
  close(): Promise<void>;
}

export async function startMockServer(): Promise<MockServer> {
  const requests: RecordedRequest[] = [];
  const handlers: { match: (req: IncomingMessage) => boolean; handler: RouteHandler }[] = [];
  let sessionHandler: RouteHandler | undefined;

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
      if ((req.url ?? "").endsWith("/session")) {
        if (sessionHandler) {
          await sessionHandler(req, body, res);
        } else {
          res.writeHead(200, {
            "content-type": "application/json",
            "x-raven-session": "1",
          });
          res.end(JSON.stringify({ handle: 1, expires_at_unix_secs: 1 }));
        }
        return;
      }
      for (const { match, handler } of handlers) {
        if (!match(req)) continue;
        let claimed: boolean;
        try {
          claimed = await handler(req, body, res);
        } catch (err) {
          // Several routes assert on the request body. A throw there used to leave the
          // response unwritten, so the SDK's fetch hung to the 60 s test timeout and the
          // failure surfaced as a timeout rather than the assertion. Answer, then rethrow
          // so the assertion still reaches the runner.
          if (!res.headersSent) {
            res.writeHead(500, { "content-type": "text/plain" });
            res.end(`mock route threw: ${String(err)}`);
          }
          throw err;
        }
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
    routeSession(handler) {
      sessionHandler = handler;
    },
    reset() {
      requests.length = 0;
      handlers.length = 0;
      sessionHandler = undefined;
    },
    async close() {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    },
  };
}

/** Write a JSON 200 response with optional extra headers. */
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

export function readJsonRpcRequest(body: Uint8Array): JsonRpcRequest {
  return JSON.parse(new TextDecoder().decode(body)) as JsonRpcRequest;
}

export function writeJsonRpcResult(
  body: Uint8Array,
  res: ServerResponse,
  result: unknown,
): JsonRpcRequest {
  const request = readJsonRpcRequest(body);
  writeJson(res, { jsonrpc: "2.0", id: request.id, result });
  return request;
}

/** Write an octet-stream 200 response with optional extra headers. */
export function writeBinary(
  res: ServerResponse,
  bytes: Uint8Array,
  extraHeaders: Record<string, string> = {},
): void {
  res.writeHead(200, {
    "content-type": "application/octet-stream",
    "x-raven-freshness": "lag_blocks=0 applied_height=0 epoch=1 confidence=1",
    ...extraHeaders,
  });
  res.end(Buffer.from(bytes));
}

/** Write a plain-text error response with the given status. */
export function writeError(
  res: ServerResponse,
  status: number,
  message: string,
): void {
  res.writeHead(status, { "content-type": "text/plain" });
  res.end(message);
}

/** Deterministic 32-byte commitment-shaped buffer keyed on `tag`. */
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
