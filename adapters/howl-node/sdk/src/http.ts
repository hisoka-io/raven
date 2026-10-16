import { HowlError } from "./errors.js";

/** One HTTP exchange with a node: the status and the body bytes. */
export interface Exchange {
  readonly status: number;
  readonly body: Uint8Array;
}

/** How the client reaches a node. Swap it to add headers, a proxy or an anonymity network. */
export interface HowlTransport {
  get(path: string): Promise<Exchange>;
  post(path: string, body: Uint8Array): Promise<Exchange>;
}

/** Bytes moved through a transport, for callers that budget a sync. */
export interface TransportStats {
  requests: number;
  bytesUp: number;
  bytesDown: number;
}

export interface FetchTransportOptions {
  /** Defaults to the global `fetch`. */
  readonly fetch?: typeof fetch;
  /** Per request; default 30 s. */
  readonly timeoutMs?: number;
}

/** A transport over `fetch` against `baseUrl` (no trailing path). */
export function fetchTransport(
  baseUrl: string,
  options: FetchTransportOptions = {},
): HowlTransport & { readonly stats: TransportStats } {
  const doFetch = options.fetch ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? 30_000;
  const root = baseUrl.replace(/\/+$/, "");
  const stats: TransportStats = { requests: 0, bytesUp: 0, bytesDown: 0 };
  const send = async (path: string, init: RequestInit): Promise<Exchange> => {
    const url = `${root}${path}`;
    let response: Response;
    try {
      response = await doFetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    } catch (e) {
      throw new HowlError("Network", `${init.method ?? "GET"} ${path}: ${String(e)}`, {
        cause: e,
      });
    }
    let body: Uint8Array;
    try {
      body = new Uint8Array(await response.arrayBuffer());
    } catch (e) {
      throw new HowlError("Network", `${path}: body did not arrive: ${String(e)}`, {
        cause: e,
      });
    }
    stats.requests += 1;
    stats.bytesDown += body.length;
    return { status: response.status, body };
  };
  return {
    stats,
    get: (path) => send(path, { method: "GET" }),
    post: (path, body) => {
      stats.bytesUp += body.length;
      // copied into an ArrayBuffer-backed view, which every fetch accepts as a body
      return send(path, {
        method: "POST",
        body: new Uint8Array(body),
        headers: { "content-type": "application/octet-stream" },
      });
    },
  };
}
