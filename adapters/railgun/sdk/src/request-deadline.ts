import { RavenError } from "./errors";

/** The stock wallet interface gives each POI node request 60 s. */
export const DEFAULT_REQUEST_TIMEOUT_MS = 60_000;

/** Largest delay a runtime timer accepts; a longer one fires at once. */
const MAX_TIMER_MS = 2 ** 31 - 1;

const NULL_BODY_STATUSES = new Set([101, 204, 205, 304]);

/** Validates a caller-supplied request deadline. */
export function checkedRequestTimeoutMs(value: number | undefined): number {
  const timeoutMs = value ?? DEFAULT_REQUEST_TIMEOUT_MS;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TIMER_MS) {
    throw RavenError.invalidQuery(
      `requestTimeoutMs must be a positive number of milliseconds no greater than ` +
        `${MAX_TIMER_MS}, got ${value}`,
    );
  }
  return timeoutMs;
}

async function readWhole(
  fetchImpl: typeof fetch,
  input: Parameters<typeof fetch>[0],
  init: RequestInit,
): Promise<Response> {
  const response = await fetchImpl(input, init);
  const body = NULL_BODY_STATUSES.has(response.status) ? null : await response.arrayBuffer();
  return new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
}

/**
 * `fetchImpl` bounded by `timeoutMs` from request to last body byte. The body is read here, so
 * a node that stalls mid-body fails the fetch itself and every caller reports it as the
 * `Network` failure it already maps a failed fetch to. The deadline holds even for a
 * `fetchImpl` that ignores its abort signal. A caller's own signal still ends the request first
 * if it fires first; the two are joined by hand because `AbortSignal.any` is missing on some
 * runtimes this package supports.
 */
export function fetchWithDeadline(fetchImpl: typeof fetch, timeoutMs: number): typeof fetch {
  return (input, init) => {
    const stops = [AbortSignal.timeout(timeoutMs)];
    if (init?.signal) stops.push(init.signal);
    const joined = new AbortController();
    return new Promise<Response>((resolve, reject) => {
      const tripped = stops.find((stop) => stop.aborted);
      if (tripped) {
        reject(tripped.reason);
        return;
      }
      const expiries = stops.map((stop) => {
        const expire = (): void => {
          joined.abort(stop.reason);
          reject(stop.reason);
        };
        stop.addEventListener("abort", expire, { once: true });
        return () => stop.removeEventListener("abort", expire);
      });
      readWhole(fetchImpl, input, { ...init, signal: joined.signal })
        .then(resolve, reject)
        .finally(() => {
          for (const release of expiries) release();
        });
    });
  };
}
