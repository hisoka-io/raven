/**
 * SSE subscriber for the Raven adapter's `/v1/events` endpoint (S038).
 *
 * Replaces poll-based status fetches with one long-lived HTTP/2 stream
 * per browser tab. The server pushes a `status` event every ~5 s with
 * the same shape the JSON-on-demand `/v1/status` endpoint returns.
 *
 * Falls back to no-op if the runtime lacks `EventSource` (older Node
 * test environments). Wallet integrators on browser targets get the
 * stream; SSR / non-browser callers get a static null.
 */

export interface InstanceStatus {
  id: string;
  epoch: number;
  role: string;
  drain_state: string;
  in_flight: number;
  active_k_concurrency: number;
}

export interface ConsumerStatus {
  last_applied_block: number;
  last_known_chain_head: number;
  indexer_lag_blocks: number;
  events_processed: number;
  commits_fired: number;
  reorgs_handled: number;
  consumer_errors: number;
}

export interface StatusBody {
  scheme: string;
  instances: InstanceStatus[];
  consumer: ConsumerStatus | null;
}

export interface RavenEventsConfig {
  endpoint: string;
  withCredentials?: boolean;
}

export interface RavenEventsHandle {
  close(): void;
  readonly state: "connecting" | "open" | "error" | "closed";
}

type Listener = (status: StatusBody) => void;
type StateListener = (state: RavenEventsHandle["state"]) => void;

export function subscribeRavenEvents(
  config: RavenEventsConfig,
  onStatus: Listener,
  onState?: StateListener,
): RavenEventsHandle {
  if (typeof EventSource === "undefined") {
    onState?.("closed");
    return {
      state: "closed",
      close: () => undefined,
    };
  }

  let state: RavenEventsHandle["state"] = "connecting";
  let source: EventSource | null = null;
  let closed = false;

  const setState = (next: RavenEventsHandle["state"]) => {
    state = next;
    onState?.(next);
  };

  const open = () => {
    if (closed) return;
    const url = `${config.endpoint.replace(/\/$/, "")}/v1/events`;
    const es = new EventSource(url, {
      withCredentials: config.withCredentials ?? false,
    });
    source = es;
    setState("connecting");

    es.addEventListener("open", () => {
      if (!closed) setState("open");
    });
    es.addEventListener("status", (ev) => {
      try {
        const data = (ev as MessageEvent<string>).data;
        const parsed = JSON.parse(data) as StatusBody;
        onStatus(parsed);
      } catch {
        // ignore: malformed event payload
      }
    });
    es.addEventListener("error", () => {
      if (closed) return;
      setState("error");
      if (es.readyState === EventSource.CLOSED) {
        source = null;
        setTimeout(open, 5_000);
      }
    });
  };

  open();

  return {
    get state() {
      return state;
    },
    close() {
      closed = true;
      source?.close();
      source = null;
      setState("closed");
    },
  };
}
