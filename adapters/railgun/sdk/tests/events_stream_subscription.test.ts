// `subscribeRavenEvents` is exported from the barrel and had no test of any kind. Node has no
// global EventSource, so the whole streaming path -- URL, state machine, status delivery,
// reconnect -- was unreachable; a fake global makes it reachable.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { subscribeRavenEvents, type RavenStatusBody } from "../src/index";

type Handler = (ev: unknown) => void;

/** Minimal EventSource stand-in: records construction args and replays events on demand. */
class FakeEventSource {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSED = 2;
  static instances: FakeEventSource[] = [];

  readState = FakeEventSource.CONNECTING;
  closeCount = 0;
  private readonly handlers = new Map<string, Handler[]>();

  constructor(
    readonly url: string,
    readonly init: { withCredentials: boolean },
  ) {
    FakeEventSource.instances.push(this);
  }

  get readyState(): number {
    return this.readState;
  }

  addEventListener(type: string, handler: Handler): void {
    const list = this.handlers.get(type) ?? [];
    list.push(handler);
    this.handlers.set(type, list);
  }

  close(): void {
    this.closeCount += 1;
    this.readState = FakeEventSource.CLOSED;
  }

  emit(type: string, ev?: unknown): void {
    for (const h of this.handlers.get(type) ?? []) h(ev);
  }
}

const globalRef = globalThis as unknown as { EventSource?: unknown };
let savedEventSource: unknown;

const SAMPLE: RavenStatusBody = {
  scheme: "inspire",
  instances: [
    {
      id: "commit-tree-0",
      epoch: 7,
      role: "live",
      drain_state: "active",
      in_flight: 0,
      active_k_concurrency: 4,
    },
  ],
  consumer: null,
};

function messageEvent(data: string): unknown {
  return { data };
}

beforeEach(() => {
  savedEventSource = globalRef.EventSource;
  FakeEventSource.instances = [];
  globalRef.EventSource = FakeEventSource;
});

afterEach(() => {
  if (savedEventSource === undefined) delete globalRef.EventSource;
  else globalRef.EventSource = savedEventSource;
  vi.useRealTimers();
});

describe("subscribeRavenEvents without an EventSource runtime", () => {
  it("reports closed and hands back an inert handle instead of throwing", () => {
    delete globalRef.EventSource;
    const states: string[] = [];
    const handle = subscribeRavenEvents({ endpoint: "http://x" }, () => undefined, (s) =>
      states.push(s),
    );
    expect(handle.state).toBe("closed");
    expect(states).toEqual(["closed"]);
    expect(() => handle.close()).not.toThrow();
  });
});

describe("subscribeRavenEvents stream lifecycle", () => {
  it("connects to /v1/events with the trailing slash stripped", () => {
    subscribeRavenEvents({ endpoint: "http://adapter.test/" }, () => undefined);
    expect(FakeEventSource.instances).toHaveLength(1);
    expect(FakeEventSource.instances[0].url).toBe("http://adapter.test/v1/events");
  });

  it("defaults withCredentials off and forwards it when set", () => {
    subscribeRavenEvents({ endpoint: "http://a" }, () => undefined);
    expect(FakeEventSource.instances[0].init.withCredentials).toBe(false);
    subscribeRavenEvents({ endpoint: "http://a", withCredentials: true }, () => undefined);
    expect(FakeEventSource.instances[1].init.withCredentials).toBe(true);
  });

  it("walks connecting -> open -> error and reports every transition", () => {
    const states: string[] = [];
    const handle = subscribeRavenEvents({ endpoint: "http://a" }, () => undefined, (s) =>
      states.push(s),
    );
    expect(handle.state).toBe("connecting");
    FakeEventSource.instances[0].emit("open");
    expect(handle.state).toBe("open");
    FakeEventSource.instances[0].emit("error");
    expect(handle.state).toBe("error");
    expect(states).toEqual(["connecting", "open", "error"]);
  });

  it("delivers a parsed status body to the consumer", () => {
    const seen: RavenStatusBody[] = [];
    subscribeRavenEvents({ endpoint: "http://a" }, (s) => seen.push(s));
    FakeEventSource.instances[0].emit("status", messageEvent(JSON.stringify(SAMPLE)));
    expect(seen).toHaveLength(1);
    expect(seen[0].instances[0].epoch).toBe(7);
    expect(seen[0].scheme).toBe("inspire");
  });

  it("close() shuts the source, reports closed, and stops delivery", () => {
    const seen: RavenStatusBody[] = [];
    const states: string[] = [];
    const handle = subscribeRavenEvents({ endpoint: "http://a" }, (s) => seen.push(s), (s) =>
      states.push(s),
    );
    const es = FakeEventSource.instances[0];
    es.emit("open");
    handle.close();
    expect(handle.state).toBe("closed");
    expect(es.closeCount).toBe(1);
    expect(states[states.length - 1]).toBe("closed");
    es.emit("error");
    // An error arriving after close must not resurrect the handle.
    expect(handle.state).toBe("closed");
    expect(seen).toHaveLength(0);
  });

  it("reconnects five seconds after the source closes on error", () => {
    vi.useFakeTimers();
    subscribeRavenEvents({ endpoint: "http://a" }, () => undefined);
    const es = FakeEventSource.instances[0];
    es.readState = FakeEventSource.CLOSED;
    es.emit("error");
    expect(FakeEventSource.instances).toHaveLength(1);
    vi.advanceTimersByTime(5_000);
    expect(FakeEventSource.instances).toHaveLength(2);
    expect(FakeEventSource.instances[1].url).toBe("http://a/v1/events");
  });

  it("does not reconnect after close(), even with a retry already scheduled", () => {
    vi.useFakeTimers();
    const handle = subscribeRavenEvents({ endpoint: "http://a" }, () => undefined);
    const es = FakeEventSource.instances[0];
    es.readState = FakeEventSource.CLOSED;
    es.emit("error");
    handle.close();
    vi.advanceTimersByTime(60_000);
    expect(FakeEventSource.instances).toHaveLength(1);
  });

  it("leaves the retry unscheduled while the source is still open", () => {
    vi.useFakeTimers();
    subscribeRavenEvents({ endpoint: "http://a" }, () => undefined);
    const es = FakeEventSource.instances[0];
    es.readState = FakeEventSource.OPEN;
    es.emit("error");
    vi.advanceTimersByTime(60_000);
    expect(FakeEventSource.instances).toHaveLength(1);
  });
});

// CHARACTERIZES the empty catch around the status handler. Everything below is today's
// behaviour, not the intended contract; each assertion is one a fix would invert.
describe("subscribeRavenEvents swallows what it cannot read", () => {
  it("drops a malformed status frame with no callback and no state change", () => {
    const seen: RavenStatusBody[] = [];
    const states: string[] = [];
    const handle = subscribeRavenEvents({ endpoint: "http://a" }, (s) => seen.push(s), (s) =>
      states.push(s),
    );
    FakeEventSource.instances[0].emit("status", messageEvent("{not json"));
    expect(seen).toHaveLength(0);
    // Nothing tells the caller a frame was lost: still "connecting", never "error".
    expect(handle.state).toBe("connecting");
    expect(states).toEqual(["connecting"]);
  });

  it("hands a well-formed-but-wrong-shape body to the consumer unchecked", () => {
    // `JSON.parse(data) as RavenStatusBody` is a cast, not a parse: `instances` is absent at
    // runtime while its type says RavenStatusBody, so the first consumer to iterate it throws.
    const seen: RavenStatusBody[] = [];
    subscribeRavenEvents({ endpoint: "http://a" }, (s) => seen.push(s));
    FakeEventSource.instances[0].emit("status", messageEvent(JSON.stringify({ scheme: 42 })));
    expect(seen).toHaveLength(1);
    expect(seen[0].instances).toBeUndefined();
    expect(seen[0].scheme as unknown).toBe(42);
  });

  it("swallows an exception thrown by the consumer's own handler", () => {
    // The same catch that guards JSON.parse also covers onStatus, so a bug in the wallet's
    // handler is invisible: no rethrow, no state change, and the stream keeps running.
    let calls = 0;
    const handle = subscribeRavenEvents({ endpoint: "http://a" }, () => {
      calls += 1;
      throw new Error("consumer bug");
    });
    const es = FakeEventSource.instances[0];
    expect(() => es.emit("status", messageEvent(JSON.stringify(SAMPLE)))).not.toThrow();
    es.emit("status", messageEvent(JSON.stringify(SAMPLE)));
    expect(calls).toBe(2);
    expect(handle.state).toBe("connecting");
  });
});
