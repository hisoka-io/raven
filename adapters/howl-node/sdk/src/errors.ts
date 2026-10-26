/** Why a call to the node did not give an answer the client accepts. */
export type HowlErrorKind =
  /** The request did not reach the node, or its answer did not arrive. */
  | "Network"
  /** The node's state is behind what the request named (409). */
  | "Stale"
  /** The session handle expired or is unknown to the node (410). */
  | "SessionExpired"
  /** The node is over its request or session rate (429), its seats or respond queue are full, or
   *  it is shutting down (503). The same call may succeed later. */
  | "Busy"
  /** The node refused the request as malformed (400, 422, others). */
  | "Refused"
  /** The answer did not decode, or its parts disagree with each other or with what the
   *  client already verified. */
  | "Protocol";

/** The tree state an answer was read at. */
export interface AnswerState {
  readonly leafCount: number;
  readonly block: number;
}

export class HowlError extends Error {
  readonly kind: HowlErrorKind;
  readonly status: number | undefined;
  /** For `Stale`: where the node stands. */
  readonly state: AnswerState | undefined;

  constructor(
    kind: HowlErrorKind,
    message: string,
    options: { status?: number; state?: AnswerState; cause?: unknown } = {},
  ) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "HowlError";
    this.kind = kind;
    this.status = options.status;
    this.state = options.state;
  }

  /** True when the same call may succeed later unchanged. */
  get retryable(): boolean {
    return this.kind === "Network" || this.kind === "Busy";
  }
}

/** Run a wasm call, raising what it throws as a `Protocol` error. */
export function protocol<T>(what: string, call: () => T): T {
  try {
    return call();
  } catch (e) {
    const detail = e instanceof Error ? e.message : String(e);
    throw new HowlError("Protocol", `${what}: ${detail}`, { cause: e });
  }
}
