/**
 * Typed error taxonomy for the Raven Railgun SDK.
 *
 * Every error surfaced by the SDK is one of the variants below. The
 * shape is a discriminated union keyed on `kind` so callers can
 * exhaustively switch on the variant without inspecting the message
 * text. Constructors carry context fields (URL, status code, retry
 * hint) so the wallet can decide whether to retry, fall back to the
 * upstream PPOI service, or surface to the user.
 *
 * Why a custom error class instead of `instanceof Error` checks alone:
 * the bundler-emitted ESM wasm module raises bare `Error` exceptions
 * via wasm-bindgen's `JsValue::from_str`, which lose context across
 * realm boundaries. We catch every wasm error at the SDK layer and
 * promote to a typed `RavenError` so the wallet sees a single
 * coherent error surface.
 */

export type RavenErrorKind =
  | "Network"
  | "InvalidQuery"
  | "StaleAdapter"
  | "ServerError"
  | "DecodeError"
  | "BatchMismatch";

export interface RavenErrorContext {
  /** Outbound URL the SDK was talking to when this error arose. */
  readonly url?: string;
  /** HTTP status code when applicable. */
  readonly status?: number;
  /** Wire schema version the server reported when applicable. */
  readonly serverWireSchemaVersion?: number;
  /** Wire schema version the SDK was speaking. */
  readonly clientWireSchemaVersion?: number;
  /** Underlying upstream error message when wrapping a thrown error. */
  readonly cause?: string;
}

/**
 * Base error class with a discriminated `kind` field. Use
 * `RavenError.is(err, "Network")` for type-narrowed branching in
 * application code.
 */
export class RavenError extends Error {
  public readonly kind: RavenErrorKind;
  public readonly context: RavenErrorContext;

  private constructor(kind: RavenErrorKind, message: string, context: RavenErrorContext) {
    super(message);
    this.name = "RavenError";
    this.kind = kind;
    this.context = context;
    // V8/Node sets the prototype explicitly so `instanceof RavenError`
    // works even after class extension (TS class hierarchy quirk).
    Object.setPrototypeOf(this, RavenError.prototype);
  }

  /**
   * Network-layer failure (DNS, TLS, connection refused, abort).
   * Caller should retry with exponential backoff.
   */
  static network(message: string, context: RavenErrorContext = {}): RavenError {
    return new RavenError("Network", message, context);
  }

  /**
   * Pre-flight input validation failure (malformed BC hex, wrong
   * list_key length, leaf_index out of range). Caller should NOT
   * retry; the input is the problem.
   */
  static invalidQuery(message: string, context: RavenErrorContext = {}): RavenError {
    return new RavenError("InvalidQuery", message, context);
  }

  /**
   * The configured adapter is on a stale wire-schema version and the
   * server has rejected the request. Caller should refresh the
   * routing table from `/v1/status` (which advertises the server's
   * current `WIRE_SCHEMA_VERSION`) and re-try.
   */
  static staleAdapter(message: string, context: RavenErrorContext = {}): RavenError {
    return new RavenError("StaleAdapter", message, context);
  }

  /**
   * Server returned 4xx or 5xx (other than the 400 stale-schema
   * codepath, which surfaces as `StaleAdapter`). The status field
   * carries the HTTP code so callers can map 401 -> re-auth, 429 ->
   * rate-limit-aware backoff, 5xx -> retry.
   */
  static serverError(message: string, context: RavenErrorContext = {}): RavenError {
    return new RavenError("ServerError", message, context);
  }

  /**
   * Server returned a successful response whose body the SDK could
   * not decode (truncated, wrong content-type, malformed bincode).
   */
  static decodeError(message: string, context: RavenErrorContext = {}): RavenError {
    return new RavenError("DecodeError", message, context);
  }

  /**
   * Server's batch reply length disagrees with the SDK's expected
   * count. Distinct from `DecodeError` because the bytes parsed
   * cleanly; the count is what's wrong.
   */
  static batchMismatch(message: string, context: RavenErrorContext = {}): RavenError {
    return new RavenError("BatchMismatch", message, context);
  }

  /**
   * Type narrow predicate: `RavenError.is(err, "Network")` returns
   * true iff `err` is a `RavenError` of the requested kind. Useful
   * inside `catch` blocks where TypeScript widens the caught value
   * to `unknown`.
   */
  static is<K extends RavenErrorKind>(err: unknown, kind: K): err is RavenError & { kind: K } {
    return err instanceof RavenError && err.kind === kind;
  }
}
