/** Typed error taxonomy for the SDK; discriminated union keyed on `kind`. */

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

/** Error class with a discriminated `kind` field; narrow via `RavenError.is`. */
export class RavenError extends Error {
  public readonly kind: RavenErrorKind;
  public readonly context: RavenErrorContext;

  private constructor(kind: RavenErrorKind, message: string, context: RavenErrorContext) {
    super(message);
    this.name = "RavenError";
    this.kind = kind;
    this.context = context;
    // restore prototype so `instanceof RavenError` survives transpiled extends
    Object.setPrototypeOf(this, RavenError.prototype);
  }

  /** Network-layer failure (DNS, TLS, refused, abort); retryable. */
  static network(message: string, context: RavenErrorContext = {}): RavenError {
    return new RavenError("Network", message, context);
  }

  /** Pre-flight input validation failure; not retryable, the input is wrong. */
  static invalidQuery(message: string, context: RavenErrorContext = {}): RavenError {
    return new RavenError("InvalidQuery", message, context);
  }

  /** Adapter wire-schema is stale; refresh from `/v1/status` and retry. */
  static staleAdapter(message: string, context: RavenErrorContext = {}): RavenError {
    return new RavenError("StaleAdapter", message, context);
  }

  /** Server 4xx/5xx (except the 400 stale-schema path); `status` carries the code. */
  static serverError(message: string, context: RavenErrorContext = {}): RavenError {
    return new RavenError("ServerError", message, context);
  }

  /** 2xx response whose body the SDK could not decode (truncated/malformed). */
  static decodeError(message: string, context: RavenErrorContext = {}): RavenError {
    return new RavenError("DecodeError", message, context);
  }

  /** Batch reply count disagrees with expected; bytes parsed but count is wrong. */
  static batchMismatch(message: string, context: RavenErrorContext = {}): RavenError {
    return new RavenError("BatchMismatch", message, context);
  }

  /** Type-narrow predicate: true iff `err` is a `RavenError` of `kind`. */
  static is<K extends RavenErrorKind>(err: unknown, kind: K): err is RavenError & { kind: K } {
    return err instanceof RavenError && err.kind === kind;
  }
}
