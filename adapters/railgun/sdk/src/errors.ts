/** Typed error taxonomy for the SDK; discriminated union keyed on `kind`. */

export type RavenErrorKind =
  | "Network"
  | "InvalidQuery"
  | "StaleAdapter"
  | "StaleData"
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

/** Public freshness values carried by a private stale-data refusal. */
export interface StaleDataContext {
  readonly operation: "t1-status" | "t2-auth-path" | "fanout";
  readonly lagBlocks: number;
  readonly appliedHeight: number;
  readonly epoch: number;
  readonly confidence: number;
  readonly confidenceFloor: number;
}

/** A private response refused because its confidence is below the configured floor. */
export type StaleDataError = RavenError<StaleDataContext> & {
  readonly kind: "StaleData";
  readonly context: StaleDataContext;
};

/** Kind-specific Raven error type returned by [`RavenError.is`]. */
export type RavenErrorByKind<K extends RavenErrorKind> = K extends "StaleData"
  ? StaleDataError
  : RavenError & { readonly kind: K };

/** Error class with a discriminated `kind` field; narrow via `RavenError.is`. */
export class RavenError<C = RavenErrorContext> extends Error {
  public readonly kind: RavenErrorKind;
  public readonly context: C;

  private constructor(kind: RavenErrorKind, message: string, context: C) {
    super(message);
    this.name = "RavenError";
    this.kind = kind;
    this.context = context;
    // Restores `instanceof RavenError` across a transpiled `extends`.
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

  /** Private data below the caller's confidence floor; fail closed by default. */
  static staleData(message: string, context: StaleDataContext): StaleDataError {
    return new RavenError("StaleData", message, context) as StaleDataError;
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
  static is<K extends RavenErrorKind>(err: unknown, kind: K): err is RavenErrorByKind<K> {
    return err instanceof RavenError && err.kind === kind;
  }
}
