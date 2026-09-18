/**
 * The ONE test-side pin of the wire schema version.
 *
 * This is deliberately a literal and not an import of the SDK's internal
 * `WIRE_SCHEMA_VERSION`: a pin that follows production automatically cannot catch an
 * accidental bump, which is the whole reason the suite pins it. It is centralised here
 * because the 6 -> 7 bump left the old literal behind in one helper and turned **39
 * assertions across 12 files red at once**, burying the real signal. A future bump now
 * fails here, loudly, in one place.
 *
 * When production bumps: change this constant, and expect exactly the tests that assert
 * a *previous* version (fail-closed refusals) to need a second look.
 */
export const EXPECTED_WIRE_SCHEMA_VERSION = 7;

/** The two big-endian prefix bytes every batch and query body opens with. */
export const EXPECTED_WIRE_SCHEMA_PREFIX: readonly [number, number] = [
  (EXPECTED_WIRE_SCHEMA_VERSION >>> 8) & 0xff,
  EXPECTED_WIRE_SCHEMA_VERSION & 0xff,
];
