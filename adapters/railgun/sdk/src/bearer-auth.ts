/** The one place an adapter `Authorization` header is built. */

import { RavenError } from "./errors";

// fetch trims edge whitespace silently and quotes any byte it rejects back in its TypeError,
// which would carry the token into an error context.
const SENDABLE_TOKEN = /^[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?$/;

/**
 * Headers authenticating one adapter request; empty for a node that takes no credential.
 * Any other value is refused rather than interpolated: `Bearer undefined` and a bare
 * `Bearer` both look authenticated on the wire and are not.
 */
export function bearerHeaders(bearerToken: string | undefined): Record<string, string> {
  if (bearerToken === undefined) return {};
  if (typeof bearerToken !== "string" || !SENDABLE_TOKEN.test(bearerToken)) {
    const shape =
      typeof bearerToken === "string"
        ? `a ${bearerToken.length}-character string outside that shape`
        : bearerToken === null
          ? "null"
          : typeof bearerToken;
    throw RavenError.invalidQuery(
      "bearerToken must be printable ASCII with no leading or trailing whitespace, " +
        `got ${shape}; omit it for a node that takes no credential`,
    );
  }
  return { authorization: `Bearer ${bearerToken}` };
}
