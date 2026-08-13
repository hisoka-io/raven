// The server serialises `StatusHeaderResponse` with `#[serde(rename_all = "camelCase")]`
// (`http/src/poi_shim.rs`), so the wire keys are `blockedBcs` / `pendingBcs` / `listKey`.
// The SDK declared snake_case, which TypeScript reported as `string[]` while the fields
// did not exist at runtime: `new Set(h.blocked_bcs ?? [])` yields an EMPTY set, so every
// ShieldBlocked commitment on the list reads as clean. Fail-open on the fast publishing
// channel, with the types asserting it was safe.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { RavenPOINodeInterface } from "../src/index";
import { startMockServer, type MockServer } from "./helpers/mock_server";

const TOKEN = "test-bearer-token-0123456789abcdef";
const LIST_KEY_HEX = "aa".repeat(32);
const BLOCKED = "11".repeat(32);
const PENDING = "22".repeat(32);

let server: MockServer;

beforeAll(async () => {
  server = await startMockServer();
});
afterAll(async () => {
  await server.close();
});
afterEach(() => {
  server.reset();
});

/** Exactly what the Rust handler emits. */
function serveCamelCaseHeader(): void {
  server.route(
    (req) => req.url?.endsWith("/status-header") ?? false,
    (_req, _body, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          epoch: 42,
          listKey: LIST_KEY_HEX,
          blockedBcs: [BLOCKED],
          pendingBcs: [PENDING],
        }),
      );
      return true;
    },
  );
}

function sdk(): RavenPOINodeInterface {
  return new RavenPOINodeInterface({ endpoint: server.url, bearerToken: TOKEN });
}

describe("status-header wire shape", () => {
  it("returns the blocked set the server actually sent", async () => {
    serveCamelCaseHeader();
    const header = await sdk().fetchStatusHeader(LIST_KEY_HEX);
    expect(header.epoch).toBe(42);
    expect(header.blockedBcs).toEqual([BLOCKED]);
    expect(header.pendingBcs).toEqual([PENDING]);
  });

  it("a blocked commitment is present in the decoded set", async () => {
    serveCamelCaseHeader();
    const header = await sdk().fetchStatusHeader(LIST_KEY_HEX);
    // The consumer shape: an empty set here is the defect, because it makes a
    // ShieldBlocked commitment indistinguishable from a clean one.
    const blocked = new Set(header.blockedBcs);
    expect(blocked.size).toBe(1);
    expect(blocked.has(BLOCKED)).toBe(true);
  });

  it("rejects a response missing the blocked array rather than defaulting it to empty", async () => {
    server.route(
      (req) => req.url?.endsWith("/status-header") ?? false,
      (_req, _body, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ epoch: 42, listKey: LIST_KEY_HEX, pendingBcs: [] }));
        return true;
      },
    );
    await expect(sdk().fetchStatusHeader(LIST_KEY_HEX)).rejects.toThrow(/blockedBcs/);
  });

  it("rejects a response whose blocked array is not an array of strings", async () => {
    server.route(
      (req) => req.url?.endsWith("/status-header") ?? false,
      (_req, _body, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            epoch: 42,
            listKey: LIST_KEY_HEX,
            blockedBcs: [1, 2, 3],
            pendingBcs: [],
          }),
        );
        return true;
      },
    );
    await expect(sdk().fetchStatusHeader(LIST_KEY_HEX)).rejects.toThrow(/blockedBcs/);
  });
});
