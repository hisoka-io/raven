// A request that says `Bearer undefined` looks authenticated and is not. `process.env.NAME!`
// with NAME unset hands the SDK `undefined` typed as `string`; interpolated, that is a header
// on every adapter route. Upstream Railgun's own POI client sends no credential at all, so a
// node that takes none has to be expressible too.

import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { ChainRegistry, RavenError, RavenPOINodeInterface } from "../src/index";
import {
  TOKEN,
  encodeBatchResponseNodes,
  encodedBatchCount,
  stubCtx,
} from "./helpers/auth_path_stub";
import { forestConfig } from "./helpers/forest";
import {
  startMockServer,
  writeBinary,
  writeJson,
  writeJsonRpcResult,
  type MockServer,
  type RecordedRequest,
} from "./helpers/mock_server";
import { PATH10_ROW_BYTES, path10Root, path10Siblings, path10Slot } from "./helpers/path10_row";
import { mountPrefixChannel } from "./helpers/prefix_channel";

const LIST_KEY = "ab".repeat(32);
const BC = "bc00112233445566778899aabbccddeeff00112233445566778899aabbccdd01";
const ROOT = "00".repeat(32);
const NODES = path10Siblings(0x2a);

// What `process.env.RAVEN_BEARER_TOKEN!` evaluates to when the variable is unset.
const UNSET_ENV_TOKEN = process.env.RAVEN_SDK_TEST_TOKEN_THAT_IS_NEVER_SET!;

type Site = "bcPrefixes" | "session" | "batch" | "registryRefresh" | "upstream";

/** The part of a request both the mock's matcher and its recorder expose. */
interface RequestLine {
  readonly method?: string;
  readonly url?: string;
}

const SITE_OF: Record<Site, (request: RequestLine) => boolean> = {
  bcPrefixes: (r) => r.method === "GET" && (r.url ?? "").includes("/bc-prefixes?"),
  session: (r) => r.method === "POST" && (r.url ?? "").endsWith("/session"),
  batch: (r) => r.method === "POST" && (r.url ?? "").endsWith("/batch"),
  registryRefresh: (r) => r.method === "GET" && r.url === "/v1/status",
  upstream: (r) => r.method === "POST" && r.url === "/",
};

const ADAPTER_SITES: Site[] = ["bcPrefixes", "session", "batch", "registryRefresh"];

/** Holds the one note at index 0, so a proof call still reaches the session and batch routes
 *  when the index channel refuses it. */
function privateSdk(server: MockServer, credential: { bearerToken?: string }): RavenPOINodeInterface {
  return new RavenPOINodeInterface({
    ...forestConfig({
      endpoint: server.url,
      listKeyHex: LIST_KEY,
      ctx: { ...stubCtx(), entrySize: PATH10_ROW_BYTES },
      placed: [[BC, 0]],
      pins: new Map([[0, path10Root(BC, NODES, 0)]]),
    }),
    ...credential,
    upstreamFallbackEndpoint: server.url,
  });
}

function mountEveryRoute(server: MockServer): void {
  mountPrefixChannel(server, LIST_KEY, { commitments: [BC] });
  server.route(SITE_OF.batch, (_req, body, res) => {
    const slots = encodedBatchCount(body);
    const slot = path10Slot({ bcHex: BC, nodes: NODES });
    writeBinary(res, encodeBatchResponseNodes(Array.from({ length: slots }, () => slot)));
    return true;
  });
  server.route(SITE_OF.registryRefresh, (_req, _body, res) => {
    writeJson(res, { scheme: "inspire", instances: [], consumer: null });
    return true;
  });
  server.route(SITE_OF.upstream, (_req, body, res) => {
    writeJsonRpcResult(body, res, true);
    return true;
  });
}

/** Drives every route the SDK can reach, adapter and upstream, under one credential config. */
async function driveEverySite(
  server: MockServer,
  credential: { bearerToken?: string },
): Promise<void> {
  mountEveryRoute(server);
  const commitments = [{ blindedCommitment: BC, type: "Shield" as const }];

  const sdk = privateSdk(server, credential);
  expect(await sdk.getPOIsPerList([LIST_KEY], commitments)).toEqual({
    [BC]: { [LIST_KEY]: "Valid" },
  });
  expect(await sdk.getPOIMerkleProofs(LIST_KEY, [BC])).toHaveLength(1);
  expect(await sdk.validatePOIMerkleroots(LIST_KEY, [ROOT])).toBe(true);

  await new ChainRegistry([{ chainId: 1, endpoint: server.url, ...credential }]).refresh(1);
}

type SentBySite = Record<Site, string | undefined>;

/** What each site sent; throws if a site went unexercised or disagreed with itself. */
function authorizationBySite(requests: readonly RecordedRequest[]): SentBySite {
  const sites = Object.keys(SITE_OF) as Site[];
  const unclassified = requests.filter((r) => !sites.some((site) => SITE_OF[site](r)));
  if (unclassified.length > 0) {
    throw new Error(
      `unclassified requests: ${unclassified.map((r) => `${r.method} ${r.url}`).join(", ")}`,
    );
  }
  const observed = {} as SentBySite;
  for (const site of sites) {
    const sent = requests.filter(SITE_OF[site]).map((r) => r.headers.authorization);
    if (sent.length === 0) throw new Error(`site ${site} was never exercised`);
    const distinct = new Set(sent);
    if (distinct.size !== 1) throw new Error(`site ${site} sent ${[...distinct].join(" | ")}`);
    const only = sent[0];
    observed[site] = Array.isArray(only) ? only.join(",") : only;
  }
  return observed;
}

function everySite(value: (site: Site) => string | undefined): SentBySite {
  const expected = {} as SentBySite;
  for (const site of Object.keys(SITE_OF) as Site[]) expected[site] = value(site);
  return expected;
}

describe("adapter authorization header", () => {
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

  it("the unset-environment fixture really is undefined", () => {
    expect(UNSET_ENV_TOKEN).toBeUndefined();
  });

  const NO_CREDENTIAL: [string, { bearerToken?: string }][] = [
    ["field omitted", {}],
    ["unset environment variable", { bearerToken: UNSET_ENV_TOKEN }],
  ];

  it.each(NO_CREDENTIAL)(
    "a node with no credential receives no authorization header on any route: %s",
    async (_name, credential) => {
      await driveEverySite(server, credential);
      expect(authorizationBySite(server.requests)).toEqual(everySite(() => undefined));
    },
  );

  it("every adapter route carries the configured token and upstream never sees it", async () => {
    await driveEverySite(server, { bearerToken: TOKEN });
    expect(authorizationBySite(server.requests)).toEqual(
      everySite((site) => (ADAPTER_SITES.includes(site) ? `Bearer ${TOKEN}` : undefined)),
    );
  });

  it("a node that requires a credential refuses a client without one on every route", async () => {
    const refuse: Parameters<MockServer["route"]>[1] = (req, _body, res) => {
      expect(req.headers.authorization).toBeUndefined();
      res.writeHead(401, { connection: "close" });
      res.end();
      return true;
    };
    server.routeSession(refuse);
    server.route(() => true, refuse);

    const commitments = [{ blindedCommitment: BC, type: "Shield" as const }];
    const sdk = privateSdk(server, {});
    const calls: [string, () => Promise<unknown>][] = [
      ["index sync", () => sdk.syncPoiListIndex(LIST_KEY)],
      ["status", () => sdk.getPOIsPerList([LIST_KEY], commitments)],
      // The held index carries the refused sync, so the proof goes on to the session route.
      ["proof session", () => sdk.getPOIMerkleProofs(LIST_KEY, [BC])],
      [
        "registry refresh",
        () => new ChainRegistry([{ chainId: 1, endpoint: server.url }]).refresh(1),
      ],
    ];
    for (const [name, call] of calls) {
      const refused = await call().then(
        () => undefined,
        (e: unknown) => e,
      );
      expect(RavenError.is(refused, "ServerError"), name).toBe(true);
      expect((refused as RavenError).context.status, name).toBe(401);
    }
  });

  const SECRET = "edge-padded-value-0123456789";
  const UNSENDABLE: [string, string][] = [
    ["empty", ""],
    ["whitespace only", "   "],
    ["leading space", ` ${SECRET}`],
    ["trailing space", `${SECRET} `],
    ["header injection", `${SECRET}\r\nx-injected: 1`],
    ["NUL", `${SECRET}\u0000`],
    ["non-ASCII", `${SECRET}\u00e9`],
    ["null", null as unknown as string],
    ["number", 42 as unknown as string],
  ];

  it.each(UNSENDABLE)("refuses a token that cannot reach the wire as given: %s", (_name, token) => {
    const builders = [
      () => new RavenPOINodeInterface({ endpoint: server.url, bearerToken: token }),
      () => new ChainRegistry([{ chainId: 1, endpoint: server.url, bearerToken: token }]),
      () => new ChainRegistry().upsert({ chainId: 1, endpoint: server.url, bearerToken: token }),
    ];
    for (const build of builders) {
      let thrown: unknown;
      try {
        build();
      } catch (e) {
        thrown = e;
      }
      expect(RavenError.is(thrown, "InvalidQuery")).toBe(true);
      const refusal = thrown as RavenError;
      const told = `${refusal.message} ${JSON.stringify(refusal.context)}`;
      expect(told).toContain("bearerToken");
      expect(told).not.toContain(SECRET);
    }
  });
});

const SRC_DIR = fileURLToPath(new URL("../src/", import.meta.url));
const HEADER_MODULE = "bearer-auth.ts";
// The header name in any case, or the scheme exactly as the server's prefix match needs it.
const HEADER_SPELLINGS = [/authorization/i, /Bearer[ `"'$]/];

function spellsHeader(text: string): boolean {
  return HEADER_SPELLINGS.some((spelling) => spelling.test(text));
}

function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory()
      ? sourceFiles(join(dir, entry.name))
      : entry.name.endsWith(".ts")
        ? [join(dir, entry.name)]
        : [],
  );
}

/** `file:line` of every header spelling outside the one module allowed to build it. */
function headerSpellingsOutsideModule(sources: ReadonlyMap<string, string>): string[] {
  const found: string[] = [];
  for (const [file, text] of sources) {
    if (file === HEADER_MODULE) continue;
    text.split("\n").forEach((line, at) => {
      if (spellsHeader(line)) found.push(`${file}:${at + 1}`);
    });
  }
  return found;
}

describe("only one module can build the adapter authorization header", () => {
  const sources = new Map(
    sourceFiles(SRC_DIR).map((file) => [relative(SRC_DIR, file), readFileSync(file, "utf-8")]),
  );

  it("scans the real source tree, including the module it exempts", () => {
    expect(sources.size).toBeGreaterThanOrEqual(10);
    expect(spellsHeader(sources.get(HEADER_MODULE) ?? "")).toBe(true);
  });

  it("flags a call site that spells the header itself", () => {
    const bypasses = [
      "headers: { authorization: `Bearer ${route.bearerToken}` },",
      'headers.set("Authorization", "Bearer " + entry.bearerToken);',
      "const scheme = `Bearer ${token}`;",
    ];
    for (const line of bypasses) {
      expect(headerSpellingsOutsideModule(new Map([["seventh-site.ts", line]]))).toEqual([
        "seventh-site.ts:1",
      ]);
    }
    expect(
      headerSpellingsOutsideModule(new Map([["seventh-site.ts", "const t = entry.bearerToken;"]])),
    ).toEqual([]);
  });

  it("no source file outside that module spells the header", () => {
    expect(headerSpellingsOutsideModule(sources)).toEqual([]);
  });
});
