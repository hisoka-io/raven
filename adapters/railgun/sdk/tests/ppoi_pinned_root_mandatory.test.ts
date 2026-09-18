// The pinned root is the ONLY thing standing between a PIR-served path-10 row and a
// forged merkle proof: the siblings arrive from the server, the fold is local, and a
// wrong sibling set folds to a wrong root that still looks like a proof. Before this
// file the guard was keyed on the chain-less label `t2Path:<lk>:<block>` while
// `instanceLabel()` resolves the chain-aware `t2Path:<chainId>:<lk>:<block>` FIRST --
// so in the primary configuration the guard never fired and an unverified proof was
// returned `Ok`. That is this codebase's signature defect (AGENTS.md:39) and its
// eighth recorded recurrence of "guard keyed on one thing, routing on another".

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  RavenError,
  RavenPOINodeInterface,
  type ClientPirContext,
  type RavenErrorKind,
} from "../src/index";
import { encodeBatchResponseNodes, stubCtx as nodeStubCtx } from "./helpers/auth_path_stub";
import { startMockServer, type MockServer } from "./helpers/mock_server";
import { foldMerkleRoot } from "../src/poseidon";

const TOKEN = "test-token-padded-long-enough-1234";
const MAINNET = 1;
const POLYGON = 137;
const LIST_KEY_HEX = "abababababababababababababababababababababababababababababababab";
const BC_HEX = "9f3c17aa04e1b28d6605c9713fe82b40d1a7c35e96280bf4517ade0c2b6d8391";
const GLOBAL_INDEX = 65_536 + 7; // block 1, local leaf 7 -- exercises the non-zero block.
const BLOCK = Math.floor(GLOBAL_INDEX / 65_536);
const LOCAL_INDEX = GLOBAL_INDEX % 65_536;
const ROW_BYTES = 512;
const ADDENDUM_BYTES = 160;

/** Sixteen deterministic siblings, distinct per level so a dropped level changes the root. */
function siblings(marker: number): Uint8Array[] {
  return Array.from({ length: 16 }, (_unused, level) => {
    const node = new Uint8Array(32);
    node[0] = marker;
    node[31] = level + 1;
    return node;
  });
}

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

/**
 * One served slot exactly as the Rust encoder lays it out: a 512 B path-10 row
 * (`RVP2` magic, levels 0..10) with the 160 B levels-11..15 addendum appended, which
 * `runClientPirQueryBatch` splits off the tail.
 */
function servedSlot(nodes: Uint8Array[]): Uint8Array {
  const row = new Uint8Array(ROW_BYTES);
  row.set(Buffer.from(BC_HEX, "hex"), 0);
  row[32] = 0; // status
  row[33] = 0; // event type
  row.set(new TextEncoder().encode("RVP2"), 34);
  for (let level = 0; level < 11; level += 1) {
    row.set(nodes[level], 38 + level * 32);
  }
  const addendum = new Uint8Array(ADDENDUM_BYTES);
  for (let level = 0; level < 5; level += 1) {
    addendum.set(nodes[11 + level], level * 32);
  }
  const slot = new Uint8Array(ROW_BYTES + ADDENDUM_BYTES);
  slot.set(row, 0);
  slot.set(addendum, ROW_BYTES);
  return slot;
}

function mountRowRoute(server: MockServer, nodes: Uint8Array[]): void {
  server.route(
    (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
    (_req, _body, res) => {
      res.writeHead(200, {
        "content-type": "application/octet-stream",
        "x-raven-epoch": "1",
        "x-raven-schema-version": "7",
        "x-raven-freshness": "lag_blocks=0 applied_height=0 epoch=1 confidence=1",
      });
      res.end(Buffer.from(encodeBatchResponseNodes([servedSlot(nodes)])));
      return true;
    },
  );
}

function pathCtx(): ClientPirContext {
  return { ...nodeStubCtx(), entrySize: ROW_BYTES };
}

interface Options {
  readonly chainId?: number;
  readonly labels?: [string, string][];
  readonly pinnedRoots?: [string, string][];
}

function makeSdk(server: MockServer, options: Options): RavenPOINodeInterface {
  return new RavenPOINodeInterface({
    endpoint: server.url,
    bearerToken: TOKEN,
    useClientPir: true,
    chainId: options.chainId ?? MAINNET,
    clientPirContexts: new Map([[`t2Path:${LIST_KEY_HEX}`, pathCtx()]]),
    clientPirInstanceLabels: new Map(options.labels ?? []),
    ppoiPinnedRoots: new Map(options.pinnedRoots ?? []),
    bcToIdxMaps: new Map([[LIST_KEY_HEX, new Map([[BC_HEX, GLOBAL_INDEX]])]]),
  });
}

async function expectRejectsWith(
  promise: Promise<unknown>,
  kind: RavenErrorKind,
): Promise<void> {
  let thrown: unknown;
  let resolved = false;
  try {
    await promise;
    resolved = true;
  } catch (e) {
    thrown = e;
  }
  expect(resolved, `expected a ${kind} refusal, but the call returned a proof`).toBe(false);
  expect(RavenError.is(thrown, kind), `expected ${kind}, got ${String(thrown)}`).toBe(true);
}

describe("the PPOI path-10 pinned root is mandatory and chain-scoped", () => {
  let server: MockServer;
  const nodes = siblings(0xab);
  const trueRoot = foldMerkleRoot(BC_HEX, nodes.map(toHex), BigInt(LOCAL_INDEX));

  beforeAll(async () => {
    server = await startMockServer();
  });
  afterAll(async () => {
    await server.close();
  });
  afterEach(() => {
    server.reset();
  });

  // THE DEFECT. The chain-aware label is what `instanceLabel()` routes on, so the
  // chain-less `has()` gate was false and the missing pin was never noticed.
  it("refuses when the routing label is chain-aware and no root is pinned", async () => {
    mountRowRoute(server, nodes);
    const sdk = makeSdk(server, {
      labels: [[`t2Path:${MAINNET}:${LIST_KEY_HEX}:${BLOCK}`, "ppoi-paths-ofac-1"]],
      pinnedRoots: [],
    });
    await expectRejectsWith(sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]), "InvalidQuery");
  });

  it("refuses when the routing label is chain-less and no root is pinned", async () => {
    mountRowRoute(server, nodes);
    const sdk = makeSdk(server, {
      labels: [[`t2Path:${LIST_KEY_HEX}:${BLOCK}`, "ppoi-paths-ofac-1"]],
      pinnedRoots: [],
    });
    await expectRejectsWith(sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]), "InvalidQuery");
  });

  // No label registered at all still folds a server-supplied path: the absence of a
  // label is not evidence that the root is trustworthy.
  it("refuses when no label is registered and no root is pinned", async () => {
    mountRowRoute(server, nodes);
    const sdk = makeSdk(server, { labels: [], pinnedRoots: [] });
    await expectRejectsWith(sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]), "InvalidQuery");
  });

  it("accepts a root pinned under the chain-aware key", async () => {
    mountRowRoute(server, nodes);
    const sdk = makeSdk(server, {
      labels: [[`t2Path:${MAINNET}:${LIST_KEY_HEX}:${BLOCK}`, "ppoi-paths-ofac-1"]],
      pinnedRoots: [[`${MAINNET}:${LIST_KEY_HEX}:${BLOCK}`, trueRoot]],
    });
    const [proof] = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);
    expect(proof.root).toBe(trueRoot);
  });

  it("accepts a root pinned under the legacy chain-less key", async () => {
    mountRowRoute(server, nodes);
    const sdk = makeSdk(server, {
      labels: [[`t2Path:${MAINNET}:${LIST_KEY_HEX}:${BLOCK}`, "ppoi-paths-ofac-1"]],
      pinnedRoots: [[`${LIST_KEY_HEX}:${BLOCK}`, trueRoot]],
    });
    const [proof] = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]);
    expect(proof.root).toBe(trueRoot);
  });

  // Forged siblings: the server swaps one level and the fold lands somewhere else.
  it("refuses a forged sibling set against the pinned root", async () => {
    mountRowRoute(server, siblings(0xcd));
    const sdk = makeSdk(server, {
      labels: [[`t2Path:${MAINNET}:${LIST_KEY_HEX}:${BLOCK}`, "ppoi-paths-ofac-1"]],
      pinnedRoots: [[`${MAINNET}:${LIST_KEY_HEX}:${BLOCK}`, trueRoot]],
    });
    await expectRejectsWith(sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]), "DecodeError");
  });

  // The chain-aware pin must not be readable from another chain: the same list key and
  // block exist on both chains with different roots.
  it("does not let one chain's pinned root satisfy another chain's fold", async () => {
    mountRowRoute(server, nodes);
    const sdk = makeSdk(server, {
      chainId: POLYGON,
      labels: [[`t2Path:${POLYGON}:${LIST_KEY_HEX}:${BLOCK}`, "ppoi-paths-ofac-1"]],
      pinnedRoots: [[`${MAINNET}:${LIST_KEY_HEX}:${BLOCK}`, trueRoot]],
    });
    await expectRejectsWith(sdk.getPOIMerkleProofs(LIST_KEY_HEX, [BC_HEX]), "InvalidQuery");
  });
});
