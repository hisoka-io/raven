// Engine keeps ONE POI node interface for every chain, installed through `POI.init`. Raven serves
// one chain, so it is installed behind a router: its own chain reaches Raven, and every other
// chain reaches the stock interface exactly as if Raven were not there. Driven through engine's
// public `POI` class, which is what the wallet calls.

import {
  BlindedCommitmentType,
  POI,
  POIListType,
  type Chain,
  type POINodeInterface,
} from "@railgun-community/engine";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { PerChainPOINodeInterface, RavenError, RavenPOINodeInterface } from "../src/index";
import { blockLabel, forestConfig } from "./helpers/forest";
import {
  readJsonRpcRequest,
  startMockServer,
  writeJsonRpcResult,
  type MockServer,
} from "./helpers/mock_server";
import { commitmentAt, mountPrefixChannel, targetNamingCtx } from "./helpers/prefix_channel";

const TXID = "V2_PoseidonMerkle" as Parameters<POINodeInterface["getPOIsPerList"]>[0];
const LIST = "ab".repeat(32);
const MAINNET = { type: 0, id: 1 } as Chain;
const POLYGON = { type: 0, id: 137 } as Chain;
const BSC = { type: 0, id: 56 } as Chain;

type StockCall = { method: string; chain: number };

/** Stands in for the wallet's `WalletPOINodeInterface`: records what reaches it and answers
 *  `isRequired` from a per-network table, as `POIRequired.isRequiredForNetwork` does. */
class StockInterface {
  readonly calls: StockCall[] = [];
  constructor(private readonly required: ReadonlyMap<number, boolean>) {}

  private seen(method: string, chain: Chain): void {
    this.calls.push({ method, chain: chain.id });
  }
  isActive(chain: Chain): boolean {
    this.seen("isActive", chain);
    return true;
  }
  async isRequired(chain: Chain): Promise<boolean> {
    this.seen("isRequired", chain);
    const required = this.required.get(chain.id);
    if (required === undefined) throw new Error(`No network for chain ${chain.type}:${chain.id}`);
    return required;
  }
  async getPOIsPerList(...args: Parameters<POINodeInterface["getPOIsPerList"]>) {
    this.seen("getPOIsPerList", args[1]);
    return {};
  }
  async getPOIMerkleProofs(...args: Parameters<POINodeInterface["getPOIMerkleProofs"]>) {
    this.seen("getPOIMerkleProofs", args[1]);
    return [];
  }
  async validatePOIMerkleroots(...args: Parameters<POINodeInterface["validatePOIMerkleroots"]>) {
    this.seen("validatePOIMerkleroots", args[1]);
    return true;
  }
  async submitPOI(...args: Parameters<POINodeInterface["submitPOI"]>) {
    this.seen("submitPOI", args[1]);
  }
  async submitLegacyTransactProofs(
    ...args: Parameters<POINodeInterface["submitLegacyTransactProofs"]>
  ) {
    this.seen("submitLegacyTransactProofs", args[1]);
  }
}

describe("per-chain dispatch through engine's POI.init", () => {
  let node: MockServer;
  let stock: StockInterface;

  beforeAll(async () => {
    node = await startMockServer();
  });
  afterAll(async () => {
    await node.close();
  });
  afterEach(() => {
    node.reset();
  });

  function install(): void {
    stock = new StockInterface(new Map([[137, true], [56, false], [1, true]]));
    const raven = new RavenPOINodeInterface(
      forestConfig({ endpoint: node.url, listKeyHex: LIST, ctx: targetNamingCtx() }),
    );
    POI.init(
      [{ key: LIST, type: POIListType.Active, name: "test", description: "test" }],
      new PerChainPOINodeInterface(stock, [raven]),
    );
  }

  it("answers isRequired on a chain Raven does not serve exactly as the stock interface does", async () => {
    install();
    await expect(POI.isRequiredForChain(POLYGON)).resolves.toBe(true);
    await expect(POI.isRequiredForChain(BSC)).resolves.toBe(false);
    await expect(POI.isRequiredForChain({ type: 0, id: 10 } as Chain)).rejects.toThrow(
      /No network for chain 0:10/,
    );
    expect(POI.isActiveForChain(POLYGON)).toBe(true);
    expect(stock.calls.map(({ method, chain }) => `${method}:${chain}`)).toEqual([
      "isRequired:137",
      "isRequired:56",
      "isRequired:10",
      "isActive:137",
    ]);
  });

  it("sends status and proof calls on another chain to the stock interface, not the node", async () => {
    install();
    const bc = commitmentAt(1);
    await POI.retrievePOIsForBlindedCommitments(TXID, POLYGON, [
      { blindedCommitment: bc, type: BlindedCommitmentType.Shield },
    ]);
    await POI.getPOIMerkleProofs(TXID, POLYGON, LIST, [bc]);
    await POI.validatePOIMerkleroots(TXID, POLYGON, LIST, []);
    await POI.submitLegacyTransactProofs(TXID, POLYGON, [LIST], []);

    expect(stock.calls.map(({ method, chain }) => `${method}:${chain}`)).toEqual([
      "getPOIsPerList:137",
      "getPOIMerkleProofs:137",
      "validatePOIMerkleroots:137",
      "submitLegacyTransactProofs:137",
    ]);
    expect(node.requests).toHaveLength(0);
  });

  it("answers the chain Raven serves from Raven, never the stock interface", async () => {
    install();
    mountPrefixChannel(node, LIST, { commitments: [commitmentAt(1)] });
    const bc = commitmentAt(1);

    await expect(POI.isRequiredForChain(MAINNET)).resolves.toBe(true);
    expect(POI.isActiveForChain(MAINNET)).toBe(true);
    const status = await POI.retrievePOIsForBlindedCommitments(TXID, MAINNET, [
      { blindedCommitment: bc, type: BlindedCommitmentType.Shield },
    ]);
    expect(status).toStrictEqual({ [bc]: { [LIST]: "Valid" } });
    // The node mounts no batch route, so the proof fails; what matters is who was asked.
    await expect(POI.getPOIMerkleProofs(TXID, MAINNET, LIST, [bc])).rejects.toSatisfy(
      (error: unknown) => RavenError.is(error, "ServerError"),
    );

    expect(stock.calls).toEqual([]);
    const urls = node.requests.map((r) => r.url);
    expect(urls).toContain(`/v1/poi/${LIST}/bc-prefixes?since=0`);
    expect(urls).toContain(`/v1/instance/${blockLabel(LIST, 0)}/batch`);
  });

  // A submission reaching the stock interface instead would leave Raven's chain answering Missing
  // after every submission, and engine would generate and submit the same proof on every refresh.
  it("sends submissions on the chain Raven serves to Raven, and on another chain to the stock interface", async () => {
    const upstream = await startMockServer();
    try {
      const upstreamMethods: string[] = [];
      upstream.route(
        () => true,
        (_req, body, res) => {
          upstreamMethods.push(readJsonRpcRequest(body).method);
          writeJsonRpcResult(body, res, null);
          return true;
        },
      );
      stock = new StockInterface(new Map([[137, true], [1, true]]));
      const raven = new RavenPOINodeInterface({
        ...forestConfig({ endpoint: node.url, listKeyHex: LIST, ctx: targetNamingCtx() }),
        upstreamFallbackEndpoint: upstream.url,
      });
      POI.init(
        [{ key: LIST, type: POIListType.Active, name: "test", description: "test" }],
        new PerChainPOINodeInterface(stock, [raven]),
      );
      mountPrefixChannel(node, LIST, { commitments: [commitmentAt(0)] });
      const proof = { pi_a: ["1", "2"], pi_b: [["3", "4"], ["5", "6"]], pi_c: ["7", "8"] } as Parameters<
        typeof POI.submitPOI
      >[3];
      const output = commitmentAt(0x61);
      const legacy = commitmentAt(0x62);
      const legacyProof = (bc: string) => ({
        txidIndex: "1",
        npk: "2",
        value: "3",
        tokenHash: "4",
        blindedCommitment: bc,
      });

      await POI.submitPOI(TXID, MAINNET, LIST, proof, [], "00".repeat(32), 0, [output], "0x00");
      await POI.submitLegacyTransactProofs(TXID, MAINNET, [LIST], [legacyProof(legacy)]);
      expect(upstreamMethods).toEqual([
        "ppoi_submit_transact_proof",
        "ppoi_submit_legacy_transact_proofs",
      ]);
      const status = await POI.retrievePOIsForBlindedCommitments(TXID, MAINNET, [
        { blindedCommitment: output, type: BlindedCommitmentType.Transact },
        { blindedCommitment: legacy, type: BlindedCommitmentType.Transact },
      ]);
      expect(status).toStrictEqual({
        [output]: { [LIST]: "ProofSubmitted" },
        [legacy]: { [LIST]: "ProofSubmitted" },
      });

      await POI.submitPOI(TXID, POLYGON, LIST, proof, [], "00".repeat(32), 0, [output], "0x00");
      await POI.submitLegacyTransactProofs(TXID, POLYGON, [LIST], [legacyProof(legacy)]);
      expect(upstreamMethods).toHaveLength(2);
      expect(stock.calls.map(({ method, chain }) => `${method}:${chain}`)).toEqual([
        "submitPOI:137",
        "submitLegacyTransactProofs:137",
      ]);
    } finally {
      await upstream.close();
    }
  });

  it("installs around the interface engine already holds, as startRailgunEngine leaves it", async () => {
    stock = new StockInterface(new Map([[137, true], [56, false]]));
    const lists = [{ key: LIST, type: POIListType.Active, name: "test", description: "test" }];
    POI.init(lists, stock);
    const raven = new RavenPOINodeInterface(
      forestConfig({ endpoint: node.url, listKeyHex: LIST, ctx: targetNamingCtx() }),
    );

    PerChainPOINodeInterface.install(POI, lists, [raven]);

    await expect(POI.isRequiredForChain(POLYGON)).resolves.toBe(true);
    await expect(POI.isRequiredForChain(BSC)).resolves.toBe(false);
    await expect(POI.isRequiredForChain(MAINNET)).resolves.toBe(true);
    expect(stock.calls.map(({ method, chain }) => `${method}:${chain}`)).toEqual([
      "isRequired:137",
      "isRequired:56",
    ]);
    // A second install would route the router's own other chains back into itself.
    expect(() => PerChainPOINodeInterface.install(POI, lists, [raven])).toThrow(
      /already holds a per-chain router/,
    );
  });

  it("refuses to install when engine holds no interface to route other chains to", () => {
    const lists = [{ key: LIST, type: POIListType.Active, name: "test", description: "test" }];
    POI.init(lists, {} as unknown as POINodeInterface);
    const raven = new RavenPOINodeInterface({ endpoint: node.url });
    expect(() => PerChainPOINodeInterface.install(POI, lists, [raven])).toThrow(
      /engine holds no POI node interface/,
    );
  });

  it("refuses two Raven interfaces for one chain", () => {
    const raven = new RavenPOINodeInterface({ endpoint: node.url });
    expect(
      () => new PerChainPOINodeInterface(new StockInterface(new Map()), [raven, raven]),
    ).toThrow(/two Raven interfaces serve chain 0:1/);
  });
});
