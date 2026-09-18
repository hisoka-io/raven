import { describe, expect, expectTypeOf, it } from "vitest";

import {
  type BlindedCommitmentData,
  type Chain,
  type LegacyTransactProofData,
  type MerkleProof,
  type Proof,
  RavenPOINodeInterface,
} from "../src/index";

abstract class FrozenUpstreamPOINodeInterface {
  abstract isActive(chain: Chain): boolean;
  abstract isRequired(chain: Chain): Promise<boolean>;
  abstract getPOIsPerList(
    txidVersion: string,
    chain: Chain,
    listKeys: string[],
    commitments: BlindedCommitmentData[],
  ): Promise<unknown>;
  abstract getPOIMerkleProofs(
    txidVersion: string,
    chain: Chain,
    listKey: string,
    commitments: string[],
  ): Promise<MerkleProof[]>;
  abstract validatePOIMerkleroots(
    txidVersion: string,
    chain: Chain,
    listKey: string,
    roots: string[],
  ): Promise<boolean>;
  abstract submitPOI(
    txidVersion: string,
    chain: Chain,
    listKey: string,
    proof: Proof,
    roots: string[],
    txidRoot: string,
    txidRootIndex: number,
    commitmentsOut: string[],
    unshieldTxid: string,
  ): Promise<void>;
  abstract submitLegacyTransactProofs(
    txidVersion: string,
    chain: Chain,
    listKeys: string[],
    proofs: LegacyTransactProofData[],
  ): Promise<void>;
}

function walletPoiInit(node: FrozenUpstreamPOINodeInterface): FrozenUpstreamPOINodeInterface {
  return node;
}

describe("upstream POINodeInterface class contract", () => {
  it("is structurally accepted by WalletPOI.init's interface parameter", async () => {
    const raven = new RavenPOINodeInterface({
      endpoint: "https://raven.invalid",
      bearerToken: "contract-test-token-long-enough",
      useClientPir: false,
    });
    const accepted = walletPoiInit(raven);
    expect(accepted).toBe(raven);
    expect(raven.isActive({ type: 0, id: 1 })).toBe(true);
    expect(raven.isActive({ type: 1, id: 1 })).toBe(false);
    await expect(raven.isRequired({ type: 0, id: 1 })).resolves.toBe(true);
    await expect(raven.isRequired({ type: 0, id: 2 })).resolves.toBe(false);
    expectTypeOf(raven).toMatchTypeOf<FrozenUpstreamPOINodeInterface>();
  });

  it("fails closed when leading engine coordinates differ from configuration", async () => {
    const raven = new RavenPOINodeInterface({
      endpoint: "https://raven.invalid",
      bearerToken: "contract-test-token-long-enough",
      useClientPir: false,
    });
    await expect(
      raven.getPOIsPerList("V3_PoseidonMerkle", { type: 0, id: 1 }, [], []),
    ).rejects.toThrow(/txidVersion/);
    await expect(
      raven.getPOIMerkleProofs("V2_PoseidonMerkle", { type: 0, id: 2 }, "00".repeat(32), []),
    ).rejects.toThrow(/not active/);
  });
});
