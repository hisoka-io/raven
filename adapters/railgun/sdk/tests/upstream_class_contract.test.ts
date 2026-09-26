import type { POI, POINodeInterface, TXOPOIListStatus } from "@railgun-community/engine";
import { describe, expect, expectTypeOf, it } from "vitest";

import { ChainRegistry, RavenPOINodeInterface } from "../src/index";

// Engine consumers compile with skipLibCheck, where a declaration that fails to resolve becomes an
// error type: it behaves as `any` and silences every check built on it, `expectTypeOf` included.
// An unused `@ts-expect-error` is still reported, so each canary below is a directive that only an
// intact declaration satisfies.
type Leaves<T, Depth extends unknown[] = []> = Depth["length"] extends 3
  ? T
  : T extends readonly (infer E)[]
    ? T | Leaves<E, [...Depth, 0]>
    : T extends object
      ? T | Leaves<T[keyof T], [...Depth, 0]>
      : T;
type ContractTypes = {
  [K in keyof POINodeInterface]: POINodeInterface[K] extends (...args: infer A) => infer R
    ? Leaves<A[number] | Awaited<R>>
    : never;
}[keyof POINodeInterface];

class Foreign {
  readonly foreignBrand = Symbol("foreign");
}

type EngineStatusMap = Awaited<ReturnType<POINodeInterface["getPOIsPerList"]>>;

// The shape Raven answered with before it adopted engine's type: the same strings, rejected
// because engine's status is a nominal enum.
class LiteralStatusNode {
  isActive(): boolean {
    return true;
  }
  async isRequired(): Promise<boolean> {
    return true;
  }
  async getPOIsPerList(): Promise<{ [bc: string]: { [listKey: string]: "Valid" } }> {
    return {};
  }
  async getPOIMerkleProofs(): Promise<never[]> {
    return [];
  }
  async validatePOIMerkleroots(): Promise<boolean> {
    return true;
  }
  async submitPOI(): Promise<void> {}
  async submitLegacyTransactProofs(): Promise<void> {}
}

describe("upstream POINodeInterface class contract", () => {
  it("is assignable to engine's POINodeInterface and to the POI.init seam", async () => {
    const raven = new RavenPOINodeInterface({
      endpoint: "https://raven.invalid",
      bearerToken: "contract-test-token-long-enough",
      useClientPir: false,
    });
    const x: POINodeInterface = raven;
    const injected: Parameters<typeof POI.init>[1] = raven;
    expect(x).toBe(raven);
    expect(injected).toBe(raven);
    expect(raven.isActive({ type: 0, id: 1 })).toBe(true);
    expect(raven.isActive({ type: 1, id: 1 })).toBe(false);
    await expect(raven.isRequired({ type: 0, id: 1 })).resolves.toBe(true);
    await expect(raven.isRequired({ type: 0, id: 2 })).resolves.toBe(false);
    expectTypeOf(raven).toMatchTypeOf<POINodeInterface>();
  });

  it("checks against engine's declaration, not an `any` it degraded to", () => {
    expectTypeOf<EngineStatusMap[string][string]>().toEqualTypeOf<TXOPOIListStatus>();
    // @ts-expect-error only an `any` somewhere in engine's contract admits a foreign instance
    const degraded: ContractTypes = new Foreign();
    // @ts-expect-error a literal-string status map is not engine's nominal enum
    const rejected: POINodeInterface = new LiteralStatusNode();
    expect(degraded).toBeInstanceOf(Foreign);
    expect(rejected).toBeInstanceOf(LiteralStatusNode);
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

  it("rejects a registered chain that differs from the configured chain", async () => {
    const registry = new ChainRegistry([
      {
        chainId: 1,
        endpoint: "https://mainnet.raven.invalid",
        bearerToken: "mainnet-contract-test-token",
      },
      {
        chainId: 137,
        endpoint: "https://polygon.raven.invalid",
        bearerToken: "polygon-contract-test-token",
      },
    ]);
    const raven = new RavenPOINodeInterface({
      endpoint: "https://ignored.invalid",
      bearerToken: "contract-test-token-long-enough",
      chainId: 1,
      chainRegistry: registry,
      useClientPir: false,
    });

    expect(raven.isActive({ type: 0, id: 137 })).toBe(false);
    await expect(
      raven.getPOIMerkleProofs(
        "V2_PoseidonMerkle",
        { type: 0, id: 137 },
        "00".repeat(32),
        [],
      ),
    ).rejects.toThrow(/not active/);
  });
});
