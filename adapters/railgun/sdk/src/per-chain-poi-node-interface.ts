/**
 * Engine installs one POI node interface for every chain (`POI.init(lists, nodeInterface)`), while
 * a Raven interface answers for one chain. This routes each call by the chain it names: to the
 * Raven interface serving that chain, and otherwise to the stock interface, unchanged. So a chain
 * Raven does not serve keeps every stock answer, `isRequired` and its failures included, and a
 * chain Raven serves always reads as requiring POI.
 */

import type {
  Chain as EngineChain,
  POI,
  POIList,
  POINodeInterface,
} from "@railgun-community/engine";

import { RavenError } from "./errors";
import type { RavenPOINodeInterface } from "./raven-poi-node-interface";

type Call<K extends keyof POINodeInterface> = POINodeInterface[K];

function chainKey(chain: { readonly type: number; readonly id: number }): string {
  return `${chain.type}:${chain.id}`;
}

const INTERFACE_METHODS = [
  "isActive",
  "isRequired",
  "getPOIsPerList",
  "getPOIMerkleProofs",
  "validatePOIMerkleroots",
  "submitPOI",
  "submitLegacyTransactProofs",
] as const;

function isNodeInterface(value: unknown): value is POINodeInterface {
  if (typeof value !== "object" || value === null) return false;
  const methods = value as Partial<Record<(typeof INTERFACE_METHODS)[number], unknown>>;
  return INTERFACE_METHODS.every((name) => typeof methods[name] === "function");
}

export class PerChainPOINodeInterface {
  private readonly served = new Map<string, POINodeInterface>();

  /** `stock` answers every chain no entry of `raven` serves; two entries for one chain are
   *  refused, since either choice would silently drop the other. */
  constructor(
    private readonly stock: POINodeInterface,
    raven: readonly RavenPOINodeInterface[],
  ) {
    for (const node of raven) {
      const key = chainKey(node.servedChain());
      if (this.served.has(key)) {
        throw RavenError.invalidQuery(
          `PerChainPOINodeInterface: two Raven interfaces serve chain ${key}; pass one per chain`,
        );
      }
      this.served.set(key, node);
    }
  }

  /**
   * Installs Raven in front of the interface engine holds now, which `startRailgunEngine` sets to
   * the stock one; `@railgun-community/wallet` does not export that class, so this is how a wallet
   * reaches it. Engine keeps it in a private static, which is read here and refused when absent or
   * already this router, so an engine that renamed it fails at install rather than at a call.
   */
  static install(
    poi: typeof POI,
    lists: POIList[],
    raven: readonly RavenPOINodeInterface[],
  ): PerChainPOINodeInterface {
    const installed = (poi as unknown as { readonly nodeInterface?: unknown }).nodeInterface;
    if (installed instanceof PerChainPOINodeInterface) {
      throw RavenError.invalidQuery(
        "PerChainPOINodeInterface.install: engine already holds a per-chain router",
      );
    }
    if (!isNodeInterface(installed)) {
      throw RavenError.invalidQuery(
        "PerChainPOINodeInterface.install: engine holds no POI node interface to route other " +
          "chains to; start the engine with poiNodeURLs first, or construct the router with the " +
          "stock interface",
      );
    }
    const router = new PerChainPOINodeInterface(installed, raven);
    poi.init(lists, router);
    return router;
  }

  private route(chain: EngineChain): POINodeInterface {
    return this.served.get(chainKey(chain)) ?? this.stock;
  }

  isActive(chain: EngineChain): boolean {
    return this.route(chain).isActive(chain);
  }

  isRequired(chain: EngineChain): Promise<boolean> {
    return this.route(chain).isRequired(chain);
  }

  getPOIsPerList(...args: Parameters<Call<"getPOIsPerList">>): ReturnType<Call<"getPOIsPerList">> {
    return this.route(args[1]).getPOIsPerList(...args);
  }

  getPOIMerkleProofs(
    ...args: Parameters<Call<"getPOIMerkleProofs">>
  ): ReturnType<Call<"getPOIMerkleProofs">> {
    return this.route(args[1]).getPOIMerkleProofs(...args);
  }

  validatePOIMerkleroots(
    ...args: Parameters<Call<"validatePOIMerkleroots">>
  ): ReturnType<Call<"validatePOIMerkleroots">> {
    return this.route(args[1]).validatePOIMerkleroots(...args);
  }

  submitPOI(...args: Parameters<Call<"submitPOI">>): ReturnType<Call<"submitPOI">> {
    return this.route(args[1]).submitPOI(...args);
  }

  submitLegacyTransactProofs(
    ...args: Parameters<Call<"submitLegacyTransactProofs">>
  ): ReturnType<Call<"submitLegacyTransactProofs">> {
    return this.route(args[1]).submitLegacyTransactProofs(...args);
  }
}
