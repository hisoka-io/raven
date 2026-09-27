/** Configuration for a list served as a forest: one path instance per PPOI block, one context
 *  per list, and an index holding the test's commitments where the test put them. */

import {
  LEAVES_PER_PPOI_BLOCK,
  type ClientPirContext,
  type RavenConfig,
} from "../../src/index";
import { indexHolding } from "./prefix_channel";

export const FOREST_BLOCKS = 7;

/** The instance id a test's forest names block `block` of `listKeyHex` by. */
export function blockLabel(listKeyHex: string, block: number): string {
  return `t2Path-${listKeyHex}-${block}`;
}

export interface ForestOptions {
  readonly endpoint: string;
  readonly listKeyHex: string;
  readonly ctx: ClientPirContext;
  /** Commitments and the global list index each sits at. */
  readonly placed?: readonly (readonly [string, number])[];
  /** Rows the preloaded index holds; the highest placed index plus one when omitted. */
  readonly total?: number;
  readonly chainId?: number;
  /** Block roots keyed `<block>`, pinned under this chain. */
  readonly pins?: ReadonlyMap<number, string>;
}

export function forestConfig(options: ForestOptions): RavenConfig {
  const chainId = options.chainId ?? 1;
  const lk = options.listKeyHex;
  const placed = options.placed ?? [];
  const blocks = Math.max(
    FOREST_BLOCKS,
    ...placed.map(([, idx]) => Math.floor(idx / LEAVES_PER_PPOI_BLOCK) + 1),
  );
  return {
    endpoint: options.endpoint,
    chainId,
    clientPirContexts: new Map([[`t2Path:${chainId}:${lk}`, options.ctx]]),
    clientPirInstanceLabels: new Map(
      Array.from({ length: blocks }, (_unused, block) => [
        `t2Path:${chainId}:${lk}:${block}`,
        blockLabel(lk, block),
      ]),
    ),
    ppoiPinnedRoots: new Map(
      [...(options.pins ?? new Map<number, string>())].map(([block, root]) => [
        `${chainId}:${lk}:${block}`,
        root,
      ]),
    ),
    ...(placed.length === 0 && options.total === undefined
      ? {}
      : {
          poiListIndexes: new Map([[`${chainId}:${lk}`, indexHolding(placed, options.total)]]),
        }),
    poiListIndexStore: false,
  };
}
