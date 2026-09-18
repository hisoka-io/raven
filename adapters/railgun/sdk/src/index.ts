// Railgun POI facade and domain-shaped wire helpers.
export {
  RavenPOINodeInterface,
  type RavenConfig,
  type PrivateStalePolicy,
  type POIStatus,
  type BlindedCommitmentType,
  type BlindedCommitmentData,
  type StatusHeader,
  type MerkleProof,
  type CommitTreeAuthPath,
  type CommitTreeProof,
  type Chain,
  type Proof,
  type LegacyTransactProofData,
  type CapturedWireRequest,
  containsByteSequence,
  hexToBytes,
  bytesToHex,
  pathIndicesForLeaf,
  pathIndicesForPerListLeaf,
  TREE_DEPTH,
  PATH_RECORD_BYTES,
} from "./raven-poi-node-interface";

export { hashLeftRight, foldMerkleRoot } from "./poseidon";

// Generic PIR session bootstrap and query-bundle handling.
export type {
  ClientPirContext,
  RavenInspireWasm,
  RavenInspireClientSession,
  ClientPirQueryBundle,
  LoadClientPirContextInput,
  LoadClientPirContextResult,
} from "./client-pir";

export {
  decodeClientPirQueryBundle,
  installPanicHook,
  loadClientPirContext,
} from "./client-pir";

// Railgun POI decoding and Merkle addressing.
export type { BcToIdxMap, RavenPOIPathWasm } from "./poi-pir";

export {
  statusByteToPOIStatus,
  validateBcHex,
  validateLeafIndex,
  validateListKeyHex,
  validateTreeNumber,
} from "./poi-pir";

// Generic client-side session persistence.
export {
  idbGet,
  idbPut,
  idbClear,
  sha256Hex,
} from "./session-cache";

// Railgun deployment routing, freshness caching, and event/status surfaces.
export { ChainRegistry, type ChainRegistryEntry } from "./chain-registry";

export {
  ImtCache,
  imtCacheKey,
  imtCacheScopeKey,
  type ImtCacheConfig,
} from "./imt-cache";

export {
  RavenError,
  type RavenErrorKind,
  type RavenErrorContext,
  type RavenErrorByKind,
  type StaleDataContext,
  type StaleDataError,
} from "./errors";

export {
  subscribeRavenEvents,
  type RavenEventsConfig,
  type RavenEventsHandle,
  type StatusBody as RavenStatusBody,
  type InstanceStatus as RavenInstanceStatus,
  type ConsumerStatus as RavenConsumerStatus,
} from "./events-stream";

export {
  BATCH_SIZE_LADDER,
  MAX_BATCH_SIZE,
  isOnLadder,
  paddedBatchLength,
} from "./batch-ladder";
