# Changelog

## 0.1.0-alpha.1

Pairs with `@hisoka-io/raven-inspire-client-wasm` and `@hisoka-io/raven-inspire-client-wasm-bundler`
`0.1.0-alpha.1`.

### Added
- Compact session seats. A node can serve the `d2048_approximate_gadget` parameter set, whose packing key is two
  polynomials instead of three: 30,843 B uploaded once per session and a 32 KiB seat on the node. An instance on that
  set speaks wire schema 9; the SDK reads the schema from the instance's params, frames its session and batch bodies
  with it, and checks every reply against it. Instances on the exact set keep schema 8 and their bytes.
- `getPOIMerkleProofs` sends its first batch while it reads the index tail, once an index this node confirmed places
  every requested commitment. The replies are read after the tail lands and are asked again from the synced index
  when the tail shows the list was replaced. A proof call over a high-latency transport takes one round trip less.
- `indexCounters()` reports `speculativeRounds` and `speculativeRoundsDiscarded`.

### Changed
- `decodeInstanceParams` and `fetchInstanceParams` accept wire schema 8 and 9, and refuse any other as
  `StaleAdapter` naming the served version. The params body's inner version must repeat its envelope.
- A node's refusal of the session or batch schema is classified as `StaleAdapter` with both versions.
- The wasm client draws each session's secret inside `build_client_session` and builds that session's one packing
  key there; the params bundle carries public parameters only.
- The wasm client's parameter floor accepts the approximate packing gadget on the shape its noise was measured on
  (ring 2048, base 2^20, three packing digits) and keeps every other floor.
- Node session handles are random 64-bit values. They still arrive as a decimal `x-raven-session` header and are
  read as a `bigint`.
- Dev tree: vitest 4, patched transitive dependencies.

### Compatibility
- Works with nodes serving the exact parameter set (schema 8), as `0.1.0-alpha.0` did, and with nodes serving the
  approximate-gadget set (schema 9).
