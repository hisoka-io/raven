<p align="center">
  <img alt="Raven: a PIR framework for blockchain state" src="https://github.com/user-attachments/assets/c5cdc7c6-4d67-4ad3-a1a4-ba0009ca2d03" width="820" />
</p>

## Why

Hiding your IP (Tor, mixnets) doesn't hide _what_ you asked for. A shielded wallet still hands the RPC server a leaf index or commitment hash on every read, and that pointer is enough to reconstruct who you are.

Raven closes that gap on the query layer. The wallet sends an encrypted query, the server runs computation over the database without ever decrypting which row is the target, and the wallet recovers the record locally. Same proofs, same chain, blind reads.

## How it works

- **Encoders** turn a logical store (Merkle tree, key-value map) into a flat array of fixed-width rows that the PIR server can answer queries over. The same engine handles per-leaf, per-path, per-node, or per-key layouts depending on what the workload needs.
- **Sharding** maps every entry to one shard at one offset. Updates re-encode only the affected shards, not the whole database.
- **Blue-green rebuilds** keep a second engine warm. It absorbs new chain events in the background and atomically swaps in when ready, so live queries never block on indexing.

## PIR schemes

| Scheme                                              | Status      |
| --------------------------------------------------- | ----------- |
| [InsPIRe](https://eprint.iacr.org/2026/030)         | Integrated. |
| [iSimplePIR](https://eprint.iacr.org/2025/1352)     | WIP         |

## Adapters

Currently one: **Railgun**.

- Uses InsPIRe for both static and dynamic state.
- Blue-green rebuild pattern keeps PPOI status, PPOI paths, and commit-tree paths fresh against live chain head.
- Drop-in `POINodeInterface` for the Railgun wallet stack.

Live demo: <https://demo.railgun.hisoka.io/>

## Build

```bash
cargo test --workspace
cargo check --workspace --target wasm32-unknown-unknown
```

## License

[Apache-2.0](./LICENSE) © Hisoka.io

