<p align="center">
  <img alt="Raven: a PIR framework for blockchain state" src="https://github.com/user-attachments/assets/c5cdc7c6-4d67-4ad3-a1a4-ba0009ca2d03" width="820" />
</p>

## Why

Hiding your IP (Tor, mixnets) doesn't hide _what_ you asked for. A shielded wallet still hands the RPC server a leaf index or commitment hash on every read, and that pointer is enough to reconstruct who you are.

Raven closes that gap on the query layer. The wallet sends an encrypted query, the server runs computation over the database without ever decrypting which row is the target, and the wallet recovers the record locally. Same proofs, same chain, blind reads.

Scope of the blindness is bounded and documented: PIR hides which row inside a shard, but the shard identifier travels in the clear today. Read [SECURITY.md](./SECURITY.md) for the open items before serving real value.

## How it works

- **Encoders** turn a logical store (Merkle tree, key-value map) into a flat array of fixed-width rows that the PIR server can answer queries over. The same engine handles per-leaf, per-path, per-node, or per-key layouts depending on what the workload needs.
- **Sharding** maps every entry to one shard at one offset. Updates re-encode only the affected shards, not the whole database.
- **Blue-green rebuilds** keep a second engine warm. It absorbs new chain events in the background and atomically swaps in when ready, so live queries never block on indexing.

## PIR schemes

| Scheme                                              | Status      |
| --------------------------------------------------- | ----------- |
| [InsPIRe](https://eprint.iacr.org/2025/1352)        | Integrated. |

## Adapters

Currently one: **Railgun**.

- Uses InsPIRe for both static and dynamic state.
- Serves PPOI list paths mirrored from the upstream PPOI node, in 65,536-row blocks, and commit-tree paths indexed from the chain.
- A `POINodeInterface` for the Railgun engine ([SDK](./adapters/railgun/sdk/README.md)): it answers PPOI status on the device from a list index it syncs from the Raven server, and fetches PPOI paths from that server by PIR. Proof submission and merkleroot validation still go to the upstream PPOI node in plaintext, and so does the root-pin fetch that checks each path (to `pinUpstream`, the upstream node by default): it names the note's 65,536-row block unless `ppoiPinnedRoots` is preloaded.

Live demo: <https://demo.railgun.hisoka.io/>

## Build

`crates/inspire`, `adapters/howl` and `adapters/eth-state` are git submodules. The root
workspace does not resolve without `crates/inspire`, and `adapters/eth-state` builds against
this checkout's crates by path:

```bash
git clone --recursive https://github.com/hisoka-io/raven.git
# already cloned without --recursive:
git submodule update --init --recursive
```

```bash
cargo test --workspace
cargo check -p raven-client --target wasm32-unknown-unknown
```

`--workspace` covers the root members only. Several trees are detached workspaces
(`crates/inspire`, `adapters/railgun`, `adapters/howl`, `adapters/eth-state`); build each with
its own `--manifest-path`. The wasm target applies to the client path (`raven-client`), not to
every crate: server-side crates pull in native-only dependencies.

## License

[Apache-2.0](./LICENSE) © Hisoka.io

