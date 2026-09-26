/** Bincode `ShardConfig { shard_size_bytes, entry_size_bytes, total_entries }`, as an
 *  instance's params carry it. */

/** Rows a leaf-keyed instance holds: one depth-16 tree. */
export const TREE_ROWS = 65_536;

export function shardConfigBincode(
  totalEntries: number = TREE_ROWS,
  entryBytes = 32,
  entriesPerShard = 2_048,
): Uint8Array {
  const bytes = new Uint8Array(24);
  const view = new DataView(bytes.buffer);
  view.setBigUint64(0, BigInt(entriesPerShard * entryBytes), true);
  view.setBigUint64(8, BigInt(entryBytes), true);
  view.setBigUint64(16, BigInt(totalEntries), true);
  return bytes;
}
