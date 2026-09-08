//! `ENTRIES_PER_SHARD` is a compile-time constant while `ring_dim` arrives at
//! runtime, and `fold.rs` declares `shard_size_bytes = ring_dim * entry_size`
//! against buffers sized `ENTRIES_PER_SHARD * entry_size`. At `ring_dim != 2048`
//! the declared and actual geometry disagree with no error, and reads return
//! wrong bytes as `Ok` — the adapter guards this same rule at
//! `validate_rows_per_shard`; the demo must refuse too, not compute.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use eth_state::fold::MainSidecar;
use eth_state::{EthStateError, ENTRIES_PER_SHARD, ENTRY_SIZE};
use raven_inspire::params::InspireParams;

/// A shipped preset whose `ring_dim` disagrees with the leaf-assignment
/// constant must be refused at build time with both quantities named.
#[test]
fn seeding_at_a_ring_dim_that_disagrees_with_entries_per_shard_is_refused() {
    let params = InspireParams::secure_128_d4096();
    assert_ne!(
        params.ring_dim, ENTRIES_PER_SHARD,
        "precondition: the probe preset must disagree with the shard constant"
    );

    let database = vec![0u8; 8 * ENTRY_SIZE];
    let dir = tempfile::tempdir().expect("tempdir");
    let err = MainSidecar::seed(&params, &database, ENTRY_SIZE, dir.path(), 7)
        .err()
        .expect("ring_dim 4096 against ENTRIES_PER_SHARD 2048 must refuse, not build");

    let EthStateError::Setup(msg) = &err else {
        panic!("expected a Setup refusal, got {err:?}");
    };
    for needle in ["4096", "2048", "ring_dim", "ENTRIES_PER_SHARD"] {
        assert!(
            msg.contains(needle),
            "the refusal must name {needle} (supplied, required, and both sources): {msg}"
        );
    }
}
