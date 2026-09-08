//! DH-L3-9: two concurrent `commit_v6` calls on ONE handle can publish writer B's
//! bytes under the id `commit_v6` returned to writer A, with no error to either.
//!
//! The window is at `engine/src/persistence.rs::commit_serialized_bundle`: the
//! manifest lock is taken only to READ `current_snapshot_id.next()`, then DROPPED;
//! `snap.save` runs unlocked and `crates/storage/src/snapshot.rs::save` is
//! replace-in-place; the CAS is checked afterwards, on re-lock — AFTER the
//! destructive write. So both writers compute the same `next_id`, both write the
//! same directory, and only the LOSER of the manifest race is told anything. The
//! winner is handed `Ok(next_id)` for bytes that are not its own.
//!
//! LATENT, not live: `run_consumer_task` is the sole writer per instance today
//! (the non-test `commit_v6` callers are orchestrator.rs:601 and
//! persistence.rs:647/:1668/:1743, all inside one consumer task). This pins the
//! mechanism so a second writer cannot be added quietly.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::{Arc, Barrier};

use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{
    apply_wal_entry, restore_inspire_state_v6, InspireServerState, LogicalLeafStore,
};
use raven_railgun_engine::persistence::{InspirePersistence, SnapshotPolicy};
use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder};
use raven_railgun_persistence::{Snapshot, StoreLayout, WalEntryPayload, SNAPSHOT_MAGIC};
use raven_railgun_testkit::canonical;

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-concurrent-commit";
const TOY_ENTRY_SIZE: usize = 32;
const ENTRIES_PER_SHARD: u32 = 256;

const A_LEAVES: u32 = 3;
const B_LEAVES: u32 = 11;

/// The race is a race: a scheduling hiccup can serialize the two writers and that
/// round is simply inconclusive. Repeating makes a false GREEN negligible without
/// weakening the claim — after the fix, every round must be clean.
const ROUNDS: usize = 8;

fn build_toy_state() -> InspireServerState {
    raven_railgun_testkit::toy_state(TOY_ENTRY_SIZE)
}

fn encoder_arc() -> Arc<dyn PirTableEncoder> {
    EncoderKind::PerLeafBc { tree_number: 0 }
        .build(TOY_ENTRY_SIZE, ENTRIES_PER_SHARD)
        .expect("build encoder")
}

/// A store with `leaves` contiguous leaves — the distinguisher between the two
/// writers' bundles.
fn store_with(leaves: u32) -> LogicalLeafStore {
    let enc = encoder_arc();
    let mut store = LogicalLeafStore::default();
    for i in 0..leaves {
        let payload = WalEntryPayload::AppendLeaf {
            tree_number: 0,
            leaf_index: i,
            commitment: canonical(u8::try_from(i).unwrap_or(0).saturating_add(1)),
        };
        apply_wal_entry(&mut store, &payload, 100 + u64::from(i), enc.as_ref())
            .expect("apply to logical");
    }
    store
}

#[test]
#[ignore = "DH-L3-9, LATENT: commit_serialized_bundle drops the manifest lock across \
            the destructive snap.save and CAS-checks only afterwards \
            (engine/src/persistence.rs:459-490 + crates/storage/src/snapshot.rs:76-131), \
            so the winner is handed Ok(id) for the loser's bytes. RED until the fix — \
            hold the manifest lock across the save, or reserve an unclaimable id. \
            Trigger: un-ignore when commit_serialized_bundle stops releasing the lock \
            before snap.save, or when a second concurrent commit_v6 caller per instance \
            is introduced (today run_consumer_task is the only one)."]
fn two_concurrent_commits_on_one_handle_do_not_publish_each_others_bytes() {
    // One toy state, reused read-only across rounds; it is the expensive part.
    let state = Arc::new(build_toy_state());
    let store_a = Arc::new(store_with(A_LEAVES));
    let store_b = Arc::new(store_with(B_LEAVES));

    let mut violations: Vec<String> = Vec::new();

    for round in 0..ROUNDS {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("layout");
        let persistence = Arc::new(
            InspirePersistence::open(
                layout,
                SCHEME_TAG,
                InstanceId::new("concurrent-commit"),
                SnapshotPolicy::default(),
                encoder_arc(),
            )
            .expect("fresh open")
            .persistence,
        );

        let gate = Arc::new(Barrier::new(2));
        let mut handles = Vec::with_capacity(2);
        for (tag, leaves, store) in [
            ("A", A_LEAVES, Arc::clone(&store_a)),
            ("B", B_LEAVES, Arc::clone(&store_b)),
        ] {
            let persistence = Arc::clone(&persistence);
            let state = Arc::clone(&state);
            let gate = Arc::clone(&gate);
            handles.push(std::thread::spawn(move || {
                // Both writers read next_id before either finishes its save.
                gate.wait();
                (tag, leaves, persistence.commit_v6(&state, &store, 200))
            }));
        }
        let results: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().expect("writer thread joined"))
            .collect();

        let layout = StoreLayout::open(dir.path()).expect("layout reopen");
        for (tag, leaves, outcome) in results {
            let Ok(id) = outcome else {
                // A refusal is the CORRECT behaviour; this writer is not the defect.
                continue;
            };
            // Two failure shapes, both from the same unlocked window, and which one you
            // get depends on the interleaving: a TORN snapshot (both writers wrote
            // header.bin and data.bincode into the one shared `snap-NNN.tmp`, so the
            // header describes one writer's body and the data is the other's), or a
            // clean but WRONG snapshot (one writer's save completed entirely, then the
            // other's replaced it).
            match Snapshot::load(&layout, id, SNAPSHOT_MAGIC) {
                Err(e) => violations.push(format!(
                    "round {round}: writer {tag} was handed Ok({id:?}) for a snapshot that \
                     does not load: {e}. The two writers interleaved inside the shared \
                     snap-NNN.tmp directory."
                )),
                Ok(snap) => match restore_inspire_state_v6(&snap.data) {
                    Err(e) => violations.push(format!(
                        "round {round}: writer {tag} was handed Ok({id:?}) for bytes that do \
                         not decode: {e}"
                    )),
                    Ok((_state, store)) => {
                        let got = u32::try_from(store.leaf_count()).unwrap_or(u32::MAX);
                        if got != leaves {
                            violations.push(format!(
                                "round {round}: writer {tag} was handed Ok({id:?}) but that \
                                 snapshot holds {got} leaves, not its own {leaves} — commit_v6 \
                                 reported success for the OTHER writer's bytes."
                            ));
                        }
                    }
                },
            }
        }
    }

    assert!(
        violations.is_empty(),
        "commit_v6 must never report success for a snapshot that is not the caller's \
         own state ({} of {ROUNDS} rounds violated it):\n  {}",
        violations.len(),
        violations.join("\n  ")
    );
}
