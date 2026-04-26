#![cfg(test)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::collections::BTreeMap;

use bytes::Bytes;
use proptest::prelude::*;
use raven_core::{MemoryStore, StorageBackend};

fn arb_key() -> impl Strategy<Value = u64> {
    0u64..=0xFFFF
}

fn arb_value() -> impl Strategy<Value = Bytes> {
    prop::collection::vec(any::<u8>(), 0..64).prop_map(Bytes::from)
}

fn arb_ops() -> impl Strategy<Value = Vec<(u64, Bytes)>> {
    prop::collection::vec((arb_key(), arb_value()), 0..256)
}

fn commit_inserts(store: &MemoryStore, ops: &[(u64, Bytes)]) {
    let mut txn = store.begin().expect("begin");
    for (k, v) in ops {
        txn.insert(*k, v.clone()).expect("insert");
    }
    txn.commit().expect("commit");
}

proptest! {
    #[test]
    fn committed_inserts_visible_with_last_write_wins(ops in arb_ops()) {
        let store = MemoryStore::new();
        let mut expected: BTreeMap<u64, Bytes> = BTreeMap::new();

        commit_inserts(&store, &ops);
        for (k, v) in &ops {
            expected.insert(*k, v.clone());
        }

        let snap = store.snapshot().expect("snapshot");
        prop_assert_eq!(snap.len() as usize, expected.len());
        for (k, want) in &expected {
            let got = snap.get(*k).expect("get").expect("key present");
            prop_assert_eq!(&got, want);
        }
    }

    #[test]
    fn snapshot_does_not_see_later_commits(
        before in arb_ops(),
        after in arb_ops(),
    ) {
        let store = MemoryStore::new();
        commit_inserts(&store, &before);
        let mut before_keys: BTreeMap<u64, Bytes> = BTreeMap::new();
        for (k, v) in &before {
            before_keys.insert(*k, v.clone());
        }

        let snap = store.snapshot().expect("snapshot");

        let novel_after: Vec<&(u64, Bytes)> = after
            .iter()
            .filter(|(k, _)| !before_keys.contains_key(k))
            .collect();
        prop_assume!(!novel_after.is_empty());

        for (k, v) in &novel_after {
            commit_inserts(&store, &[(*k, v.clone())]);
            prop_assert!(snap.get(*k).expect("get").is_none());
        }

        prop_assert_eq!(snap.len() as usize, before_keys.len());
    }

    #[test]
    fn mid_txn_snapshot_excludes_pending_writes(
        before in arb_ops(),
        pending in arb_ops(),
    ) {
        let store = MemoryStore::new();
        commit_inserts(&store, &before);
        let mut before_keys: BTreeMap<u64, Bytes> = BTreeMap::new();
        for (k, v) in &before {
            before_keys.insert(*k, v.clone());
        }

        let mut txn = store.begin().expect("begin");
        for (k, v) in &pending {
            txn.insert(*k, v.clone()).expect("insert");
        }

        let snap = store.snapshot().expect("snapshot");
        prop_assert_eq!(snap.len() as usize, before_keys.len());
        for (k, v) in &before_keys {
            let got = snap.get(*k).expect("get").expect("key present");
            prop_assert_eq!(&got, v);
        }

        txn.commit().expect("commit");
        prop_assert_eq!(snap.len() as usize, before_keys.len());
    }

    #[test]
    fn snapshot_len_matches_scan_count(ops in arb_ops()) {
        let store = MemoryStore::new();
        commit_inserts(&store, &ops);
        let snap = store.snapshot().expect("snapshot");
        let scan_count = snap
            .scan()
            .collect::<Result<Vec<_>, _>>()
            .expect("scan ok")
            .len();
        prop_assert_eq!(snap.len() as usize, scan_count);
    }

    #[test]
    fn get_agrees_with_scan(ops in arb_ops()) {
        let store = MemoryStore::new();
        commit_inserts(&store, &ops);
        let snap = store.snapshot().expect("snapshot");
        let scanned: BTreeMap<u64, Bytes> = snap
            .scan()
            .map(|r| r.expect("scan row"))
            .collect();

        for (k, want) in &scanned {
            let got = snap.get(*k).expect("get").expect("key present");
            prop_assert_eq!(&got, want);
        }
    }

    #[test]
    fn two_snapshots_at_same_generation_match(ops in arb_ops()) {
        let store = MemoryStore::new();
        commit_inserts(&store, &ops);
        let a = store.snapshot().expect("snap a");
        let b = store.snapshot().expect("snap b");
        prop_assert_eq!(a.len(), b.len());
        prop_assert_eq!(a.generation(), b.generation());

        let ka: BTreeMap<u64, Bytes> = a.scan().map(|r| r.expect("row a")).collect();
        let kb: BTreeMap<u64, Bytes> = b.scan().map(|r| r.expect("row b")).collect();
        prop_assert_eq!(ka, kb);
    }

    #[test]
    fn remove_deletes_on_commit(ops in arb_ops()) {
        let store = MemoryStore::new();
        commit_inserts(&store, &ops);

        let Some(&(to_remove, _)) = ops.first() else {
            return Ok(());
        };
        let mut txn = store.begin().expect("begin");
        txn.remove(to_remove).expect("remove");
        txn.commit().expect("commit");

        let snap = store.snapshot().expect("snapshot");
        prop_assert!(snap.get(to_remove).expect("get").is_none());
    }

    #[test]
    fn dropped_txn_has_no_effect(
        before in arb_ops(),
        abandoned in arb_ops(),
    ) {
        let store = MemoryStore::new();
        commit_inserts(&store, &before);
        let gen_before = store.generation();
        let len_before = store.len().expect("len");

        {
            let mut txn = store.begin().expect("begin");
            for (k, v) in &abandoned {
                txn.insert(*k, v.clone()).expect("insert");
            }
        }

        prop_assert_eq!(store.generation(), gen_before);
        prop_assert_eq!(store.len().expect("len"), len_before);
    }

    #[test]
    fn absent_keys_return_none(ops in arb_ops(), probe in arb_key()) {
        let store = MemoryStore::new();
        let mut present: BTreeMap<u64, Bytes> = BTreeMap::new();
        for (k, v) in &ops {
            present.insert(*k, v.clone());
        }
        commit_inserts(&store, &ops);
        let snap = store.snapshot().expect("snapshot");
        if present.contains_key(&probe) {
            prop_assert!(snap.get(probe).expect("get").is_some());
        } else {
            prop_assert!(snap.get(probe).expect("get").is_none());
        }
    }
}
