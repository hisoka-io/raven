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
    fn scan_yields_strictly_ascending_keys(ops in arb_ops()) {
        let store = MemoryStore::new();
        commit_inserts(&store, &ops);
        let snap = store.snapshot().expect("snapshot");

        let keys: Vec<u64> = snap
            .scan()
            .map(|r| r.expect("scan row").0)
            .collect();

        for (prev, next) in keys.iter().zip(keys.iter().skip(1)) {
            prop_assert!(
                prev < next,
                "scan order violated: key {} followed by {}",
                prev,
                next
            );
        }

        let mut sorted_unique: Vec<u64> = ops.iter().map(|(k, _)| *k).collect();
        sorted_unique.sort_unstable();
        sorted_unique.dedup();
        prop_assert_eq!(keys, sorted_unique);
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

/// `#![deny(missing_docs)]` is what keeps the framework's extension points documented, and
/// nothing observed its presence: deleting the attribute leaves `cargo build` green and the
/// prose it protects rots silently from there.
///
/// Text rather than a compile-fail harness, because that needs a dev-dependency to assert one
/// line. But text done properly: a bare `contains` passes on a COMMENTED-OUT attribute, on one
/// followed by an `allow`, and on a mention inside a doc comment - all three measured. The
/// needles are split so this file is not its own counterexample.
fn denies_missing_docs(src: &str) -> bool {
    const DENY: &str = concat!("deny(missing", "_docs)");
    const ALLOW: &str = concat!("allow(missing", "_docs)");
    let active = |line: &str| {
        let t = line.trim_start();
        !t.starts_with("//") && t.starts_with("#!")
    };
    let denied = src.lines().any(|l| active(l) && l.contains(DENY));
    let allowed = src.lines().any(|l| active(l) && l.contains(ALLOW));
    denied && !allowed
}

/// Reclassified: this is a guard on a guard, not raven-core coverage. Stripping
/// `#![deny(missing_docs)]` from all six framework crates leaves it green while its
/// sibling `every_framework_crate_still_denies_missing_docs` goes red; what it stops
/// is the sibling passing vacuously on a commented-out attribute, an overriding
/// `allow`, or a doc-comment mention. 17 lines to keep a real test honest.
#[test]
fn the_missing_docs_detector_rejects_what_a_bare_substring_accepts() {
    // The three shapes m8 named, each of which the previous `contains` check passed.
    assert!(denies_missing_docs("#![deny(missing_docs)]\n"));
    assert!(
        !denies_missing_docs("// #![deny(missing_docs)]\n"),
        "a commented-out attribute must not count"
    );
    assert!(
        !denies_missing_docs("#![deny(missing_docs)]\n#![allow(missing_docs)]\n"),
        "a later allow must override the deny"
    );
    assert!(
        !denies_missing_docs("//! see #![deny(missing_docs)] for details\n"),
        "a mention inside a doc comment must not count"
    );
    assert!(!denies_missing_docs(""), "an empty source denies nothing");
}

/// Every framework crate, not just this one. The lint previously had a guard on `raven-core`
/// alone, so partial coverage read as full coverage.
#[test]
fn every_framework_crate_still_denies_missing_docs() {
    let crates = [
        ("raven-core", include_str!("../src/lib.rs")),
        ("raven-client", include_str!("../../client/src/lib.rs")),
        ("raven-server", include_str!("../../server/src/lib.rs")),
        ("raven-storage", include_str!("../../storage/src/lib.rs")),
        ("raven-indexer", include_str!("../../indexer/src/lib.rs")),
        (
            "raven-crypto-primitives",
            include_str!("../../crypto-primitives/src/lib.rs"),
        ),
    ];
    for (name, src) in crates {
        assert!(
            denies_missing_docs(src),
            "{name} must keep denying missing docs: these crates are the framework's public \
             surface and their contracts live in prose the types cannot express"
        );
    }
}
