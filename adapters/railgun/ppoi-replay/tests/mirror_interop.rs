//! The production mirror client, pointed at the replay over loopback, takes a generated list
//! to completion through a cold catch-up and then a growth step, every row intact.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use common::{generate_rows, list_key, replay};
use raven_railgun_core::ListKey;
use raven_railgun_persistence::{PpoiEventType, WalEntryPayload};
use raven_railgun_ppoi_mirror::{MirrorConfig, UpstreamPpoiMirror};
use raven_railgun_ppoi_replay::EventType;
use tokio::sync::mpsc;

fn wal_type(event_type: EventType) -> PpoiEventType {
    match event_type {
        EventType::Shield => PpoiEventType::Shield,
        EventType::Transact => PpoiEventType::Transact,
        EventType::Unshield => PpoiEventType::Unshield,
        EventType::LegacyTransact => PpoiEventType::LegacyTransact,
    }
}

async fn leaves_until(
    rx: &mut mpsc::Receiver<(WalEntryPayload, u64)>,
    delivered: &mut Vec<WalEntryPayload>,
    want: usize,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while delivered.len() < want {
        let (payload, _) = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "mirror delivered {} of {want} rows in 30 s",
                    delivered.len()
                )
            })
            .expect("mirror feed open");
        if matches!(payload, WalEntryPayload::PpoiListLeafAdded { .. }) {
            delivered.push(payload);
        }
    }
}

#[tokio::test]
async fn the_mirror_catches_up_then_follows_growth_with_every_root_matching() {
    let rows = generate_rows(1_300);
    let replay = Arc::new(replay(rows.clone(), BTreeMap::new(), 700));
    let (addr, server) = common::spawn(Arc::clone(&replay)).await;
    let mirror = Arc::new(
        UpstreamPpoiMirror::new(MirrorConfig {
            endpoint: format!("http://{addr}"),
            poll_interval_secs: 1,
            max_rows_per_fetch: 501,
            ..MirrorConfig::default()
        })
        .expect("mirror config")
        .with_backfill_interval(Duration::ZERO),
    );
    let list = ListKey(list_key());
    mirror
        .preflight(&list, Duration::from_secs(5))
        .await
        .expect("preflight accepts the replay");

    let (tx, mut rx) = mpsc::channel(4_096);
    let worker = tokio::spawn(Arc::clone(&mirror).run_worker(ListKey(list_key()), 0, tx));
    let mut delivered = Vec::new();
    leaves_until(&mut rx, &mut delivered, 700).await;
    replay.grow_to(1_300).expect("grow");
    leaves_until(&mut rx, &mut delivered, 1_300).await;

    assert_eq!(delivered.len(), rows.len());
    for (payload, row) in delivered.iter().zip(&rows) {
        let WalEntryPayload::PpoiListLeafAdded {
            list_key: key,
            list_index,
            blinded_commitment,
            event_type,
            signature,
            validated_merkleroot,
            ..
        } = payload
        else {
            unreachable!("filtered to leaf rows");
        };
        assert_eq!(*key, list_key());
        assert_eq!(*list_index, row.index);
        assert_eq!(
            *blinded_commitment, row.blinded_commitment,
            "index {}",
            row.index
        );
        assert_eq!(
            *validated_merkleroot, row.validated_merkleroot,
            "index {}",
            row.index
        );
        assert_eq!(
            signature.as_slice(),
            row.signature.as_slice(),
            "index {}",
            row.index
        );
        assert_eq!(*event_type, wal_type(row.event_type), "index {}", row.index);
    }
    worker.abort();
    server.abort();
}
