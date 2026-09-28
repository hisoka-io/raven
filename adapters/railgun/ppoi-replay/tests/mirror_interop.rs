//! The production mirror feed, which checks every signature, pointed at the replay over loopback,
//! takes a generated list to completion through a cold catch-up and then a growth step, every
//! row intact, and stops in front of a row whose signature fails.

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

use common::{generate_rows, list_key, replay, unprefixed_override};
use raven_railgun_core::ListKey;
use raven_railgun_persistence::{PpoiEventType, WalEntryPayload};
use raven_railgun_ppoi_mirror::{FeedStatus, MirrorConfig, PreflightFailure, UpstreamPpoiMirror};
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

fn checking_mirror(addr: std::net::SocketAddr) -> Arc<UpstreamPpoiMirror> {
    Arc::new(
        UpstreamPpoiMirror::new(MirrorConfig {
            endpoint: format!("http://{addr}"),
            poll_interval_secs: 1,
            max_rows_per_fetch: 501,
            ..MirrorConfig::default()
        })
        .expect("mirror config")
        .with_backfill_interval(Duration::ZERO),
    )
}

/// Row 900 is served the upstream way, commitment without `0x`, signed over that string.
#[tokio::test]
async fn the_mirror_catches_up_then_follows_growth_with_every_root_matching() {
    let mut rows = generate_rows(1_300);
    let overrides = unprefixed_override(&mut rows, 900);
    let replay = Arc::new(replay(rows.clone(), overrides, 700));
    let (addr, server) = common::spawn(Arc::clone(&replay)).await;
    let mirror = checking_mirror(addr);
    let list = ListKey(list_key());
    mirror
        .preflight(&list, Duration::from_secs(5))
        .await
        .expect("preflight accepts the replay");

    let status = FeedStatus::default();
    let (tx, mut rx) = mpsc::channel(4_096);
    let worker = tokio::spawn(Arc::clone(&mirror).run_feed(
        list,
        0,
        |cursor| cursor..u64::MAX,
        status.clone(),
        tx,
    ));
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
        assert_eq!(*event_type, wal_type(row.event_type), "index {}", row.index);
    }
    assert_eq!(status.snapshot().signatures_refused, 0);
    worker.abort();
    server.abort();
}

/// A row whose signature fails is refused by index and counted; the rows below it are taken and
/// nothing at or past it is sent, while the feed keeps asking for it.
#[tokio::test]
async fn a_planted_forgery_stops_the_feed_in_front_of_it() {
    const FORGED: u32 = 17;
    let mut rows = generate_rows(40);
    rows[FORGED as usize].signature[0] ^= 1;
    let replay = Arc::new(replay(rows, BTreeMap::new(), 40));
    let (addr, server) = common::spawn(replay).await;
    let status = FeedStatus::default();
    let (tx, mut rx) = mpsc::channel(128);
    let worker = tokio::spawn(checking_mirror(addr).run_feed(
        ListKey(list_key()),
        0,
        |cursor| cursor..u64::MAX,
        status.clone(),
        tx,
    ));
    let mut delivered = Vec::new();
    leaves_until(&mut rx, &mut delivered, FORGED as usize).await;
    tokio::time::timeout(Duration::from_secs(30), async {
        while status.snapshot().signatures_refused < 2 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the forged row is asked for again and refused again");
    worker.abort();
    server.abort();

    let progress = status.snapshot();
    assert_eq!(
        (
            progress.last_failure,
            progress.next_index,
            progress.rows_delivered
        ),
        (
            Some(PreflightFailure::BadSignature(u64::from(FORGED))),
            u64::from(FORGED),
            u64::from(FORGED)
        )
    );
    while let Ok((payload, _)) = rx.try_recv() {
        delivered.push(payload);
    }
    let indices: Vec<u32> = delivered
        .iter()
        .filter_map(|payload| match payload {
            WalEntryPayload::PpoiListLeafAdded { list_index, .. } => Some(*list_index),
            _ => None,
        })
        .collect();
    assert_eq!(indices, (0..FORGED).collect::<Vec<u32>>());
}
