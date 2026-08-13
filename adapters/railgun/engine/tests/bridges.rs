//! Indexer<->Consumer + Mirror<->Consumer bridge property tests.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use raven_railgun_core::{CommitmentLeaf, RailgunEvent};
use raven_railgun_engine::orchestrator::{indexer_to_consumer_bridge, mirror_to_consumer_bridge};
use raven_railgun_engine::persistence::ConsumerEvent;
use raven_railgun_indexer::IndexerMessage;
use raven_railgun_persistence::WalEntryPayload;
use std::time::Duration;
use tokio::sync::mpsc;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn indexer_bridge_translates_event_reorg_heartbeat() {
    let (idx_tx, idx_rx) = mpsc::channel::<IndexerMessage>(8);
    let (cons_tx, mut cons_rx) = mpsc::channel::<ConsumerEvent>(8);
    let bridge = tokio::spawn(indexer_to_consumer_bridge(idx_rx, cons_tx, None));

    let event = RailgunEvent::Transact {
        block_number: 100,
        tx_hash: [1u8; 32],
        tree_number: 0,
        start_position: 5,
        leaves: vec![CommitmentLeaf {
            tree_number: 0,
            leaf_index: 5,
            commitment_hash: [0xab; 32],
            ciphertext: vec![],
        }],
    };
    idx_tx
        .send(IndexerMessage::Event {
            event: event.clone(),
            block_height: 100,
        })
        .await
        .expect("send event");

    idx_tx
        .send(IndexerMessage::Reorg { height: 99 })
        .await
        .expect("send reorg");

    idx_tx
        .send(IndexerMessage::Heartbeat {
            wallclock_unix_ms: 1_700_000_000,
            chain_head_block: 200,
            scanned_through_block: 198,
        })
        .await
        .expect("send heartbeat");

    let got = tokio::time::timeout(Duration::from_secs(2), cons_rx.recv())
        .await
        .expect("recv 1")
        .expect("event present");
    match got {
        ConsumerEvent::Chain(e, h) => {
            assert_eq!(h, 100);
            // RailgunEvent::Transact does not impl PartialEq; compare via Debug.
            assert_eq!(format!("{e:?}"), format!("{event:?}"));
        }
        other => panic!("expected Chain, got {other:?}"),
    }

    let got = tokio::time::timeout(Duration::from_secs(2), cons_rx.recv())
        .await
        .expect("recv 2")
        .expect("event present");
    assert!(matches!(got, ConsumerEvent::Reorg(99)));

    let got = tokio::time::timeout(Duration::from_secs(2), cons_rx.recv())
        .await
        .expect("recv 3")
        .expect("event present");
    assert!(matches!(
        got,
        ConsumerEvent::Heartbeat {
            chain_head: 200,
            scanned_through: 198,
        }
    ));

    drop(idx_tx);
    tokio::time::timeout(Duration::from_secs(2), bridge)
        .await
        .expect("bridge exits when indexer channel closes")
        .expect("join");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mirror_bridge_translates_ppoi_payload() {
    let (mir_tx, mir_rx) = mpsc::channel::<(WalEntryPayload, u64)>(8);
    let (cons_tx, mut cons_rx) = mpsc::channel::<ConsumerEvent>(8);
    let bridge = tokio::spawn(mirror_to_consumer_bridge(mir_rx, cons_tx));

    let payload = WalEntryPayload::PpoiStatus {
        list_key: [1u8; 32],
        blinded_commitment: [2u8; 32],
        status: 3,
    };
    mir_tx.send((payload.clone(), 0)).await.expect("send ppoi");

    let got = tokio::time::timeout(Duration::from_secs(2), cons_rx.recv())
        .await
        .expect("recv")
        .expect("event present");
    match got {
        ConsumerEvent::Ppoi(p, h) => {
            assert_eq!(h, 0);
            assert_eq!(p, payload);
        }
        other => panic!("expected Ppoi, got {other:?}"),
    }

    drop(mir_tx);
    tokio::time::timeout(Duration::from_secs(2), bridge)
        .await
        .expect("bridge exits when mirror channel closes")
        .expect("join");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn indexer_bridge_exits_when_consumer_closes() {
    let (idx_tx, idx_rx) = mpsc::channel::<IndexerMessage>(8);
    let (cons_tx, cons_rx) = mpsc::channel::<ConsumerEvent>(8);
    let bridge = tokio::spawn(indexer_to_consumer_bridge(idx_rx, cons_tx, None));

    drop(cons_rx);
    let _ = idx_tx
        .send(IndexerMessage::Heartbeat {
            wallclock_unix_ms: 0,
            chain_head_block: 0,
            scanned_through_block: 0,
        })
        .await;
    tokio::time::timeout(Duration::from_secs(2), bridge)
        .await
        .expect("bridge exits when consumer channel closes")
        .expect("join");
}

fn transact_in(tree_number: u32, leaf_index: u32) -> RailgunEvent {
    RailgunEvent::Transact {
        block_number: 100 + u64::from(leaf_index),
        tx_hash: [2u8; 32],
        tree_number,
        start_position: leaf_index,
        leaves: vec![CommitmentLeaf {
            tree_number,
            leaf_index,
            commitment_hash: [0xcd; 32],
            ciphertext: vec![],
        }],
    }
}

/// The single-instance path has no route table, so the bridge is where the tree scope is
/// enforced. Without it a `per-leaf-bc` store receives every tree and, because rows are
/// indexed by `leaf_index` alone, the higher tree silently overwrites the lower one's row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_bridge_drops_chain_events_for_other_trees() {
    let (idx_tx, idx_rx) = mpsc::channel::<IndexerMessage>(8);
    let (cons_tx, mut cons_rx) = mpsc::channel::<ConsumerEvent>(8);
    let bridge = tokio::spawn(indexer_to_consumer_bridge(idx_rx, cons_tx, Some(0)));

    for tree in [0u32, 1, 0, 2] {
        idx_tx
            .send(IndexerMessage::Event {
                event: transact_in(tree, tree),
                block_height: 100 + u64::from(tree),
            })
            .await
            .expect("send");
    }
    drop(idx_tx);

    let mut seen_trees = Vec::new();
    while let Some(ev) = cons_rx.recv().await {
        if let ConsumerEvent::Chain(event, _) = ev {
            seen_trees.push(event.tree_number().expect("Transact carries a tree"));
        }
    }
    assert_eq!(
        seen_trees,
        vec![0, 0],
        "a bridge scoped to tree 0 must forward only tree-0 events; forwarding {seen_trees:?} \
         lets a foreign tree reach a store whose rows are indexed by leaf_index alone"
    );
    let _ = tokio::time::timeout(Duration::from_secs(2), bridge).await;
}

/// `None` means a per-list encoder, which consumes no chain-tree events by shape; the
/// bridge must not start dropping everything in that case.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unscoped_bridge_still_forwards_every_tree() {
    let (idx_tx, idx_rx) = mpsc::channel::<IndexerMessage>(8);
    let (cons_tx, mut cons_rx) = mpsc::channel::<ConsumerEvent>(8);
    let bridge = tokio::spawn(indexer_to_consumer_bridge(idx_rx, cons_tx, None));

    for tree in [0u32, 1, 2] {
        idx_tx
            .send(IndexerMessage::Event {
                event: transact_in(tree, tree),
                block_height: 100 + u64::from(tree),
            })
            .await
            .expect("send");
    }
    drop(idx_tx);

    let mut n = 0;
    while let Some(ev) = cons_rx.recv().await {
        if matches!(ev, ConsumerEvent::Chain(..)) {
            n += 1;
        }
    }
    assert_eq!(n, 3, "an unscoped bridge must forward all three");
    let _ = tokio::time::timeout(Duration::from_secs(2), bridge).await;
}
