//! Bootstrap dedup keys on `(DataSourceFilter, encoder_label)`, so one list key
//! may carry several encoder kinds but not a duplicate pair.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    non_snake_case
)]

use std::time::Duration;

use raven_inspire::params::InspireParams;
use raven_railgun_core::{AdapterError, InstanceId};
use raven_railgun_engine::inspire::InspireServerState;
use raven_railgun_engine::orchestrator::{
    bootstrap_railgun_engine_multi, DataSourceFilter, InstanceConfig, VerificationMode,
};
use raven_railgun_engine::persistence::{ConsumerEvent, SnapshotPolicy};
use raven_railgun_engine::pir_table::EncoderKind;
use raven_railgun_engine::InstanceRole;
use raven_railgun_persistence::WalEntryPayload;
use tokio::sync::mpsc;

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-dedup-encoder-test";
const TOY_ENTRY_SIZE: usize = 256;
const TOY_ENTRIES_PER_SHARD: u32 = 2048;

fn build_toy_state(config: &InstanceConfig) -> raven_railgun_core::Result<InspireServerState> {
    raven_railgun_testkit::try_toy_state(config.record_size)
}

fn ofac_list_key() -> [u8; 32] {
    let hex = "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        let s = &hex[i * 2..i * 2 + 2];
        *b = u8::from_str_radix(s, 16).expect("hex");
    }
    out
}

fn cfg(
    id: &str,
    sub: &str,
    root: &std::path::Path,
    encoder: EncoderKind,
    ds: DataSourceFilter,
) -> InstanceConfig {
    InstanceConfig {
        instance_id: InstanceId::new(id),
        role: InstanceRole::Live,
        data_dir: root.join(sub),
        encoder,
        // fixed-layout encoders pin their own row width; a declared 256 is substituted, not served
        record_size: encoder.effective_record_size(TOY_ENTRY_SIZE),
        entries_per_shard: TOY_ENTRIES_PER_SHARD,
        verification_mode: VerificationMode::UpstreamSignature,
        data_source: ds,
        use_flock: false,
        snapshot_policy: SnapshotPolicy::default(),
        scheme_tag: SCHEME_TAG.to_owned(),
        channel_capacity: 256,
        max_concurrent_queries: None,
        verification_cadence_n: 0,
        chain_source: None,
    }
}

#[test]
fn bootstrap_engine_rejects_two_instances_with_identical_data_source_AND_encoder_kind() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let lk = ofac_list_key();
    let configs = vec![
        cfg(
            "ppoi-status-a",
            "a",
            tmp.path(),
            EncoderKind::PerListStatus { list_key: lk },
            DataSourceFilter::PpoiList(lk),
        ),
        cfg(
            "ppoi-status-b",
            "b",
            tmp.path(),
            EncoderKind::PerListStatus { list_key: lk },
            DataSourceFilter::PpoiList(lk),
        ),
    ];
    let params = InspireParams::secure_128_d2048();
    let factory = |c: &InstanceConfig| -> raven_railgun_core::Result<InspireServerState> {
        build_toy_state(c)
    };
    let res = bootstrap_railgun_engine_multi(configs, params, factory);
    let err = res.expect_err("expected dedup rejection");
    match err {
        AdapterError::InvalidQuery(msg) => {
            assert!(
                msg.contains("duplicate") && msg.contains("per-list-status"),
                "expected duplicate + encoder label in error, got: {msg}"
            );
        }
        other => panic!("expected InvalidQuery, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stands up 2 InsPIRe instances, ~7 s of setup each. Trigger: changing the bootstrap \
            dedup key over (DataSourceFilter, encoder_label). CI runs it in the durability + \
            closure engine-ignored lane."]
async fn bootstrap_railgun_engine_multi_routes_two_ppoi_instances_with_same_list_key_different_encoder_kinds(
) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let lk = ofac_list_key();
    let configs = vec![
        cfg(
            "ppoi-status-ofac",
            "status",
            tmp.path(),
            EncoderKind::PerListStatus { list_key: lk },
            DataSourceFilter::PpoiList(lk),
        ),
        cfg(
            "ppoi-paths-ofac",
            "paths",
            tmp.path(),
            EncoderKind::PerListPath { list_key: lk },
            DataSourceFilter::PpoiList(lk),
        ),
    ];
    let params = InspireParams::secure_128_d2048();
    let factory = |c: &InstanceConfig| -> raven_railgun_core::Result<InspireServerState> {
        build_toy_state(c)
    };
    let mh =
        bootstrap_railgun_engine_multi(configs, params, factory).expect("bootstrap should succeed");
    assert_eq!(mh.instances.len(), 2, "two instances expected");
    let labels: Vec<&str> = mh
        .instances
        .iter()
        .map(|p| p.config.encoder.label())
        .collect();
    assert!(labels.contains(&"per-list-status"));
    assert!(labels.contains(&"per-list-path"));
    let _ = mh;
}

/// One list key with two route entries must reach both consumers. Drives the REAL
/// router fan-out (`bootstrap_railgun_engine_multi`'s mirror channel), not a local
/// restatement of it: the production comment warns that `.find()` would drop events
/// past the first match, and only the real path can prove that warning is enforced.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ppoi_route_dispatch_does_not_collide_for_status_and_paths_on_same_list_key() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let lk = ofac_list_key();
    let cfgs = vec![cfg(
        "ppoi-fanout-host",
        "host",
        tmp.path(),
        EncoderKind::PerListStatus { list_key: lk },
        DataSourceFilter::PpoiList(lk),
    )];
    let params = InspireParams::secure_128_d2048();
    let mut handle =
        bootstrap_railgun_engine_multi(cfgs, params, build_toy_state).expect("bootstrap");

    let (tx_status, mut rx_status) = mpsc::channel::<ConsumerEvent>(8);
    let (tx_paths, mut rx_paths) = mpsc::channel::<ConsumerEvent>(8);
    handle.ppoi_list_routes.store(std::sync::Arc::new(vec![
        (DataSourceFilter::PpoiList(lk), tx_status),
        (DataSourceFilter::PpoiList(lk), tx_paths),
    ]));

    let payload = WalEntryPayload::PpoiStatus {
        list_key: lk,
        blinded_commitment: [7u8; 32],
        status: 1,
    };
    handle
        .channels
        .mirror_tx
        .send((payload.clone(), 100))
        .await
        .expect("router mirror inbound open");

    let got_status = tokio::time::timeout(Duration::from_secs(2), rx_status.recv())
        .await
        .expect("status consumer timed out")
        .expect("status channel closed");
    let got_paths = tokio::time::timeout(Duration::from_secs(2), rx_paths.recv())
        .await
        .expect("second route bound to the same list_key never received the payload")
        .expect("paths channel closed");
    match (got_status, got_paths) {
        (ConsumerEvent::Ppoi(p1, h1), ConsumerEvent::Ppoi(p2, h2)) => {
            assert_eq!(p1, payload);
            assert_eq!(p2, payload);
            assert_eq!(h1, 100);
            assert_eq!(h2, 100);
        }
        other => panic!("expected Ppoi events on both consumers, got {other:?}"),
    }

    drop(handle.channels);
    for h in handle.instances.drain(..) {
        let _ = h.sender.send(ConsumerEvent::Shutdown).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), h.consumer).await;
    }
    let _ = tokio::time::timeout(Duration::from_secs(2), handle.router).await;
}
