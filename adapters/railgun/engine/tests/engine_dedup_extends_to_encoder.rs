//! Bootstrap dedup keys on `(DataSourceFilter, encoder_label)`, so one block of a list may not
//! be declared twice, and the router hands a row to every route bound to its block.

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
    bootstrap_railgun_engine_multi, DataSourceFilter, InstanceConfig,
};
use raven_railgun_engine::persistence::{ConsumerEvent, SnapshotPolicy};
use raven_railgun_engine::pir_table::EncoderKind;
use raven_railgun_engine::InstanceRole;
use raven_railgun_persistence::{PpoiEventType, WalEntryPayload};

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
    let block = |id: &str, sub: &str| {
        cfg(
            id,
            sub,
            tmp.path(),
            EncoderKind::PerListPath10 { list_key: lk },
            DataSourceFilter::PpoiListBlock {
                list_key: lk,
                block: 2,
            },
        )
    };
    let configs = vec![block("ppoi-block-a", "a"), block("ppoi-block-b", "b")];
    let params = InspireParams::secure_128_d2048();
    let res = bootstrap_railgun_engine_multi(configs, params, build_toy_state);
    let err = res.expect_err("expected dedup rejection");
    match err {
        AdapterError::InvalidQuery(msg) => {
            assert!(
                msg.contains("duplicate") && msg.contains("per-list-path10"),
                "expected duplicate + encoder label in error, got: {msg}"
            );
        }
        other => panic!("expected InvalidQuery, got {other:?}"),
    }
}

/// Two routes bound to one block must both receive its row. Drives the REAL router fan-out
/// (`bootstrap_railgun_engine_multi`'s mirror channel), not a local restatement of it: the
/// production comment warns that `.find()` would drop events past the first match, and only the
/// real path can prove that warning is enforced. Dedup keys on the encoder too, so two encoders
/// may share a block.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_row_reaches_every_route_bound_to_its_block() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let lk = ofac_list_key();
    let block = DataSourceFilter::PpoiListBlock {
        list_key: lk,
        block: 0,
    };
    let cfgs = vec![
        cfg(
            "ppoi-fanout-path",
            "path",
            tmp.path(),
            EncoderKind::PerListPath10 { list_key: lk },
            block,
        ),
        cfg(
            "ppoi-fanout-bc",
            "bc",
            tmp.path(),
            EncoderKind::PerLeafBc { tree_number: 0 },
            block,
        ),
    ];
    let params = InspireParams::secure_128_d2048();
    let mut handle =
        bootstrap_railgun_engine_multi(cfgs, params, build_toy_state).expect("bootstrap");

    let mut bc = [0u8; 32];
    bc[31] = 7;
    let payload = WalEntryPayload::PpoiListLeafAdded {
        list_key: lk,
        list_index: 0,
        blinded_commitment: bc,
        event_type: PpoiEventType::Shield,
        validated_merkleroot: [0; 32],
    };
    handle
        .channels
        .mirror_tx
        .send((payload, 100))
        .await
        .expect("router mirror inbound open");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    for h in &handle.instances {
        while h.logical_store.lock().ppoi_bc_at(&lk, 0) != Some(bc) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "{} never received the row its block routes to it",
                h.config.instance_id
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    drop(handle.channels);
    for h in handle.instances.drain(..) {
        let _ = h.sender.send(ConsumerEvent::Shutdown).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), h.consumer).await;
    }
    let _ = tokio::time::timeout(Duration::from_secs(2), handle.router).await;
}
