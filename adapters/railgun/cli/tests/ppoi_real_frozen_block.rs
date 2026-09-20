#![allow(clippy::expect_used, clippy::panic)]

use raven_railgun_cli::bootstrap_subsquid::{PpoiEventsSource, RailwayPpoiClient};
use raven_railgun_engine::inspire::{apply_wal_entry, LogicalLeafStore};
use raven_railgun_engine::pir_table::PerListStatusEncoder;
use raven_railgun_persistence::WalEntryPayload;

const FROZEN_BLOCK_ROWS: u64 = 65_536;
const LIST_KEY: [u8; 32] = [
    0xef, 0xc6, 0xdd, 0xb5, 0x9c, 0x09, 0x8a, 0x13, 0xfb, 0x2b, 0x61, 0x8f, 0xda, 0xe9, 0x4c, 0x1c,
    0x3a, 0x80, 0x7a, 0xbc, 0x8f, 0xb1, 0x83, 0x7c, 0x93, 0x62, 0x0c, 0x91, 0x43, 0xee, 0x9e, 0x88,
];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "trigger: run by hand against live production; 131 JSON-RPC event pages \
             (65,536 rows at 501 inclusive rows per page)"]
async fn first_real_frozen_block_sync_retains_metadata_and_matches_every_root() {
    let client = RailwayPpoiClient::new("https://ppoi.fdi.network", 0, 1)
        .expect("live client")
        .with_event_limit(FROZEN_BLOCK_ROWS);
    let rows = client
        .fetch_all_events(LIST_KEY)
        .await
        .expect("frozen block fetch");
    let expected_rows = usize::try_from(FROZEN_BLOCK_ROWS).expect("row count fits usize");
    assert_eq!(rows.len(), expected_rows);

    let encoder = PerListStatusEncoder::new(64, 2048, LIST_KEY).expect("encoder");
    let mut store = LogicalLeafStore::new();
    for row in rows {
        let event_type = row.event_type.expect("Railway row carries event type");
        let signature = row.signature.expect("Railway row carries signature");
        let payload = WalEntryPayload::PpoiListLeafAdded {
            list_key: LIST_KEY,
            list_index: u32::try_from(row.index).expect("index fits u32"),
            blinded_commitment: row.leaf,
            status: 0,
            event_type,
            signature,
            validated_merkleroot: row.validated_merkleroot,
        };
        apply_wal_entry(&mut store, &payload, 0, &encoder).expect("atomic store append");
        assert_eq!(
            store.ppoi_imt_root(&LIST_KEY),
            Some(row.validated_merkleroot)
        );
    }

    assert_eq!(
        store.ppoi_list_leaves_iter(&LIST_KEY).count(),
        expected_rows
    );
    let metadata = store
        .ppoi_event_metadata(
            &LIST_KEY,
            u32::try_from(FROZEN_BLOCK_ROWS - 1).expect("fits"),
        )
        .expect("tail metadata retained");
    assert_eq!(metadata.signature.len(), 64);
    assert_eq!(FROZEN_BLOCK_ROWS.div_ceil(501), 131);
}
