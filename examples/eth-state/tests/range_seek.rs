#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use eth_state::fold::materialize_shard_bytes;
use eth_state::{ENTRIES_PER_SHARD, ENTRY_SIZE};
use raven_core::storage::{Row, Snapshot};
use raven_core::Error;

struct RangeOnlySnapshot {
    rows: Vec<Row>,
    range_calls: AtomicUsize,
}

impl Snapshot for RangeOnlySnapshot {
    fn generation(&self) -> u64 {
        0
    }

    fn len(&self) -> u64 {
        self.rows.len() as u64
    }

    fn get(&self, key: u64) -> Result<Option<Bytes>, Error> {
        Ok(self
            .rows
            .iter()
            .find(|(row_key, _)| *row_key == key)
            .map(|(_, value)| value.clone()))
    }

    fn scan<'a>(&'a self) -> Box<dyn Iterator<Item = Result<Row, Error>> + 'a> {
        panic!("materialization must not consume the prefix scan")
    }

    fn scan_range<'a>(
        &'a self,
        range: std::ops::Range<u64>,
    ) -> Box<dyn Iterator<Item = Result<Row, Error>> + 'a> {
        self.range_calls.fetch_add(1, Ordering::Relaxed);
        Box::new(
            self.rows
                .iter()
                .filter(move |(key, _)| range.contains(key))
                .cloned()
                .map(Ok),
        )
    }
}

#[test]
fn shard_materialization_seeks_to_its_window_without_row_drift() {
    let shard_id = 3u32;
    let first = u64::from(shard_id) * ENTRIES_PER_SHARD as u64;
    let snapshot = RangeOnlySnapshot {
        rows: vec![
            (0, Bytes::from_static(b"prefix")),
            (first + 7, Bytes::from(vec![0xA5; ENTRY_SIZE])),
            (
                first + ENTRIES_PER_SHARD as u64,
                Bytes::from_static(b"suffix"),
            ),
        ],
        range_calls: AtomicUsize::new(0),
    };

    let bytes = materialize_shard_bytes(&snapshot, shard_id, ENTRY_SIZE).expect("materialize");
    assert_eq!(snapshot.range_calls.load(Ordering::Relaxed), 1);
    assert!(bytes[..7 * ENTRY_SIZE].iter().all(|byte| *byte == 0));
    assert!(bytes[7 * ENTRY_SIZE..8 * ENTRY_SIZE]
        .iter()
        .all(|byte| *byte == 0xA5));
    assert!(bytes[8 * ENTRY_SIZE..].iter().all(|byte| *byte == 0));
}
