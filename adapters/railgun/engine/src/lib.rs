//! Railgun PIR engine adapter: the `RavenInspireScheme` and per-instance integration
//! over the generic lifecycle (`PirScheme`/`Engine`/`PirInstance`) in `raven-server`.

#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]
#![deny(missing_docs)]

pub mod imt;
pub mod inspire;
pub mod layer_two;
pub mod offline_packing_keys_cache;
pub mod orchestrator;
pub mod persistence;
pub mod pir_table;
pub mod tree_fill_watcher;

pub use raven_server::{
    DrainState, Engine, InFlightGuard, InstanceRole, PirInstance, PirScheme, Snapshot,
};

use raven_railgun_core::{Epoch, Result};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_record_round_trips() {
        let payload = b"\x01\x02\x03\x04";
        let padded = inspire::pad_record(payload).expect("pad");
        assert_eq!(padded.len(), inspire::MIN_SAFE_RECORD_BYTES);
        assert_eq!(padded.get(..4), Some(payload.as_slice()));
        assert!(padded.iter().skip(4).all(|b| *b == 0));
        let recovered = inspire::unpad_record(&padded, 4).expect("unpad");
        assert_eq!(recovered, payload);
    }

    #[test]
    fn pad_record_rejects_oversized_payload() {
        let oversized = vec![0u8; inspire::MIN_SAFE_RECORD_BYTES + 1];
        assert!(inspire::pad_record(&oversized).is_none());
    }

    #[test]
    fn unpad_record_rejects_wrong_length() {
        let wrong_size = vec![0u8; inspire::MIN_SAFE_RECORD_BYTES - 1];
        assert!(inspire::unpad_record(&wrong_size, 4).is_none());
    }

    #[test]
    fn snapshot_then_restore_recovers_byte_identical_query_response() {
        use raven_inspire::params::{InspireParams, InspireVariant};
        use raven_railgun_persistence::{Snapshot, SnapshotId, StoreLayout, SNAPSHOT_MAGIC};

        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StoreLayout::open(dir.path()).expect("open");

        let params = InspireParams::secure_128_d2048();
        let entries = 256usize;
        let entry_size = 256usize;
        let db: Vec<u8> = (0..entries)
            .flat_map(|i| (0..entry_size).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
            .collect();
        let (state_a, sk) =
            inspire::setup_state(&params, &db, entry_size, InspireVariant::TwoPacking)
                .expect("setup state");

        let bytes = inspire::snapshot_inspire_state(&state_a).expect("serialize");
        let snap = Snapshot::build(bytes, SNAPSHOT_MAGIC);
        snap.save(&layout, SnapshotId(1)).expect("save");

        let snap_loaded = Snapshot::load(&layout, SnapshotId(1), SNAPSHOT_MAGIC).expect("load");
        let state_b = inspire::restore_inspire_state(&snap_loaded.data).expect("restore");

        let mut client_session_a =
            inspire::build_client_session((*state_a.crs).clone(), sk.clone(), &params)
                .expect("client session a");
        inspire::register_client_session(&mut client_session_a, &state_a).expect("register a");
        let target = 42u64;
        let (cs, q) =
            inspire::build_seeded_query(&client_session_a, state_a.shard_config(), target, &params)
                .expect("query a");

        let resp_a =
            <inspire::RavenInspireScheme as PirScheme>::respond(&state_a, &q).expect("respond a");

        let mut client_session_b =
            inspire::build_client_session((*state_b.crs).clone(), sk.clone(), &params)
                .expect("client session b");
        inspire::register_client_session(&mut client_session_b, &state_b).expect("register b");
        let (cs_b, q_b) =
            inspire::build_seeded_query(&client_session_b, state_b.shard_config(), target, &params)
                .expect("query b");
        let resp_b =
            <inspire::RavenInspireScheme as PirScheme>::respond(&state_b, &q_b).expect("respond b");

        let plaintext_a =
            inspire::extract_response(&state_a.crs, &cs, &resp_a, entry_size).expect("extract a");
        let plaintext_b =
            inspire::extract_response(&state_b.crs, &cs_b, &resp_b, entry_size).expect("extract b");
        assert_eq!(
            plaintext_a, plaintext_b,
            "snapshot+restore must preserve query semantics"
        );
        let target_idx = usize::try_from(target).expect("fits");
        let expected = db
            .get(target_idx * entry_size..(target_idx + 1) * entry_size)
            .expect("planted slice");
        assert_eq!(
            plaintext_a.get(..entry_size),
            Some(expected),
            "byte-equality with planted DB"
        );
    }
}
