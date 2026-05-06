//! Tests for the auto-spawn JSONL log helpers.

#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use std::io::Write;

    use raven_railgun_cli::auto_spawn::{
        append_spawn_record, load_spawn_log, spawn_log_path, SpawnRecord,
    };

    fn make_record(tree_number: u32) -> SpawnRecord {
        SpawnRecord {
            tree_number,
            instance_id: format!("commit-tree-{tree_number}"),
            data_dir: std::path::PathBuf::from(format!("/var/lib/raven/{tree_number}")),
            spawned_at_secs: 1_700_000_000 + u64::from(tree_number),
        }
    }

    #[test]
    fn spawn_log_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let registry = dir.path();

        let r0 = make_record(0);
        let r1 = make_record(1);
        let r2 = make_record(2);

        append_spawn_record(registry, &r0).expect("append r0");
        append_spawn_record(registry, &r1).expect("append r1");
        append_spawn_record(registry, &r2).expect("append r2");

        let records = load_spawn_log(registry).expect("load");
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].tree_number, 0);
        assert_eq!(records[1].tree_number, 1);
        assert_eq!(records[2].tree_number, 2);
        assert_eq!(records[0].instance_id, "commit-tree-0");
        assert_eq!(records[2].data_dir.to_str().unwrap(), "/var/lib/raven/2");
    }

    #[test]
    fn spawn_log_skips_malformed_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let registry = dir.path();

        let good = make_record(7);
        append_spawn_record(registry, &good).expect("append");

        let path = spawn_log_path(registry);
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open");
        writeln!(f, "{{not valid json}}").expect("write junk");

        let records = load_spawn_log(registry).expect("load");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].tree_number, 7);
    }

    #[test]
    fn spawn_log_empty_when_file_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let records = load_spawn_log(dir.path()).expect("load");
        assert!(records.is_empty());
    }
}
