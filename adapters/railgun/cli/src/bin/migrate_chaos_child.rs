//! Child subprocess for the real-SIGKILL `migrate-encoder` chaos harness.
//!
//! Steps through the offline encoder migration and pauses at a requested checkpoint by writing
//! `{"checkpoint":"<name>"}` to stdout, then sleeping until the parent SIGKILLs it.
//!
//! Checkpoints: `pre-re-encode`, `post-re-encode`, `pre-snapshot`, `post-snapshot`,
//! `pre-manifest-bump`, `post-manifest-bump`.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unwrap_used,
    clippy::doc_overindented_list_items,
    clippy::too_many_lines,
    clippy::needless_continue
)]

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use raven_railgun_core::AdapterError;
use raven_railgun_engine::inspire::{
    apply_wal_entry, re_encode_shard, restore_inspire_state, snapshot_inspire_state,
    LogicalLeafStore,
};
use raven_railgun_engine::pir_table::{EncoderKind, PerLeafCommitmentEncoder, PirTableEncoder};
use raven_railgun_persistence::{
    Manifest, Snapshot, SnapshotId, StoreLayout, Wal, WalEntryPayload, MANIFEST_SCHEMA_VERSION,
};

#[derive(Debug, Clone)]
struct Args {
    data_dir: PathBuf,
    target: EncoderKind,
    pause_at: Checkpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Checkpoint {
    PreReEncode,
    PostReEncode,
    PreSnapshot,
    PostSnapshot,
    PreManifestBump,
    PostManifestBump,
}

impl Checkpoint {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "pre-re-encode" => Ok(Self::PreReEncode),
            "post-re-encode" => Ok(Self::PostReEncode),
            "pre-snapshot" => Ok(Self::PreSnapshot),
            "post-snapshot" => Ok(Self::PostSnapshot),
            "pre-manifest-bump" => Ok(Self::PreManifestBump),
            "post-manifest-bump" => Ok(Self::PostManifestBump),
            other => Err(format!("unknown --pause-at {other}")),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::PreReEncode => "pre-re-encode",
            Self::PostReEncode => "post-re-encode",
            Self::PreSnapshot => "pre-snapshot",
            Self::PostSnapshot => "post-snapshot",
            Self::PreManifestBump => "pre-manifest-bump",
            Self::PostManifestBump => "post-manifest-bump",
        }
    }
}

fn parse_target(label: &str, tree_number: u32) -> Result<EncoderKind, String> {
    match label {
        "per-leaf-bc" => Ok(EncoderKind::PerLeafBc),
        "per-leaf-path" => Ok(EncoderKind::PerLeafPath { tree_number }),
        "per-node" => Ok(EncoderKind::PerNode { tree_number }),
        other => Err(format!("unsupported --target {other}")),
    }
}

fn parse_args() -> Args {
    let mut data_dir: Option<PathBuf> = None;
    let mut target_label: Option<String> = None;
    let mut pause_at: Option<Checkpoint> = None;
    let mut tree_number: u32 = 0;

    let mut iter = std::env::args().skip(1);
    while let Some(flag) = iter.next() {
        match flag.as_str() {
            "--data-dir" => {
                data_dir = Some(PathBuf::from(
                    iter.next().expect("--data-dir requires a value"),
                ));
            }
            "--target" => {
                target_label = Some(iter.next().expect("--target requires a value"));
            }
            "--pause-at" => {
                pause_at = Some(
                    Checkpoint::parse(&iter.next().expect("--pause-at requires a value"))
                        .expect("valid checkpoint name"),
                );
            }
            "--tree-number" => {
                tree_number = iter
                    .next()
                    .expect("--tree-number requires a value")
                    .parse()
                    .expect("--tree-number must be u32");
            }
            other => {
                eprintln!("migrate_chaos_child: unknown flag {other}");
                std::process::exit(2);
            }
        }
    }

    let data_dir = data_dir.expect("--data-dir is required");
    let target_label = target_label.expect("--target is required");
    let pause_at = pause_at.expect("--pause-at is required");
    let target = parse_target(&target_label, tree_number).expect("valid encoder label");

    Args {
        data_dir,
        target,
        pause_at,
    }
}

fn pause_until_killed(name: &str) -> ! {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{{\"checkpoint\":\"{name}\"}}").expect("write sentinel");
    stdout.flush().expect("flush sentinel");
    drop(stdout);
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

fn main() {
    let args = parse_args();
    eprintln!(
        "migrate_chaos_child: data_dir={} target={} pause_at={}",
        args.data_dir.display(),
        args.target.label(),
        args.pause_at.name()
    );

    let layout = StoreLayout::open(&args.data_dir).expect("open layout");
    let manifest = Manifest::load(&layout)
        .expect("manifest load")
        .expect("manifest present (parent must seed)");
    let old_label = manifest.encoder_label.clone();
    let new_label = args.target.label();
    assert_ne!(
        old_label, new_label,
        "child invoked with target == on-disk encoder; parent must seed against a different encoder"
    );
    assert_ne!(
        manifest.current_snapshot_id,
        SnapshotId(0),
        "child requires a committed snapshot in the seeded data_dir"
    );

    let snap = Snapshot::load(&layout, manifest.current_snapshot_id).expect("load snapshot");
    let mut state = restore_inspire_state(&snap.data).expect("restore inspire state");

    let noop_encoder: Arc<dyn PirTableEncoder> =
        Arc::new(PerLeafCommitmentEncoder::new(32, 1).expect("noop encoder"));
    let wal_floor = manifest.current_snapshot_seq.checked_sub(1);
    let wal = Wal::open(&layout, wal_floor).expect("wal open");
    let replay = wal.replay().expect("wal replay");
    let mut logical_store = LogicalLeafStore::new();
    for entry in &replay.entries {
        if entry.seq < manifest.current_snapshot_seq {
            continue;
        }
        let payload: WalEntryPayload =
            bincode::deserialize(&entry.payload).expect("wal payload deserialize");
        if let Err(AdapterError::InvalidQuery(_msg)) = apply_wal_entry(
            &mut logical_store,
            &payload,
            entry.block_height,
            noop_encoder.as_ref(),
        ) {
            continue;
        }
    }

    let entries_per_shard = u32::try_from(
        state
            .encoded_db
            .config
            .entries_per_shard()
            .min(u64::from(u32::MAX)),
    )
    .unwrap_or(u32::MAX);
    let entry_size = state.entry_size;
    let encoder = args
        .target
        .build(entry_size, entries_per_shard)
        .expect("build target encoder");

    if matches!(args.pause_at, Checkpoint::PreReEncode) {
        pause_until_killed(args.pause_at.name());
    }

    let shard_count = state.encoded_db.shards.len();
    for shard_id in 0..u32::try_from(shard_count).unwrap_or(u32::MAX) {
        let shard_bytes = encoder.materialize_shard(shard_id, &logical_store);
        re_encode_shard(
            Arc::make_mut(&mut state.encoded_db),
            &state.crs.params,
            shard_id,
            &shard_bytes,
            entry_size,
        )
        .expect("re_encode_shard");
    }

    if matches!(args.pause_at, Checkpoint::PostReEncode) {
        pause_until_killed(args.pause_at.name());
    }

    if matches!(args.pause_at, Checkpoint::PreSnapshot) {
        pause_until_killed(args.pause_at.name());
    }

    let bundle = snapshot_inspire_state(&state).expect("snapshot_inspire_state");
    let new_snap = Snapshot::build(bundle);
    let new_id = manifest.current_snapshot_id.next();
    new_snap.save(&layout, new_id).expect("snapshot save");

    if matches!(
        args.pause_at,
        Checkpoint::PostSnapshot | Checkpoint::PreManifestBump
    ) {
        pause_until_killed(args.pause_at.name());
    }

    let new_manifest = Manifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        scheme_tag: manifest.scheme_tag.clone(),
        instance_id: manifest.instance_id.clone(),
        current_snapshot_id: new_id,
        current_snapshot_seq: manifest.current_snapshot_seq,
        current_block_height: manifest.current_block_height,
        encoder_label: new_label.to_owned(),
        prev_encoder_label: Some(old_label.clone()),
    };
    new_manifest.save(&layout).expect("manifest save");

    if matches!(args.pause_at, Checkpoint::PostManifestBump) {
        pause_until_killed(args.pause_at.name());
    }

    eprintln!(
        "migrate_chaos_child: reached end-of-main without parking; \
         pause_at={} unhandled",
        args.pause_at.name()
    );
    std::process::exit(3);
}
