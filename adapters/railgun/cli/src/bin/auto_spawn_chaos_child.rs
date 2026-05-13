//! Child subprocess for the real-SIGKILL auto-spawn lifecycle harness.
//!
//! Reproduces `spawn_one` up to one of three pause points, emits `{"paused_at":"<name>"}` to
//! stdout, then parks until the parent SIGKILLs it. Tests inspect on-disk recovery semantics at
//! each crash window that the append-LAST ordering invariant is designed to close.
//!
//! Pause points: `before-add-live`, `after-add-live-before-log`, `after-log`.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unwrap_used
)]

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_cli::auto_spawn::{append_spawn_record, instance_id_for_tree, SpawnRecord};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{setup_state, RavenInspireScheme};
use raven_railgun_engine::persistence::{bootstrap_inspire_instance, SnapshotPolicy};
use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance};
use raven_railgun_persistence::StoreLayout;

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-auto-spawn-chaos-child";
const TOY_ENTRIES: usize = 256;
const TOY_ENTRY_SIZE: usize = 32;
const ENTRIES_PER_SHARD: u32 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PausePoint {
    BeforeAddLive,
    AfterAddLiveBeforeLog,
    AfterLog,
}

impl PausePoint {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "before-add-live" => Ok(Self::BeforeAddLive),
            "after-add-live-before-log" => Ok(Self::AfterAddLiveBeforeLog),
            "after-log" => Ok(Self::AfterLog),
            other => Err(format!("unknown --pause-at {other}")),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::BeforeAddLive => "before-add-live",
            Self::AfterAddLiveBeforeLog => "after-add-live-before-log",
            Self::AfterLog => "after-log",
        }
    }
}

#[derive(Debug, Clone)]
struct Args {
    data_dir: PathBuf,
    spawn_log_dir: PathBuf,
    tree_number: u32,
    pause_at: PausePoint,
}

fn parse_args() -> Args {
    let mut data_dir: Option<PathBuf> = None;
    let mut spawn_log_dir: Option<PathBuf> = None;
    let mut tree_number: Option<u32> = None;
    let mut pause_at: Option<PausePoint> = None;

    let mut iter = std::env::args().skip(1);
    while let Some(flag) = iter.next() {
        match flag.as_str() {
            "--data-dir" => {
                data_dir = Some(PathBuf::from(
                    iter.next().expect("--data-dir requires a value"),
                ));
            }
            "--spawn-log-dir" => {
                spawn_log_dir = Some(PathBuf::from(
                    iter.next().expect("--spawn-log-dir requires a value"),
                ));
            }
            "--tree-number" => {
                tree_number = Some(
                    iter.next()
                        .expect("--tree-number requires a value")
                        .parse()
                        .expect("--tree-number must be u32"),
                );
            }
            "--pause-at" => {
                pause_at = Some(
                    PausePoint::parse(&iter.next().expect("--pause-at requires a value"))
                        .expect("valid pause point"),
                );
            }
            other => {
                eprintln!("auto_spawn_chaos_child: unknown flag {other}");
                std::process::exit(2);
            }
        }
    }

    Args {
        data_dir: data_dir.expect("--data-dir is required"),
        spawn_log_dir: spawn_log_dir.expect("--spawn-log-dir is required"),
        tree_number: tree_number.expect("--tree-number is required"),
        pause_at: pause_at.expect("--pause-at is required"),
    }
}

fn pause_until_killed(name: &str) -> ! {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{{\"paused_at\":\"{name}\"}}").expect("write sentinel");
    stdout.flush().expect("flush sentinel");
    drop(stdout);
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

fn build_fresh_state(params: &InspireParams) -> raven_railgun_engine::inspire::InspireServerState {
    let db: Vec<u8> = (0..TOY_ENTRIES)
        .flat_map(|i| (0..TOY_ENTRY_SIZE).map(move |j| u8::try_from((i + j) % 251).expect("< 251")))
        .collect();
    let (state, _sk) =
        setup_state(params, &db, TOY_ENTRY_SIZE, InspireVariant::TwoPacking).expect("setup_state");
    state
}

fn build_encoder() -> Arc<dyn PirTableEncoder> {
    EncoderKind::PerLeafBc
        .build(TOY_ENTRY_SIZE, ENTRIES_PER_SHARD)
        .expect("build per-leaf-bc encoder")
}

fn run(args: &Args) -> ! {
    let Args {
        data_dir,
        spawn_log_dir,
        tree_number,
        pause_at,
    } = args;

    eprintln!(
        "auto_spawn_chaos_child: data_dir={} spawn_log_dir={} tree={} pause_at={}",
        data_dir.display(),
        spawn_log_dir.display(),
        tree_number,
        pause_at.name()
    );

    std::fs::create_dir_all(data_dir).expect("create_dir_all data_dir");
    let layout = StoreLayout::open(data_dir).expect("StoreLayout::open data_dir");

    let params = InspireParams::secure_128_d2048();
    let encoder = build_encoder();
    let instance_id = InstanceId::new(instance_id_for_tree(*tree_number));
    let fresh_state_factory = {
        let params = params.clone();
        move || -> raven_railgun_core::Result<_> { Ok(build_fresh_state(&params)) }
    };
    let (instance, _persistence) = bootstrap_inspire_instance(
        layout,
        SCHEME_TAG,
        instance_id.clone(),
        InstanceRole::Live,
        SnapshotPolicy::default(),
        Arc::clone(&encoder),
        fresh_state_factory,
    )
    .expect("bootstrap_inspire_instance");

    if matches!(pause_at, PausePoint::BeforeAddLive) {
        pause_until_killed(pause_at.name());
    }

    let instance_arc: Arc<PirInstance<RavenInspireScheme>> = Arc::new(instance);
    let engine: Arc<Engine<RavenInspireScheme>> = Arc::new(Engine::new());
    engine
        .add_live(Arc::clone(&instance_arc))
        .expect("engine.add_live");

    if matches!(pause_at, PausePoint::AfterAddLiveBeforeLog) {
        pause_until_killed(pause_at.name());
    }

    let record = SpawnRecord {
        tree_number: *tree_number,
        instance_id: instance_id.to_string(),
        data_dir: data_dir.clone(),
        spawned_at_secs: 1_700_000_000_u64.saturating_add(u64::from(*tree_number)),
    };
    append_spawn_record(spawn_log_dir, &record).expect("append spawn record");

    if matches!(pause_at, PausePoint::AfterLog) {
        pause_until_killed(pause_at.name());
    }

    eprintln!(
        "auto_spawn_chaos_child: reached end-of-main without parking; \
         pause_at={} unhandled",
        pause_at.name()
    );
    std::process::exit(3);
}

fn main() {
    let args = parse_args();
    run(&args);
}

#[doc(hidden)]
pub fn pause_point_names() -> [&'static str; 3] {
    [
        PausePoint::BeforeAddLive.name(),
        PausePoint::AfterAddLiveBeforeLog.name(),
        PausePoint::AfterLog.name(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pause_point_round_trips_known_names() {
        for name in pause_point_names() {
            let parsed = PausePoint::parse(name).expect("parse known");
            assert_eq!(parsed.name(), name);
        }
    }

    #[test]
    fn parse_pause_point_rejects_unknown() {
        let err = PausePoint::parse("nonsense").expect_err("must reject");
        assert!(err.contains("nonsense"), "got: {err}");
    }
}
