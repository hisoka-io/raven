//! Fault-injection child for the real `migrate-encoder` implementation.

#![allow(
    clippy::expect_used,
    clippy::print_stderr,
    clippy::print_stdout,
    reason = "subprocess test harness; an abort here is the failure report"
)]

use std::io::Write;
use std::path::PathBuf;

use raven_railgun_cli::migrate_encoder::{self, MigrationCheckpoint};
use raven_railgun_engine::pir_table::EncoderKind;

#[derive(Debug, Clone)]
struct Args {
    data_dir: PathBuf,
    target: EncoderKind,
    pause_at: MigrationCheckpoint,
}

fn parse_checkpoint(value: &str) -> Result<MigrationCheckpoint, String> {
    match value {
        "pre-re-encode" => Ok(MigrationCheckpoint::PreReEncode),
        "post-re-encode" => Ok(MigrationCheckpoint::PostReEncode),
        "pre-snapshot" => Ok(MigrationCheckpoint::PreSnapshot),
        "post-snapshot" => Ok(MigrationCheckpoint::PostSnapshot),
        "pre-manifest-bump" => Ok(MigrationCheckpoint::PreManifestBump),
        "post-manifest-bump" => Ok(MigrationCheckpoint::PostManifestBump),
        other => Err(format!("unknown --pause-at {other}")),
    }
}

fn parse_target(label: &str, tree_number: u32) -> Result<EncoderKind, String> {
    match label {
        "per-leaf-bc" => Ok(EncoderKind::PerLeafBc { tree_number }),
        "per-leaf-path" => Ok(EncoderKind::PerLeafPath { tree_number }),
        "per-node" => Ok(EncoderKind::PerNode { tree_number }),
        other => Err(format!("unsupported --target {other}")),
    }
}

fn parse_args() -> Args {
    let mut data_dir: Option<PathBuf> = None;
    let mut target_label: Option<String> = None;
    let mut pause_at: Option<MigrationCheckpoint> = None;
    let mut tree_number = 0u32;
    let mut arguments = std::env::args().skip(1);

    while let Some(flag) = arguments.next() {
        match flag.as_str() {
            "--data-dir" => {
                data_dir = Some(PathBuf::from(
                    arguments.next().expect("--data-dir requires a value"),
                ));
            }
            "--target" => {
                target_label = Some(arguments.next().expect("--target requires a value"));
            }
            "--pause-at" => {
                pause_at = Some(
                    parse_checkpoint(&arguments.next().expect("--pause-at requires a value"))
                        .expect("valid checkpoint name"),
                );
            }
            "--tree-number" => {
                tree_number = arguments
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

fn pause_until_killed(checkpoint: MigrationCheckpoint) -> ! {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{{\"checkpoint\":\"{}\"}}", checkpoint.as_str()).expect("write sentinel");
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
        args.pause_at.as_str()
    );

    migrate_encoder::run_with_checkpoint(&args.data_dir, args.target, |checkpoint| {
        if checkpoint == args.pause_at {
            pause_until_killed(checkpoint);
        }
    })
    .expect("real migrate-encoder run");

    eprintln!(
        "migrate_chaos_child: reached end-of-main without parking; pause_at={} unhandled",
        args.pause_at.as_str()
    );
    std::process::exit(3);
}
