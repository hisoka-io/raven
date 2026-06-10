//! Child binary for the snapshot save-time chaos harness (`tests/snapshot_chaos_save_two_rename.rs`).
//!
//! Runs the two-rename save pipeline with explicit per-step sleeps so the parent can
//! SIGKILL inside a chosen window and assert `Snapshot::load` recovers the correct payload.

#![allow(
    clippy::expect_used,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::cast_possible_truncation,
    clippy::panic,
    clippy::unwrap_used
)]

use raven_railgun_persistence::{Snapshot, SnapshotId, StoreLayout, SNAPSHOT_MAGIC};
use std::io::Write;
use std::time::Duration;

fn parse_hex(s: &str) -> Vec<u8> {
    let s = s.trim();
    if s.is_empty() {
        return Vec::new();
    }
    assert!(
        s.len() % 2 == 0,
        "hex payload must be even length, got {}",
        s.len()
    );
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut chunks = bytes.chunks_exact(2);
    for chunk in chunks.by_ref() {
        match chunk {
            [hi, lo] => out.push((decode_hex_nibble(*hi) << 4) | decode_hex_nibble(*lo)),
            _ => unreachable!("chunks_exact(2) yields only 2-element slices"),
        }
    }
    assert!(chunks.remainder().is_empty());
    out
}

fn decode_hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => 10 + (b - b'a'),
        b'A'..=b'F' => 10 + (b - b'A'),
        _ => panic!("non-hex byte: 0x{b:02x}"),
    }
}

#[derive(Debug)]
struct Args {
    data_dir: std::path::PathBuf,
    pause: Duration,
    base_payload: Vec<u8>,
    new_payload: Vec<u8>,
    id: u64,
}

fn parse_args() -> Args {
    let mut data_dir = None;
    let mut pause_ms = 200u64;
    let mut base_payload = Vec::new();
    let mut new_payload = Vec::new();
    let mut id = 1u64;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--data-dir" => {
                data_dir = Some(std::path::PathBuf::from(
                    args.next().expect("--data-dir requires value"),
                ));
            }
            "--pause-ms" => {
                pause_ms = args
                    .next()
                    .expect("--pause-ms requires value")
                    .parse()
                    .expect("pause-ms must be u64");
            }
            "--base-payload" => {
                base_payload = parse_hex(&args.next().expect("--base-payload requires value"));
            }
            "--new-payload" => {
                new_payload = parse_hex(&args.next().expect("--new-payload requires value"));
            }
            "--id" => {
                id = args
                    .next()
                    .expect("--id requires value")
                    .parse()
                    .expect("id must be u64");
            }
            other => panic!("unknown flag {other}"),
        }
    }
    Args {
        data_dir: data_dir.expect("--data-dir required"),
        pause: Duration::from_millis(pause_ms),
        base_payload,
        new_payload,
        id,
    }
}

fn main() {
    let args = parse_args();
    eprintln!(
        "snapshot_chaos_child: data_dir={} pause_ms={} base_len={} new_len={} id={}",
        args.data_dir.display(),
        args.pause.as_millis(),
        args.base_payload.len(),
        args.new_payload.len(),
        args.id,
    );
    std::fs::create_dir_all(&args.data_dir).expect("mkdir data_dir");
    let layout = StoreLayout::open(&args.data_dir).expect("open layout");

    let base = Snapshot::build(args.base_payload.clone(), SNAPSHOT_MAGIC);
    base.save(&layout, SnapshotId(args.id)).expect("base save");
    println!("READY_FOR_CHAOS");
    std::io::stdout().flush().ok();
    std::thread::sleep(args.pause);

    let new_snap = Snapshot::build(args.new_payload.clone(), SNAPSHOT_MAGIC);
    let final_dir = layout.snapshot_dir(SnapshotId(args.id));
    let tmp_dir = final_dir.with_extension("tmp");
    let final_old_tmp = final_dir.with_extension("old.tmp");

    let _ = std::fs::remove_dir_all(&tmp_dir);
    let _ = std::fs::remove_dir_all(&final_old_tmp);
    std::fs::create_dir_all(&tmp_dir).expect("mkdir tmp_dir");

    let header_bytes = bincode::serialize(&new_snap.header).expect("ser header");
    write_atomic_basic(&tmp_dir.join("header.bin"), &header_bytes);
    let body = wrap_payload(&new_snap.data);
    write_atomic_basic(&tmp_dir.join("data.bincode"), &body);

    println!("STAGED_TMP");
    std::io::stdout().flush().ok();
    std::thread::sleep(args.pause);

    std::fs::rename(&final_dir, &final_old_tmp).expect("step-1 rename");
    println!("AFTER_STEP_1");
    std::io::stdout().flush().ok();
    std::thread::sleep(args.pause);

    std::fs::rename(&tmp_dir, &final_dir).expect("step-2 rename");
    println!("AFTER_STEP_2");
    std::io::stdout().flush().ok();
    std::thread::sleep(args.pause);

    std::fs::remove_dir_all(&final_old_tmp).expect("step-3 remove");
    println!("AFTER_STEP_3");
    std::io::stdout().flush().ok();
    eprintln!("snapshot_chaos_child: completed save cleanly");
}

fn write_atomic_basic(path: &std::path::Path, bytes: &[u8]) {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp).expect("create tmp");
        f.write_all(bytes).expect("write tmp");
        f.sync_all().expect("fsync tmp");
    }
    std::fs::rename(&tmp, path).expect("rename tmp -> path");
}

#[cfg(feature = "zstd-compression")]
fn wrap_payload(p: &[u8]) -> Vec<u8> {
    zstd::bulk::compress(p, 3).expect("zstd compress")
}

#[cfg(not(feature = "zstd-compression"))]
fn wrap_payload(p: &[u8]) -> Vec<u8> {
    p.to_vec()
}
