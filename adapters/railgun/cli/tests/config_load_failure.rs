//! A config the node cannot load ends the process once, naming the file and the cause.
//!
//! Starting the process again is the supervisor's policy, and no binary can stop a supervisor
//! told to restart forever. What each start owes is one prompt failure that says why, so the
//! first log line an operator reads is the whole diagnosis.

#![allow(clippy::expect_used, clippy::panic)]

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The failure takes tens of milliseconds, so a start that outlives this is retrying or hung.
const EXIT_DEADLINE: Duration = Duration::from_secs(2);

/// Reaps at teardown only: the kill runs once the deadline has already failed the test.
struct Reap(Child);

impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Reap {
    fn exited(&mut self) -> Option<std::process::ExitStatus> {
        self.0.try_wait().expect("poll raven-railgun")
    }
}

fn assert_within_deadline(started: Instant, path: &Path) {
    assert!(
        started.elapsed() < EXIT_DEADLINE,
        "serve-production over {} still running after {EXIT_DEADLINE:?}; a config it cannot \
         load must end the process",
        path.display()
    );
}

/// How the config reaches the binary.
enum Delivery<'a> {
    File,
    /// Written once into a FIFO. A second read blocks in `open` with no writer, so any retry,
    /// however short or quiet, turns into a hang the deadline catches.
    FifoOnce(&'a str),
}

/// Opens the write end once the binary has opened the read end, then closes it after one body.
fn feed_once(path: &Path, body: &str, child: &mut Reap, started: Instant) {
    loop {
        match OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
        {
            Ok(mut writer) => {
                writer.write_all(body.as_bytes()).expect("write config");
                return;
            }
            Err(err) if err.raw_os_error() == Some(libc::ENXIO) => {}
            Err(err) => panic!("open {} for writing: {err}", path.display()),
        }
        if child.exited().is_some() {
            return;
        }
        assert_within_deadline(started, path);
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn serve_with_config(path: &Path, delivery: &Delivery<'_>) -> (i32, String) {
    let child = Command::new(env!("CARGO_BIN_EXE_raven-railgun"))
        .arg("serve-production")
        .arg("--config")
        .arg(path)
        .env_remove("RAVEN_BEARER_TOKEN")
        .env_remove("RAVEN_RPC_URL")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn raven-railgun");
    let mut child = Reap(child);
    let started = Instant::now();
    if let Delivery::FifoOnce(body) = delivery {
        feed_once(path, body, &mut child, started);
    }
    let status = loop {
        if let Some(status) = child.exited() {
            break status;
        }
        assert_within_deadline(started, path);
        std::thread::sleep(Duration::from_millis(5));
    };
    let mut stderr = String::new();
    child
        .0
        .stderr
        .take()
        .expect("piped stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    let code = status
        .code()
        .unwrap_or_else(|| panic!("ended by a signal, not an exit: {status:?}\n{stderr}"));
    (code, stderr)
}

fn assert_one_failure(path: &Path, delivery: &Delivery<'_>, stage: &str, cause: &str) {
    let (code, stderr) = serve_with_config(path, delivery);
    assert_ne!(code, 0, "{stderr}");
    let head = format!("{stage} config file: {}", path.display());
    assert_eq!(
        stderr.matches(&head).count(),
        1,
        "one failure naming `{head}`: {stderr}"
    );
    assert!(stderr.contains(cause), "the cause `{cause}`: {stderr}");
}

fn fifo(dir: &Path) -> PathBuf {
    let path = dir.join("mainnet.toml");
    let made = Command::new("mkfifo")
        .arg(&path)
        .status()
        .expect("spawn mkfifo");
    assert!(made.success(), "mkfifo {}: {made:?}", path.display());
    path
}

/// A wrong owner and a 0o000 mode both refuse the open with EACCES, so this one case covers both.
#[test]
fn an_unreadable_config_fails_once_naming_the_path_and_the_cause() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mainnet.toml");
    std::fs::write(&path, "[global]\n").expect("write config");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod 000");
    assert!(
        std::fs::read(&path).is_err(),
        "mode 0o000 does not deny this user (root?), so no unreadable file can be built here"
    );
    assert_one_failure(&path, &Delivery::File, "read", "Permission denied");
}

#[test]
fn a_malformed_config_fails_once_naming_the_path_and_the_cause() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = fifo(dir.path());
    assert_one_failure(
        &path,
        &Delivery::FifoOnce("[global\nbind = \"127.0.0.1:0\"\n"),
        "parse",
        "TOML parse error at line 1",
    );
}

#[test]
fn a_misspelt_key_fails_once_naming_the_path_and_the_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = fifo(dir.path());
    assert_one_failure(
        &path,
        &Delivery::FifoOnce("[global]\npoll_interval_secs = 1\n"),
        "parse",
        "unknown field `poll_interval_secs`",
    );
}
