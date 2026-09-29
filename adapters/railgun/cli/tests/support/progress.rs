//! Waits on a booted server that fail only when what they watch stops moving.
//!
//! A fixed window reds a correct run on a loaded box: the apply is fsync-bound and slows with
//! every other process writing. Progress is what separates a slow run from a stuck one.

// `#[path]`-included by several targets; each uses a different subset.
#![allow(dead_code, unreachable_pub)]

use std::fmt::Debug;
use std::time::Duration;

/// How long nothing a boot test watches may stay unchanged before the test fails.
pub const STALL: Duration = Duration::from_secs(120);

/// A stop budget no test's stop spends, so a stop waits for every final commit; the test bounds
/// that wait by progress, through [`until_stopped`].
pub const STOP_BUDGET_LIFTED: Duration = Duration::from_hours(24);

/// Polls `probe` until it returns a result. Fails only once the progress it reports alongside
/// has not changed for [`STALL`], naming what stalled and where it stood.
pub async fn until_done_or_stalled<P, T>(
    what: &str,
    mut probe: impl AsyncFnMut() -> (P, Option<T>),
) -> T
where
    P: PartialEq + Debug,
{
    let mut last: Option<P> = None;
    let mut unchanged_since = tokio::time::Instant::now();
    loop {
        let (progress, done) = probe().await;
        if let Some(done) = done {
            return done;
        }
        if last.as_ref() == Some(&progress) {
            assert!(
                unchanged_since.elapsed() < STALL,
                "{what}: stalled, nothing moved for {STALL:?}; last seen {progress:?}"
            );
        } else {
            last = Some(progress);
            unchanged_since = tokio::time::Instant::now();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Awaits a stopping server's task. Fails only once `progress`, which moves as each final commit
/// lands, has not changed for [`STALL`].
pub async fn until_stopped<T, P>(
    mut server: tokio::task::JoinHandle<T>,
    mut progress: impl FnMut() -> P,
) -> T
where
    P: PartialEq + Debug,
{
    until_done_or_stalled("the graceful stop", async || {
        (progress(), server.is_finished().then_some(()))
    })
    .await;
    (&mut server).await.expect("server task panicked")
}

/// Per instance, the commits it has made and the holders of its store: a final commit moves the
/// first, and a consumer that exits drops out of the second.
pub fn final_commit_progress(
    view: &raven_railgun_cli::serve_production_multi::BootstrapView,
) -> Vec<(u64, usize)> {
    view.instances
        .iter()
        .map(|instance| {
            (
                instance.metrics.lock().commits_fired,
                std::sync::Arc::strong_count(&instance.logical_store),
            )
        })
        .collect()
}
