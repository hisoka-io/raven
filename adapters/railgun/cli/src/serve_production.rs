//! Single-instance production serve path: wires persistence, chain indexer, PPOI mirror,
//! and axum HTTP server. On SIGINT/SIGTERM: drains in-flight requests, sends
//! `ConsumerEvent::Shutdown` for a final `drive_commit`, then waits for indexer + mirror workers.

#![allow(clippy::too_many_lines, clippy::missing_errors_doc)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::ListKey;
use raven_railgun_engine::inspire::setup_state;
use raven_railgun_engine::orchestrator::{bootstrap_railgun_engine, OrchestratorConfig};
use raven_railgun_engine::{Engine, InstanceRole};
use raven_railgun_http::{inspire_router, AppState, HttpConfig};

#[derive(Debug, Clone)]
pub struct ProductionServeOptions {
    pub bind: SocketAddr,
    pub token: String,
    pub rpc_url: String,
    pub railgun_proxy: String,
    pub chain_id: u64,
    pub start_block: u64,
    pub mirror_endpoint: String,
    pub list_key: String,
    pub data_dir: PathBuf,
    pub instance_id: String,
    pub max_concurrent_queries: usize,
    pub respond_timeout_secs: u64,
    pub entries: usize,
    pub entry_bytes: usize,
    pub encoder: raven_railgun_engine::pir_table::EncoderKind,
    /// Periodic heartbeat session-eviction interval (seconds). `0`
    /// disables. Default 3600. Mirrors the multi-instance binary so
    /// single-instance deployments also bound resident memory under
    /// sustained bearer churn.
    pub session_eviction_interval_secs: u64,
    /// Expose `/metrics` without bearer auth. Default-deny (`false`).
    /// When `true`, the scrape endpoint is unauthenticated; only safe
    /// behind a private-network firewall where bearer rotation is not
    /// a requirement.
    pub metrics_public: bool,
}

/// Locked production-cell shape: 65,536 × 512 B (16 Poseidon-Merkle siblings × 32 B).
pub const DEFAULT_PRODUCTION_ENTRIES: usize = 65_536;
pub const DEFAULT_PRODUCTION_ENTRY_BYTES: usize = 512;

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-cache-session";

pub async fn run(opts: ProductionServeOptions) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(opts.bind)
        .await
        .with_context(|| format!("bind {}", opts.bind))?;
    run_with_listener(opts, listener, signal_shutdown()).await
}

async fn signal_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(sig) => sig,
            Err(e) => {
                tracing::warn!(error = %e, "SIGTERM handler unavailable; waiting for SIGINT only");
                let _ = tokio::signal::ctrl_c().await;
                tracing::info!("SIGINT received; shutting down");
                return;
            }
        };
        tokio::select! {
            res = tokio::signal::ctrl_c() => {
                match res {
                    Ok(()) => tracing::info!("SIGINT received; shutting down"),
                    Err(e) => tracing::warn!(error = %e, "ctrl_c handler error; shutting down"),
                }
            }
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received; shutting down");
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("SIGINT received; shutting down");
    }
}

/// Bind- and shutdown-injected variant for tests.
pub async fn run_with_listener<F: std::future::Future<Output = ()> + Send + 'static>(
    opts: ProductionServeOptions,
    listener: tokio::net::TcpListener,
    shutdown: F,
) -> anyhow::Result<()> {
    const CONSUMER_DRAIN_SECS: u64 = 5;
    const WORKER_DRAIN_SECS: u64 = 12;
    // abort() is a signal; the task drops at its next await. 2 s covers RPC poll latency.
    const ABORT_AWAIT_SECS: u64 = 2;
    use alloy::primitives::Address;
    use raven_railgun_indexer::{
        ChainSource, IndexerWorker, IndexerWorkerConfig, RpcChainSource, DEFAULT_POLL_INTERVAL_SECS,
    };
    use raven_railgun_ppoi_mirror::{MirrorConfig, MirrorCursor, UpstreamPpoiMirror};

    let proxy_addr: Address = opts
        .railgun_proxy
        .parse()
        .with_context(|| format!("invalid --railgun-proxy: {}", opts.railgun_proxy))?;
    let list_key_bytes: [u8; 32] = parse_hex32(&opts.list_key).with_context(|| {
        format!(
            "invalid --list-key (must be 64 hex chars): {}",
            opts.list_key
        )
    })?;
    let list_key = ListKey(list_key_bytes);

    if opts.entries == 0 || opts.entry_bytes == 0 {
        anyhow::bail!(
            "production-cell shape must be non-zero (entries={}, entry_bytes={})",
            opts.entries,
            opts.entry_bytes
        );
    }
    raven_railgun_engine::pir_table::validate_total_entries(&opts.encoder, opts.entries)
        .map_err(|e| anyhow::anyhow!("encoder cell shape rejected: {e}"))?;
    let params = InspireParams::secure_128_d2048();
    let entries = opts.entries;
    let entry_bytes = opts.entry_bytes;
    let initial_db: Vec<u8> = (0..entries)
        .flat_map(|i| (0..entry_bytes).map(move |j| u8::try_from((i + j) % 251).unwrap_or(0)))
        .collect();

    let mut state_holder = Some(
        setup_state(
            &params,
            &initial_db,
            entry_bytes,
            InspireVariant::TwoPacking,
        )
        .map_err(|e| anyhow::anyhow!("setup_state: {e}"))?
        .0,
    );
    let factory = move || {
        state_holder.take().ok_or_else(|| {
            raven_railgun_core::AdapterError::Internal("factory called twice".into())
        })
    };

    let mut config = OrchestratorConfig::demo(opts.data_dir.clone(), &opts.instance_id);
    SCHEME_TAG.clone_into(&mut config.scheme_tag);
    config.role = InstanceRole::Live;
    config.encoder = opts.encoder;
    config.record_size = opts.entry_bytes;
    config.entries_per_shard = u32::try_from(opts.entries.min(2048)).unwrap_or(2048);
    config.max_concurrent_queries = Some(opts.max_concurrent_queries);
    let resolved_k = u32::try_from(config.resolved_max_concurrent_queries()).unwrap_or(u32::MAX);

    let handle = bootstrap_railgun_engine(config, params.clone(), factory)
        .map_err(|e| anyhow::anyhow!("bootstrap_railgun_engine: {e}"))?;

    let chain_source = Arc::new(RpcChainSource::new(
        opts.rpc_url.clone(),
        proxy_addr,
        opts.start_block,
        opts.chain_id,
    ));
    let head = chain_source
        .latest_block()
        .await
        .map_err(|e| anyhow::anyhow!("chain RPC unreachable: {e}"))?;
    tracing::info!(
        chain_head = head,
        start_block = opts.start_block,
        "chain RPC reachable"
    );

    let worker = IndexerWorker::new(
        Arc::clone(&chain_source),
        handle.channels.indexer_tx.clone(),
    );
    // Recovered baseline: never start the indexer below the manifest's
    // recovered chain-event height. A fresh-bootstrap returns 0 (so
    // `opts.start_block` wins); a recovered instance returns the
    // last committed `current_block_height` and the indexer resumes
    // there instead of silently re-scanning the prefix the consumer
    // task would only drop as duplicates.
    let recovered_floor = opts
        .start_block
        .max(handle.persistence.manifest_block_height());
    if recovered_floor > opts.start_block {
        tracing::info!(
            toml_start_block = opts.start_block,
            recovered_floor,
            "single-instance indexer start_block raised to recovered manifest height"
        );
    }
    let worker_config = IndexerWorkerConfig {
        start_block: recovered_floor,
        poll_interval_secs: DEFAULT_POLL_INTERVAL_SECS,
        ..IndexerWorkerConfig::default()
    };
    let indexer_handle = tokio::spawn(async move { worker.run(worker_config).await.map(|_| ()) });

    let mirror_config = MirrorConfig {
        endpoint: opts.mirror_endpoint.clone(),
        ..MirrorConfig::default()
    };
    let mirror = Arc::new(
        UpstreamPpoiMirror::new(mirror_config)
            .map_err(|e| anyhow::anyhow!("ppoi mirror constructor: {e}"))?,
    );
    let mirror_tx = handle.channels.mirror_tx.clone();
    let mirror_clone = Arc::clone(&mirror);
    // Cursor sidecar lives under the operator-provided data_dir so a
    // restart resumes from the post-WAL-replay floor rather than
    // re-firing `expected list_index N, got 0..N-1` on every startup.
    // Kind is dispatched from the configured encoder: per-list-path
    // encoders own the path sidecar; chain-tree encoders + status
    // encoders share the status sidecar by convention.
    let mirror_kind = mirror_kind_for_encoder(opts.encoder);
    let fallback = {
        let store = handle.logical_store.lock();
        #[allow(clippy::cast_possible_truncation)]
        let count = store
            .ppoi_imt(&list_key.0)
            .map_or(0u64, |imt| imt.leaf_count() as u64);
        count
    };
    let cursor = MirrorCursor::new(opts.data_dir.clone(), mirror_kind, fallback);
    let mirror_handle = tokio::spawn(async move {
        if let Err(e) = mirror_clone
            .run_worker_with_cursor(list_key, 0, Some(cursor), mirror_tx)
            .await
        {
            tracing::error!(error = %e, "ppoi mirror worker exiting");
        }
    });

    let mut http_config = HttpConfig::demo(opts.token.clone());
    http_config.max_concurrent_queries = opts.max_concurrent_queries;
    http_config.respond_timeout_secs = opts.respond_timeout_secs;
    http_config.metrics_public = opts.metrics_public;
    http_config.session_eviction_interval_secs = opts.session_eviction_interval_secs;

    let mut engine: Engine<raven_railgun_engine::inspire::RavenInspireScheme> = Engine::new();
    engine
        .register_instance(Arc::clone(&handle.instance))
        .map_err(|e| anyhow::anyhow!("register_instance: {e}"))?;

    let app_state =
        AppState::new(engine, http_config).map_err(|e| anyhow::anyhow!("AppState::new: {e}"))?;
    let app_state = app_state.with_consumer_metrics(Arc::clone(&handle.metrics));
    let mut k_map: std::collections::HashMap<raven_railgun_core::InstanceId, u32> =
        std::collections::HashMap::new();
    k_map.insert(handle.instance.id.clone(), resolved_k);
    let app_state = app_state.with_instance_concurrency(k_map);
    // Wire instance_metrics so `/metrics` emits `instance="..."`-labelled
    // gauges on the single-instance path too. Without this the scrape
    // endpoint serves only the legacy single-cell `consumer_metrics`
    // shape, hiding the per-instance label that dashboards expect.
    let mut instance_metrics: std::collections::HashMap<
        raven_railgun_core::InstanceId,
        Arc<parking_lot::Mutex<raven_railgun_engine::persistence::ConsumerMetrics>>,
    > = std::collections::HashMap::new();
    instance_metrics.insert(handle.instance.id.clone(), Arc::clone(&handle.metrics));
    let app_state = app_state.with_instance_metrics(instance_metrics);

    // Periodic session-map sweeper drops past-TTL entries even if the
    // bearer never repeats (a prior implementation carried the bug
    // forward; this closes it). Cadence is 60 s.
    let mut auxiliary_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    auxiliary_tasks.push(app_state.start_session_sweeper(std::time::Duration::from_secs(60)));

    // Heartbeat session eviction. `0` disables; default 3600 s. Bounds
    // resident memory under bearer churn at the cost of dropping every
    // live session once per interval. Symmetry with the multi-instance
    // binary.
    if opts.session_eviction_interval_secs > 0 {
        let instance = Arc::clone(&handle.instance);
        let instance_id = handle.instance.id.clone();
        let tick = std::time::Duration::from_secs(opts.session_eviction_interval_secs);
        let h = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tick);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker.tick().await; // drop the immediate t=0 tick.
            loop {
                ticker.tick().await;
                match raven_railgun_engine::inspire::heartbeat_session_eviction(&instance) {
                    Ok(()) => {
                        metrics::counter!(
                            "raven_railgun_session_eviction_swaps_total",
                            "instance" => instance_id.as_str().to_owned()
                        )
                        .increment(1);
                    }
                    Err(e) => {
                        tracing::warn!(
                            instance = instance_id.as_str(),
                            error = %e,
                            "heartbeat session eviction failed"
                        );
                    }
                }
            }
        });
        auxiliary_tasks.push(h);
    }

    let router = inspire_router(app_state).map_err(|e| anyhow::anyhow!("inspire_router: {e}"))?;
    let local_addr = listener
        .local_addr()
        .with_context(|| "listener local_addr")?;
    tracing::info!(
        bind = %local_addr,
        instance = %opts.instance_id,
        "raven-railgun production serve listening"
    );

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await?;

    // Shutdown order: send Shutdown -> consumer fires final drive_commit -> consumer receiver drop
    // closes indexer/mirror bridges -> workers exit at next tick. abort_handle is captured BEFORE
    // the timeout so a real abort() fires; dropping the JoinHandle would only detach the task.
    let indexer_abort = indexer_handle.abort_handle();
    let mirror_abort = mirror_handle.abort_handle();
    let _ = handle
        .sender
        .send(raven_railgun_engine::persistence::ConsumerEvent::Shutdown)
        .await;
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(CONSUMER_DRAIN_SECS),
        handle.consumer,
    )
    .await;

    let worker_deadline = std::time::Duration::from_secs(WORKER_DRAIN_SECS);
    let abort_await_deadline = std::time::Duration::from_secs(ABORT_AWAIT_SECS);
    drain_or_abort_worker(
        "indexer",
        indexer_handle,
        indexer_abort,
        worker_deadline,
        abort_await_deadline,
    )
    .await;
    drain_or_abort_worker(
        "ppoi mirror",
        mirror_handle,
        mirror_abort,
        worker_deadline,
        abort_await_deadline,
    )
    .await;

    // Auxiliary tasks (session sweeper, heartbeat ticker) run forever;
    // abort them on shutdown so the process exits cleanly.
    for task in auxiliary_tasks {
        task.abort();
        let _ = tokio::time::timeout(abort_await_deadline, task).await;
    }

    Ok(())
}

/// Wait `drain_deadline` for the worker to exit; if it hasn't, abort it and wait
/// `abort_await_deadline` for unwinding. Dropping a JoinHandle only detaches the task;
/// abort() is required for actual cancellation.
async fn drain_or_abort_worker<T>(
    name: &str,
    handle: tokio::task::JoinHandle<T>,
    abort: tokio::task::AbortHandle,
    drain_deadline: std::time::Duration,
    abort_await_deadline: std::time::Duration,
) {
    if tokio::time::timeout(drain_deadline, handle).await.is_ok() {
        return;
    }
    tracing::warn!(
        worker = name,
        drain_secs = drain_deadline.as_secs(),
        "worker did not exit within drain window; aborting"
    );
    abort.abort();
    // abort() returns immediately; JoinHandle was consumed by the timeout. Sleep so cancellation
    // can propagate; after this window the OS will reap the process.
    tokio::time::sleep(abort_await_deadline).await;
    tracing::warn!(
        worker = name,
        abort_await_secs = abort_await_deadline.as_secs(),
        "abort signal sent + waited; if task is still alive, OS will reap it"
    );
}

fn parse_hex32(s: &str) -> anyhow::Result<[u8; 32]> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    if trimmed.len() != 64 {
        anyhow::bail!("expected 64 hex chars, got {}", trimmed.len());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = trimmed
            .as_bytes()
            .get(i * 2)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("hex hi"))?;
        let lo = trimmed
            .as_bytes()
            .get(i * 2 + 1)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("hex lo"))?;
        let nib = |c: u8| -> anyhow::Result<u8> {
            match c {
                b'0'..=b'9' => Ok(c - b'0'),
                b'a'..=b'f' => Ok(c - b'a' + 10),
                b'A'..=b'F' => Ok(c - b'A' + 10),
                other => anyhow::bail!("invalid hex byte {other:#x}"),
            }
        };
        *byte = (nib(hi)? << 4) | nib(lo)?;
    }
    Ok(out)
}

/// Dispatch [`raven_railgun_ppoi_mirror::MirrorKind`] from the
/// configured encoder.
///
/// `per-list-path` owns the path sidecar; every other encoder kind
/// defaults to the status sidecar. Chain-tree encoders (`PerLeafBc`,
/// `PerLeafPath`, `PerNode`) still drive the single-list mirror feed
/// in the single-instance entry point and the status sidecar is the
/// canonical resume point there.
fn mirror_kind_for_encoder(
    encoder: raven_railgun_engine::pir_table::EncoderKind,
) -> raven_railgun_ppoi_mirror::MirrorKind {
    use raven_railgun_engine::pir_table::EncoderKind;
    use raven_railgun_ppoi_mirror::MirrorKind;
    match encoder {
        EncoderKind::PerListPath { .. } => MirrorKind::Path,
        _ => MirrorKind::Status,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    #[tokio::test]
    async fn drain_or_abort_helper_aborts_a_stuck_worker_within_window() {
        let stuck = tokio::spawn(async {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        });
        let abort = stuck.abort_handle();
        let started = std::time::Instant::now();
        super::drain_or_abort_worker(
            "stuck-test",
            stuck,
            abort,
            std::time::Duration::from_millis(50),
            std::time::Duration::from_millis(150),
        )
        .await;
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "drain_or_abort must return within bounded window; took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn timeout_then_abort_actually_cancels_the_task() {
        let handle = tokio::spawn(async {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        });
        let abort = handle.abort_handle();
        // Timeout fires; handle is consumed but the task is still running.
        let timed_out = tokio::time::timeout(std::time::Duration::from_millis(50), handle).await;
        assert!(timed_out.is_err(), "timeout must fire on infinite task");
        abort.abort();
        // Re-spawn to exercise the JoinError path directly (original handle is gone).
        let handle2 = tokio::spawn(async {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        });
        let abort2 = handle2.abort_handle();
        abort2.abort();
        let join_err = handle2
            .await
            .expect_err("aborted task must return JoinError");
        assert!(
            join_err.is_cancelled(),
            "JoinError must report is_cancelled=true after abort_handle.abort()"
        );
    }
}
