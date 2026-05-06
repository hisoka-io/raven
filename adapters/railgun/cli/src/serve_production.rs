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
    use raven_railgun_ppoi_mirror::{MirrorConfig, UpstreamPpoiMirror};

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
    let worker_config = IndexerWorkerConfig {
        start_block: opts.start_block,
        poll_interval_secs: DEFAULT_POLL_INTERVAL_SECS,
        ..IndexerWorkerConfig::default()
    };
    let indexer_handle = tokio::spawn(async move { worker.run(worker_config).await.map(|_| ()) });

    let mirror_config = MirrorConfig {
        endpoint: opts.mirror_endpoint.clone(),
        ..MirrorConfig::default()
    };
    let mirror = Arc::new(UpstreamPpoiMirror::new(mirror_config));
    let mirror_tx = handle.channels.mirror_tx.clone();
    let mirror_clone = Arc::clone(&mirror);
    let mirror_handle = tokio::spawn(async move {
        if let Err(e) = mirror_clone.run_worker(list_key, 0, mirror_tx).await {
            tracing::error!(error = %e, "ppoi mirror worker exiting");
        }
    });

    let mut http_config = HttpConfig::demo(opts.token.clone());
    http_config.max_concurrent_queries = opts.max_concurrent_queries;
    http_config.respond_timeout_secs = opts.respond_timeout_secs;

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
