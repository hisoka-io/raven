//! Single-instance production serve path.
//!
//! Shutdown order is load-bearing: drain in-flight requests, send
//! `ConsumerEvent::Shutdown` for a final `drive_commit`, then await the workers.

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
    /// Heartbeat session-eviction interval (seconds); `0` disables.
    pub session_eviction_interval_secs: u64,
    /// Expose `/metrics` without bearer auth; only safe behind a private firewall.
    pub metrics_public: bool,
    /// Mount one-query multi-shard fanout. Disabled unless explicitly enabled.
    pub enable_fanout: bool,
    /// Maximum shard ids accepted by one fanout request.
    pub max_fanout_shards: usize,
}

/// Per-leaf cell: 65,536 rows x 512 B (16 siblings x 32 B). Per-node encoders
/// derive a different shape from `TREE_DEPTH`.
pub const DEFAULT_PRODUCTION_ENTRIES: usize = 65_536;
pub const DEFAULT_PRODUCTION_ENTRY_BYTES: usize = 512;

const SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-cache-session";

/// Build the HTTP configuration used by the single-instance production path.
#[must_use]
pub fn build_http_config(opts: &ProductionServeOptions) -> HttpConfig {
    let mut config = HttpConfig::demo(opts.token.clone());
    config.max_concurrent_queries = opts.max_concurrent_queries;
    config.respond_timeout_secs = opts.respond_timeout_secs;
    config.metrics_public = opts.metrics_public;
    config.session_eviction_interval_secs = opts.session_eviction_interval_secs;
    config.enable_fanout = opts.enable_fanout;
    config.max_fanout_shards = opts.max_fanout_shards;
    config
}

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

pub async fn run_with_listener<F: std::future::Future<Output = ()> + Send + 'static>(
    opts: ProductionServeOptions,
    listener: tokio::net::TcpListener,
    shutdown: F,
) -> anyhow::Result<()> {
    const CONSUMER_DRAIN_SECS: u64 = 5;
    const WORKER_DRAIN_SECS: u64 = 12;
    // abort() only signals; the task drops at its next await, up to one RPC poll away.
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
    let params = InspireParams::secure_128_d2048();
    raven_railgun_engine::pir_table::validate_cell_shape(
        &opts.encoder,
        opts.entries,
        opts.entry_bytes,
        params.ring_dim,
    )
    .map_err(|e| anyhow::anyhow!("encoder cell shape rejected: {e}"))?;
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
    config.entries_per_shard = u32::try_from(opts.entries.min(params.ring_dim)).unwrap_or(u32::MAX);
    raven_railgun_engine::pir_table::validate_rows_per_shard(
        config.entries_per_shard,
        params.ring_dim,
    )
    .map_err(|e| anyhow::anyhow!("rows per shard rejected: {e}"))?;
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
    // Below the recovered manifest height the indexer re-scans a duplicate prefix.
    let manifest_block_height = handle.persistence.manifest_block_height();
    let recovered_floor = opts.start_block.max(manifest_block_height);
    let chain_backed = opts.encoder.chain_tree_number().is_some();
    let (recovered_block_height, reorg_window_required) = if chain_backed {
        let store = handle.logical_store.lock();
        (
            manifest_block_height.max(store.last_block_height()),
            manifest_block_height > 0 || store.last_block_height() > 0 || store.leaf_count() > 0,
        )
    } else {
        (0, false)
    };
    if recovered_floor > opts.start_block {
        tracing::info!(
            toml_start_block = opts.start_block,
            recovered_floor,
            "single-instance indexer start_block raised to recovered manifest height"
        );
    }
    let worker_config = IndexerWorkerConfig {
        start_block: recovered_floor,
        configured_start_block: opts.start_block,
        recovered_block_height,
        reorg_window_required,
        poll_interval_secs: DEFAULT_POLL_INTERVAL_SECS,
        reorg_window_path: chain_backed.then(|| opts.data_dir.join("indexer_reorg_window.bin")),
        ..IndexerWorkerConfig::default()
    };
    let indexer_handle = worker
        .spawn_reconciled(worker_config)
        .await
        .map_err(|error| anyhow::anyhow!("chain indexer startup reconciliation: {error}"))?;
    let mut indexer_task = AbortOnDropTask::new(indexer_handle);

    let http_config = build_http_config(&opts);

    let mut engine: Engine<raven_railgun_engine::inspire::RavenInspireScheme> = Engine::new();
    engine
        .register_instance(Arc::clone(&handle.instance))
        .map_err(|e| anyhow::anyhow!("register_instance: {e}"))?;

    let app_state =
        AppState::new(engine, http_config).map_err(|e| anyhow::anyhow!("AppState::new: {e}"))?;
    let app_state = app_state
        .require_consumer_metrics()
        .with_consumer_metrics(Arc::clone(&handle.metrics));
    let mut k_map: std::collections::HashMap<raven_railgun_core::InstanceId, u32> =
        std::collections::HashMap::new();
    k_map.insert(handle.instance.id.clone(), resolved_k);
    let app_state = app_state.with_instance_concurrency(k_map);
    // Emits the `instance="..."` label, not just the single-cell `consumer_metrics` shape.
    let mut instance_metrics: std::collections::HashMap<
        raven_railgun_core::InstanceId,
        Arc<parking_lot::Mutex<raven_railgun_engine::persistence::ConsumerMetrics>>,
    > = std::collections::HashMap::new();
    instance_metrics.insert(handle.instance.id.clone(), Arc::clone(&handle.metrics));
    let app_state = app_state.with_instance_metrics(instance_metrics);

    // After `AppState::new`, so the preflight counts into the recorder it installs.
    ensure_mirror_preflight_metrics_described();
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
    // Under data_dir so a restart resumes from the post-WAL-replay floor instead of
    // re-firing `expected list_index N, got 0..N-1`.
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
    // A chain cell serves chain rows whatever the list upstream does.
    preflight_mirror_upstream(
        &mirror,
        &list_key,
        chain_backed || fallback > 0,
        "--mirror-endpoint",
    )
    .await?;
    let mirror_handle = tokio::spawn(async move {
        if let Err(e) = mirror_clone
            .run_worker_with_cursor(list_key, 0, Some(cursor), mirror_tx)
            .await
        {
            tracing::error!(error = %e, "ppoi mirror worker exiting");
        }
    });
    let mut mirror_task = AbortOnDropTask::new(mirror_handle);

    let mut auxiliary_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    auxiliary_tasks.push(app_state.start_session_sweeper(std::time::Duration::from_secs(60)));
    auxiliary_tasks.push(app_state.start_packing_key_sweeper(std::time::Duration::from_secs(60)));

    // Bounds resident memory under bearer churn by dropping every live session.
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

    // Shutdown -> consumer final drive_commit -> receiver drop closes the bridges ->
    // workers exit. abort_handle is captured before the timeout consumes the JoinHandle.
    let indexer_handle = indexer_task
        .take()
        .ok_or_else(|| anyhow::anyhow!("indexer task handle missing during shutdown"))?;
    let mirror_handle = mirror_task
        .take()
        .ok_or_else(|| anyhow::anyhow!("PPOI mirror task handle missing during shutdown"))?;
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

    for task in auxiliary_tasks {
        task.abort();
        let _ = tokio::time::timeout(abort_await_deadline, task).await;
    }

    Ok(())
}

struct AbortOnDropTask<T> {
    handle: Option<tokio::task::JoinHandle<T>>,
}

impl<T> AbortOnDropTask<T> {
    fn new(handle: tokio::task::JoinHandle<T>) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    fn take(&mut self) -> Option<tokio::task::JoinHandle<T>> {
        self.handle.take()
    }
}

impl<T> Drop for AbortOnDropTask<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

/// Wait `drain_deadline`, then `abort()` and wait `abort_await_deadline` for
/// unwinding; dropping a JoinHandle only detaches.
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

/// Bound on the one request that decides whether the configured upstream can feed the mirror.
pub const MIRROR_PREFLIGHT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Boots that went on to serve local rows past an upstream that failed its preflight.
pub const MIRROR_PREFLIGHT_FAILED_TOTAL: &str = "raven_railgun_ppoi_mirror_preflight_failed_total";

pub(crate) fn ensure_mirror_preflight_metrics_described() {
    metrics::describe_counter!(
        MIRROR_PREFLIGHT_FAILED_TOTAL,
        metrics::Unit::Count,
        "Count of PPOI lists whose upstream failed the boot preflight while this node had \
         rows to serve, so it booted and serves them with no feed. Non-zero means the list \
         stops advancing until the upstream answers; the boot log names the endpoint and the \
         failure class."
    );
    metrics::counter!(MIRROR_PREFLIGHT_FAILED_TOTAL).increment(0);
}

/// One bounded request to the configured upstream, refused only when `can_serve_without_it`
/// is false. The worker warns and retries forever, so this is the one place a node with
/// nothing to serve can be stopped from booting clean and serving nothing. A node with rows
/// keeps serving: an upstream outage must not become this node's outage.
///
/// Counts into the recorder `AppState::new` installs, so it has to run after that.
pub(crate) async fn preflight_mirror_upstream(
    mirror: &raven_railgun_ppoi_mirror::UpstreamPpoiMirror,
    list: &ListKey,
    can_serve_without_it: bool,
    endpoint_setting: &str,
) -> anyhow::Result<()> {
    let Err(refusal) = mirror.preflight(list, MIRROR_PREFLIGHT_TIMEOUT).await else {
        return Ok(());
    };
    if !can_serve_without_it {
        anyhow::bail!(
            "{refusal}; this node holds no rows for list {} and would serve nothing: fix \
             {endpoint_setting}",
            hex::encode(list.0)
        );
    }
    metrics::counter!(MIRROR_PREFLIGHT_FAILED_TOTAL).increment(1);
    tracing::error!(
        error = %refusal,
        list_key = %hex::encode(list.0),
        "ppoi upstream failed its boot preflight; serving local rows with no feed"
    );
    Ok(())
}

/// Path-projection encoders own the path sidecar; every other kind uses the status
/// sidecar. The two feeds advance independently, so the wrong sidecar means the wrong
/// resume cursor after a restart.
///
/// **One derivation, both call sites.** This lived inline in `serve_production_multi.rs`
/// as well and the two drifted: the multi copy learned `PerListPath10` and this one did
/// not. Both entry points can construct every variant, so a second copy of this routing
/// decision is a wrong resume cursor on whichever path it lags.
pub(crate) fn mirror_kind_for_encoder(
    encoder: raven_railgun_engine::pir_table::EncoderKind,
) -> raven_railgun_ppoi_mirror::MirrorKind {
    use raven_railgun_engine::pir_table::EncoderKind;
    use raven_railgun_ppoi_mirror::MirrorKind;
    // EXHAUSTIVE on purpose. A `_` arm is what swallowed `PerListPath10` here while the
    // multi path handled it, and it was still swallowing `PerListNode`. Adding a variant
    // must now be a compile error that forces this decision, the way
    // `EncoderKind::chain_tree_number` already does.
    match encoder {
        // Driven by `PpoiListLeafAdded`: all three read the per-list IMT that arm writes.
        EncoderKind::PerListPath { .. }
        | EncoderKind::PerListPath10 { .. }
        | EncoderKind::PerListNode { .. } => MirrorKind::Path,
        // `PerListStatus` is driven by `PpoiStatus`. The three chain-tree encoders take no
        // mirror feed at all and only reach here via a `PpoiList*` data source, which they
        // cannot have; Status is the inert answer for them. Merged into one arm because
        // clippy::match_same_arms rejects splitting on documentation alone -- the point of
        // this match is that it is EXHAUSTIVE, not how the equal answers are grouped.
        EncoderKind::PerListStatus { .. }
        | EncoderKind::PerLeafBc { .. }
        | EncoderKind::PerLeafPath { .. }
        | EncoderKind::PerNode { .. } => MirrorKind::Status,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use raven_railgun_engine::pir_table::EncoderKind;
    use raven_railgun_ppoi_mirror::MirrorKind;

    /// The status and path feeds own SEPARATE sidecars and advance independently, so an
    /// encoder routed to the wrong one resumes from the wrong cursor after a restart.
    /// `serve_production_multi.rs:2349` already matched both path encoders; this single
    /// instance path matched only `PerListPath`, so `PerListPath10` fell through `_` to
    /// `Status`. One derivation now serves both call sites.
    #[test]
    fn every_path_projection_encoder_owns_the_path_sidecar() {
        let list_key = [7u8; 32];
        for encoder in [
            EncoderKind::PerListPath { list_key },
            EncoderKind::PerListPath10 { list_key },
            // The CLI's DEFAULT --ppoi-path-encoder, and it was routed to Status by the
            // old `_` arm. `PerListNodeEncoder::materialize_shard` reads the per-list IMT,
            // which only the `PpoiListLeafAdded` arm writes, so it is path-driven.
            EncoderKind::PerListNode { list_key },
        ] {
            assert_eq!(
                super::mirror_kind_for_encoder(encoder),
                MirrorKind::Path,
                "{encoder:?} drives PpoiListLeafAdded and must own the path sidecar"
            );
        }
    }

    #[test]
    fn non_path_encoders_keep_the_status_sidecar() {
        assert_eq!(
            super::mirror_kind_for_encoder(EncoderKind::PerListStatus {
                list_key: [7u8; 32]
            }),
            MirrorKind::Status
        );
    }

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
        let timed_out = tokio::time::timeout(std::time::Duration::from_millis(50), handle).await;
        assert!(timed_out.is_err(), "timeout must fire on infinite task");
        abort.abort();
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
