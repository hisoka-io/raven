//! `POST /session` derives server-side packing keys, the costliest thing an uncredentialed caller
//! can ask for. A flood of them must not delay `/v1/health/live`, which the container health
//! check polls: a probe that times out restarts a node that was only busy.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::print_stdout
)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use raven_inspire::inspiring::ClientPackingKeys;
use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::{setup_state, RavenInspireScheme};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance};
use raven_railgun_http::{inspire_router, write_versioned, AppState, HttpConfig};

const INSTANCE_ID: &str = "session-flood";
const ENTRIES: usize = 2048;
const ENTRY_BYTES: usize = 512;
const FLOODERS: usize = 8;
/// Two workers, as on a small container: a handful of blocked workers is all of them.
const SERVER_WORKERS: usize = 2;
const PROBE_EVERY: Duration = Duration::from_millis(10);
const FLOOD_FOR: Duration = Duration::from_secs(4);

struct Served {
    base: String,
    stop: tokio::sync::oneshot::Sender<()>,
    thread: std::thread::JoinHandle<()>,
}

/// The server on its own small runtime, so the client's flood tasks do not share its workers.
fn serve(config: HttpConfig) -> (Served, Vec<u8>) {
    let params = InspireParams::secure_128_d2048();
    let db = raven_railgun_testkit::toy_db(ENTRIES, ENTRY_BYTES);
    let (state, sk) =
        setup_state(&params, &db, ENTRY_BYTES, InspireVariant::TwoPacking).expect("toy state");
    let mut sampler = GaussianSampler::with_seed(params.sigma, 7);
    let keys = write_versioned(&ClientPackingKeys::generate(
        &sk,
        state.cache.pack_params(),
        state.crs.inspiring_w_seed,
        &mut sampler,
    ))
    .expect("serialize keys");
    let mut engine: Engine<RavenInspireScheme> = Engine::new();
    engine
        .add_instance(PirInstance::new(
            InstanceId::new(INSTANCE_ID),
            InstanceRole::Live,
            state,
        ))
        .expect("register instance");
    let router = inspire_router(AppState::new(engine, config).expect("appstate")).expect("router");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(SERVER_WORKERS)
            .enable_all()
            .build()
            .expect("server runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).expect("listener");
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                let _ = stopped.await;
            })
            .await
            .expect("serve");
        });
        runtime.shutdown_background();
    });
    (Served { base, stop, thread }, keys)
}

fn config() -> HttpConfig {
    let mut config = HttpConfig::demo("session-flood-read-token-padded");
    config.rate_limit_rps = 1_000_000;
    config.rate_limit_burst = 1_000_000;
    config
}

async fn probe_health(client: &reqwest::Client, base: &str, window: Duration) -> Vec<Duration> {
    let mut latencies = Vec::new();
    let end = Instant::now() + window;
    while Instant::now() < end {
        let started = Instant::now();
        let response = client
            .get(format!("{base}/v1/health/live"))
            .send()
            .await
            .expect("health request");
        assert!(response.status().is_success(), "{}", response.status());
        latencies.push(started.elapsed());
        tokio::time::sleep(PROBE_EVERY).await;
    }
    latencies.sort();
    latencies
}

fn quantile(sorted: &[Duration], q: f64) -> Duration {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss
    )]
    let index = ((sorted.len() as f64 - 1.0) * q).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

/// Each flooder re-handshakes under its own identity, so the flood costs a derivation per
/// request without filling the pool.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_flood_does_not_delay_the_health_probe() {
    let (served, keys) = serve(config());
    let client = reqwest::Client::new();
    let idle = probe_health(&client, &served.base, Duration::from_secs(1)).await;

    let running = Arc::new(AtomicBool::new(true));
    let established = Arc::new(AtomicUsize::new(0));
    let flooders: Vec<_> = (0..FLOODERS)
        .map(|index| {
            let (client, running, established) = (
                client.clone(),
                Arc::clone(&running),
                Arc::clone(&established),
            );
            let (url, keys) = (
                format!("{}/v1/instance/{INSTANCE_ID}/session", served.base),
                keys.clone(),
            );
            tokio::spawn(async move {
                while running.load(Ordering::Relaxed) {
                    let response = client
                        .post(&url)
                        .header("content-type", "application/octet-stream")
                        .header("x-raven-client-id", format!("{:032x}", 0xf100 + index))
                        .body(keys.clone())
                        .send()
                        .await
                        .expect("session request");
                    if response.status().is_success() {
                        established.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let flooded = probe_health(&client, &served.base, FLOOD_FOR).await;
    running.store(false, Ordering::Relaxed);
    for flooder in flooders {
        flooder.await.expect("flooder");
    }
    let _ = served.stop.send(());
    served.thread.join().expect("server thread");

    let (idle_p50, idle_p99) = (quantile(&idle, 0.5), quantile(&idle, 0.99));
    let (p50, p99) = (quantile(&flooded, 0.5), quantile(&flooded, 0.99));
    let handshakes = established.load(Ordering::Relaxed);
    println!(
        "health idle p50={idle_p50:?} p99={idle_p99:?}; under a {FLOODERS}-way /session flood \
         p50={p50:?} p99={p99:?} over {} probes; {handshakes} handshakes completed",
        flooded.len()
    );
    assert!(handshakes > 0, "the flood never derived a key set");
    assert!(
        p99 < Duration::from_millis(100),
        "health p99 {p99:?} under a /session flood (p50 {p50:?}, idle p99 {idle_p99:?})"
    );
}

/// One derivation permit and a 1 ms wait: a concurrent burst is answered, part of it 503 at
/// once, rather than queued behind every derivation ahead of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_handshake_waits_a_bounded_time_for_a_derivation_permit() {
    const BURST: usize = 8;
    let mut config = config();
    config.max_concurrent_handshakes = 1;
    config.respond_permit_wait_ms = 1;
    let (served, keys) = serve(config);
    let client = reqwest::Client::new();
    let url = format!("{}/v1/instance/{INSTANCE_ID}/session", served.base);
    let burst: Vec<_> = (0..BURST)
        .map(|index| {
            let request = client
                .post(&url)
                .header("content-type", "application/octet-stream")
                .header("x-raven-client-id", format!("{:032x}", 0xf200 + index))
                .body(keys.clone())
                .send();
            tokio::spawn(async move { request.await.expect("session request").status() })
        })
        .collect();
    let mut statuses = Vec::new();
    for request in burst {
        statuses.push(request.await.expect("burst request"));
    }
    let _ = served.stop.send(());
    served.thread.join().expect("server thread");

    let admitted = statuses.iter().filter(|s| s.is_success()).count();
    let refused = statuses
        .iter()
        .filter(|s| **s == reqwest::StatusCode::SERVICE_UNAVAILABLE)
        .count();
    assert!(admitted >= 1, "{statuses:?}");
    assert!(
        refused >= 1,
        "a burst of {BURST} against one permit and a 1 ms wait must refuse some: {statuses:?}"
    );
    assert_eq!(admitted + refused, BURST, "{statuses:?}");
}
