//! Cloudflare-cacheability regression suite for
//! `GET /v1/instance/{id}/params`.
//!
//! Pins the ETag + Cache-Control + Vary contract surfaced to public
//! caches, the `If-None-Match` 304-fast-path, and the per-instance
//! ETag cache invalidation on epoch advance.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::sync::PoisonError;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::{Epoch, InstanceId};
use raven_railgun_engine::inspire::{setup_state, RavenInspireScheme};
use raven_railgun_engine::{Engine, InstanceRole, PirInstance};
use raven_railgun_http::{AppState, HttpConfig};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use tower::ServiceExt;

const READ_TOKEN: &str = "BEARER-PARAMS-CACHE-padded-min-len-aabb";
const INSTANCE_ID: &str = "params-cache-instance";
const TOY_ENTRIES: usize = 256;
const TOY_ENTRY_BYTES: usize = 256;

/// Serialize across tests: `AppState::new` registers a process-global
/// Prometheus recorder. Mirrors the lock pattern in sibling tests.
static APPSTATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn build_engine() -> Engine<RavenInspireScheme> {
    let params = InspireParams::secure_128_d2048();
    let db: Vec<u8> = (0..TOY_ENTRIES)
        .flat_map(|i| {
            (0..TOY_ENTRY_BYTES).map(move |j| u8::try_from((i + j) % 251).expect("< 251"))
        })
        .collect();
    let (state, _sk) =
        setup_state(&params, &db, TOY_ENTRY_BYTES, InspireVariant::TwoPacking).expect("toy state");
    let mut engine: Engine<RavenInspireScheme> = Engine::new();
    let instance = PirInstance::new(InstanceId::new(INSTANCE_ID), InstanceRole::Live, state);
    engine.add_instance(instance).expect("register instance");
    engine
}

fn build_app_state() -> AppState<RavenInspireScheme> {
    let cfg = HttpConfig::demo(READ_TOKEN);
    let _g = APPSTATE_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    AppState::new(build_engine(), cfg).expect("appstate")
}

fn build_router(app_state: AppState<RavenInspireScheme>) -> axum::Router {
    raven_railgun_http::inspire_router(app_state).expect("router build")
}

/// `PeerIpKeyExtractor` (governor) requires `ConnectInfo<SocketAddr>`;
/// axum's `oneshot` doesn't install it, so inject one before dispatch.
fn install_connect_info(mut req: Request<Body>) -> Request<Body> {
    let addr: SocketAddr = "127.0.0.1:50101".parse().expect("addr");
    req.extensions_mut().insert(ConnectInfo(addr));
    req
}

fn build_params_request(token: &str) -> Request<Body> {
    install_connect_info(
        Request::builder()
            .method(Method::GET)
            .uri(format!("/v1/instance/{INSTANCE_ID}/params"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build req"),
    )
}

fn build_params_request_inm(token: &str, if_none_match: &str) -> Request<Body> {
    install_connect_info(
        Request::builder()
            .method(Method::GET)
            .uri(format!("/v1/instance/{INSTANCE_ID}/params"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::IF_NONE_MATCH, if_none_match)
            .body(Body::empty())
            .expect("build req"),
    )
}

async fn body_bytes(resp: axum::response::Response) -> Vec<u8> {
    resp.into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes()
        .to_vec()
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let hi = char::from_digit(u32::from(b >> 4), 16).unwrap_or('0');
        let lo = char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0');
        out.push(hi);
        out.push(lo);
    }
    out
}

/// Positive: ETag header is `"<sha256-hex>"` of the full body bytes,
/// emitted alongside `Cache-Control: public, max-age=86400, immutable`
/// and `Vary: Authorization`: the headers Cloudflare needs to cache
/// the body across origin epoch boundaries.
#[tokio::test]
async fn params_handler_emits_etag_and_immutable_cache_control() {
    let app_state = build_app_state();
    let router = build_router(app_state);
    let resp = router
        .oneshot(build_params_request(READ_TOKEN))
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    let etag = resp
        .headers()
        .get(header::ETAG)
        .expect("etag header present")
        .to_str()
        .expect("ascii etag")
        .to_owned();
    let cc = resp
        .headers()
        .get(header::CACHE_CONTROL)
        .expect("cache-control present")
        .to_str()
        .expect("ascii")
        .to_owned();
    let vary = resp
        .headers()
        .get(header::VARY)
        .expect("vary header present")
        .to_str()
        .expect("ascii")
        .to_owned();
    let body = body_bytes(resp).await;

    let digest = Sha256::digest(&body);
    let expected = format!("\"{}\"", hex_lower(digest.as_slice()));
    assert_eq!(etag, expected, "etag must be quoted hex sha256 of body");
    assert!(etag.starts_with('\"') && etag.ends_with('\"'));
    assert_eq!(etag.len(), 1 + 64 + 1);
    assert_eq!(cc, "public, max-age=86400, immutable");
    assert_eq!(vary, "Authorization");
}

/// Failure-injection: matching `If-None-Match` returns 304 with the
/// same ETag + Cache-Control + Vary headers and no body.
#[tokio::test]
async fn params_handler_returns_304_on_matching_if_none_match() {
    let app_state = build_app_state();
    let router = build_router(app_state);

    // First fetch to capture the live ETag.
    let resp1 = router
        .clone()
        .oneshot(build_params_request(READ_TOKEN))
        .await
        .expect("oneshot");
    assert_eq!(resp1.status(), StatusCode::OK);
    let etag = resp1
        .headers()
        .get(header::ETAG)
        .expect("etag")
        .to_str()
        .expect("ascii")
        .to_owned();

    // Re-fetch with If-None-Match equal to the captured ETag.
    let resp2 = router
        .oneshot(build_params_request_inm(READ_TOKEN, &etag))
        .await
        .expect("oneshot");
    assert_eq!(resp2.status(), StatusCode::NOT_MODIFIED);
    let etag2 = resp2
        .headers()
        .get(header::ETAG)
        .expect("etag on 304")
        .to_str()
        .expect("ascii");
    assert_eq!(etag2, etag, "304 must echo the same ETag");
    let cc = resp2
        .headers()
        .get(header::CACHE_CONTROL)
        .expect("cache-control on 304")
        .to_str()
        .expect("ascii");
    assert_eq!(cc, "public, max-age=86400, immutable");
    let vary = resp2
        .headers()
        .get(header::VARY)
        .expect("vary on 304")
        .to_str()
        .expect("ascii");
    assert_eq!(vary, "Authorization");
    let body = body_bytes(resp2).await;
    assert!(body.is_empty(), "304 body must be empty");
}

/// Positive: mismatched `If-None-Match` returns 200 with the full body
/// (not 304). Pins the round-trip ETag-mismatch path.
#[tokio::test]
async fn params_handler_returns_200_on_mismatching_if_none_match() {
    let app_state = build_app_state();
    let router = build_router(app_state);

    let resp = router
        .oneshot(build_params_request_inm(
            READ_TOKEN,
            "\"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"",
        ))
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let etag = resp
        .headers()
        .get(header::ETAG)
        .expect("etag")
        .to_str()
        .expect("ascii")
        .to_owned();
    assert_ne!(
        etag,
        "\"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\""
    );
    let body = body_bytes(resp).await;
    assert!(!body.is_empty(), "200 body must carry full payload");
}

/// Regression-guard: the per-instance ETag cache invalidates on
/// `swap_state` epoch bump. Forcing a fresh state with a new epoch
/// must yield a distinct ETag; a stale `If-None-Match` from the
/// pre-bump epoch must surface 200 (not 304).
#[tokio::test]
async fn params_handler_invalidates_etag_on_epoch_bump() {
    let app_state = build_app_state();

    // Capture handle on the live instance so we can drive swap_state
    // out-of-band before issuing the second request.
    let instance = app_state
        .engine
        .instance(&InstanceId::new(INSTANCE_ID))
        .expect("instance");
    let pre_epoch = instance.current_epoch();

    let router = build_router(app_state.clone());
    let resp1 = router
        .clone()
        .oneshot(build_params_request(READ_TOKEN))
        .await
        .expect("oneshot");
    assert_eq!(resp1.status(), StatusCode::OK);
    let etag_pre = resp1
        .headers()
        .get(header::ETAG)
        .expect("etag")
        .to_str()
        .expect("ascii")
        .to_owned();

    // Build a fresh InspireServerState and swap_state-bump the epoch.
    // The new state is bit-for-bit different from the boot state
    // (different DB contents) so the body bytes, and therefore the
    // SHA-256, must differ.
    let params = InspireParams::secure_128_d2048();
    let db_v2: Vec<u8> = (0..TOY_ENTRIES)
        .flat_map(|i| {
            (0..TOY_ENTRY_BYTES).map(move |j| u8::try_from((i + j + 7) % 251).expect("< 251"))
        })
        .collect();
    let (new_state, _sk) =
        setup_state(&params, &db_v2, TOY_ENTRY_BYTES, InspireVariant::TwoPacking)
            .expect("toy state v2");
    let next_epoch: Epoch = pre_epoch.next();
    instance.swap_state(new_state, next_epoch);
    assert_ne!(
        instance.current_epoch(),
        pre_epoch,
        "swap_state must bump epoch"
    );

    // Re-fetch with the now-stale ETag. The cache lookup keys on
    // (instance_id, epoch) so the old digest is unreachable; we get a
    // 200 with a fresh ETag rather than a 304.
    let resp2 = router
        .oneshot(build_params_request_inm(READ_TOKEN, &etag_pre))
        .await
        .expect("oneshot");
    assert_eq!(
        resp2.status(),
        StatusCode::OK,
        "stale If-None-Match from prior epoch must NOT short-circuit"
    );
    let etag_post = resp2
        .headers()
        .get(header::ETAG)
        .expect("etag")
        .to_str()
        .expect("ascii")
        .to_owned();
    assert_ne!(
        etag_pre, etag_post,
        "etag must change when the epoch advances"
    );

    // X-Raven-Epoch reflects the new epoch on the post-swap response.
    let epoch_hdr = resp2
        .headers()
        .get("x-raven-epoch")
        .expect("x-raven-epoch")
        .to_str()
        .expect("ascii");
    assert_eq!(epoch_hdr, next_epoch.0.to_string());
}
