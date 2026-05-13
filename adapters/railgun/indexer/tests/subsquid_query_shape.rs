//! C6 regression: `SubsquidClient` must POST `{query, variables}` targeting the `Transaction`
//! entity, not the non-existent `commitmentBatches` field.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::print_stderr,
    clippy::format_push_string
)]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use parking_lot::Mutex;
use raven_railgun_indexer::subsquid::{SubsquidClient, SubsquidError, SubsquidRootSource};
use serde_json::{json, Value};
use tokio::sync::oneshot;

#[derive(Clone)]
struct MockState {
    captured: Arc<Mutex<Vec<Value>>>,
    response: Arc<Value>,
}

async fn handle(
    State(state): State<MockState>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    state.captured.lock().push(body);
    (StatusCode::OK, Json((*state.response).clone()))
}

async fn spawn_mock_gateway(response: Value) -> (SocketAddr, Arc<Mutex<Vec<Value>>>) {
    let captured: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let state = MockState {
        captured: captured.clone(),
        response: Arc::new(response),
    };
    let app = Router::new()
        .route("/graphql", post(handle))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock gateway");
    let addr = listener.local_addr().expect("local addr");
    let (ready_tx, ready_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = ready_tx.send(());
        let _ = axum::serve(listener, app).await;
    });
    ready_rx.await.expect("mock ready");
    (addr, captured)
}

#[tokio::test]
async fn subsquid_client_posts_variables_shaped_transaction_query() {
    let response = json!({
        "data": {
            "transactions": [
                {
                    "merkleRoot": "0xefc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88",
                    "blockNumber": "5944900",
                    "utxoTreeOut": "0",
                    "utxoBatchStartPositionOut": "30",
                    "commitments": ["0xaa", "0xbb"],
                }
            ]
        }
    });
    let (addr, captured) = spawn_mock_gateway(response).await;
    let client = SubsquidClient::new(format!("http://{addr}/graphql"));

    let r = client
        .commitment_root_at_height(0, 5_944_900)
        .await
        .expect("client decodes mock response");

    assert_eq!(r.tree_number, 0);
    assert_eq!(r.leaf_count, 32);
    assert_eq!(r.root[0], 0xef);
    assert_eq!(r.root[31], 0x88);

    let reqs = captured.lock().clone();
    assert_eq!(reqs.len(), 1, "exactly one POST expected");
    let body = &reqs[0];
    let q = body
        .get("query")
        .and_then(Value::as_str)
        .expect("body carries `query` string");
    assert!(
        q.contains("transactions("),
        "query must target Transaction entity: {q}"
    );
    assert!(
        !q.contains("commitmentBatches"),
        "query must NOT target the non-existent commitmentBatches field: {q}"
    );
    assert!(
        !q.contains("leafCount"),
        "schema has no leafCount scalar: {q}"
    );

    let vars = body
        .get("variables")
        .expect("body carries `variables` object");
    let vars = vars.as_object().expect("variables is an object");
    let tree = vars.get("tree").expect("`tree` variable present");
    let block = vars.get("block").expect("`block` variable present");
    assert!(
        tree.as_u64() == Some(0) || tree.as_str() == Some("0"),
        "tree variable must equal 0; got {tree:?}"
    );
    assert!(
        block.as_u64() == Some(5_944_900) || block.as_str() == Some("5944900"),
        "block variable must equal 5_944_900; got {block:?}"
    );
}

#[tokio::test]
async fn subsquid_client_surfaces_not_indexed_for_empty_transactions() {
    let response = json!({ "data": { "transactions": [] } });
    let (addr, _captured) = spawn_mock_gateway(response).await;
    let client = SubsquidClient::new(format!("http://{addr}/graphql"));
    let err = client
        .commitment_root_at_height(7, 1_000)
        .await
        .expect_err("empty transactions[] -> NotIndexed");
    assert!(
        matches!(&err, SubsquidError::NotIndexed(msg) if msg.contains("tree=7")),
        "got {err:?}"
    );
}

/// Spawn a TCP listener that accepts connections but never writes a response.
/// Without the explicit `SUBSQUID_REQUEST_TIMEOUT` configured on the client,
/// the call would hang indefinitely; with it, the client errors within ~30s.
async fn spawn_silent_tcp_sink() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind silent sink");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        loop {
            // Accept and hold; never read or write.
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                // Park the socket forever to ensure the client perceives a
                // fully-silent server.
                let _hold = stream;
                std::future::pending::<()>().await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn subsquid_client_times_out_on_silent_server() {
    let addr = spawn_silent_tcp_sink().await;
    let client = SubsquidClient::new(format!("http://{addr}/graphql"));

    // Bracket the call with a 60s wall-clock cap so the test fails fast if the
    // timeout is missing (without it, the call hangs forever and only the
    // outer test-runner timeout would kick in).
    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        client.commitment_root_at_height(0, 5_944_900),
    )
    .await
    .expect("must error inside 60s when 30s timeout is wired");
    let elapsed = started.elapsed();

    let err = outcome.expect_err("silent server must yield an error, not Ok");
    assert!(
        matches!(err, SubsquidError::Http(_) | SubsquidError::Decode(_)),
        "expected Http/Decode timeout error, got {err:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(45),
        "elapsed {elapsed:?} > 45s suggests the 30s timeout did not fire"
    );
}
