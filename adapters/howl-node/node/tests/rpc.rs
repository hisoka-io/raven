//! The JSON-RPC chain source against an endpoint that answers like a node does: the table
//! it builds is the one built from the same chain read in-process, through a reorganisation.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

#[path = "../../../howl/indexer/tests/support/mod.rs"]
mod chain;
mod support;

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use chain::Fixture;
use howl_indexer::{
    RawLog, TOPIC_GENESIS_SEEDED, TOPIC_LEAF_INSERTED, TOPIC_NEW_NOTE, TOPIC_NEW_PRIVATE_MEMO,
};
use howl_node::chain::{unhex, Chain, RpcChain, SELECTOR_NEXT_LEAF_INDEX};
use howl_node::follow::Step;
use howl_node::http::{router, Served};
use howl_node::NodeConfig;
use raven_inspire_session::SessionStoreLimits;
use serde_json::{json, Value};
use support::{extend, fixture_tree, FakeChain, Http};

fn hex(bytes: &[u8]) -> String {
    format!(
        "0x{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

fn quantity(value: &Value) -> u64 {
    u64::from_str_radix(value.as_str().expect("hex").trim_start_matches("0x"), 16)
        .expect("quantity")
}

fn log_json(log: &RawLog) -> Value {
    json!({
        "blockNumber": format!("0x{:x}", log.block_number),
        "logIndex": format!("0x{:x}", log.log_index),
        "address": hex(&log.address),
        "topics": log.topics.iter().map(|t| hex(t)).collect::<Vec<_>>(),
        "data": hex(&log.data),
        "blockHash": hex(&[0u8; 32]),
        "removed": false,
    })
}

/// Answers the four methods the node calls from `chain`, checking the requests' shape.
async fn endpoint(
    State((chain, pool)): State<(FakeChain, [u8; 20])>,
    Json(request): Json<Value>,
) -> Json<Value> {
    let params = &request["params"];
    let result = match request["method"].as_str().expect("method") {
        "eth_blockNumber" => json!(format!("0x{:x}", chain.head().await.expect("head"))),
        "eth_getBlockByNumber" => {
            assert_eq!(params[1], json!(false));
            match chain.block_hash(quantity(&params[0])).await.expect("hash") {
                Some(hash) => json!({ "hash": hex(&hash), "number": params[0] }),
                None => Value::Null,
            }
        }
        "eth_getLogs" => {
            let filter = &params[0];
            assert_eq!(filter["address"], json!(hex(&pool)));
            let topics: Vec<String> = [
                TOPIC_LEAF_INSERTED,
                TOPIC_GENESIS_SEEDED,
                TOPIC_NEW_NOTE,
                TOPIC_NEW_PRIVATE_MEMO,
            ]
            .iter()
            .map(|t| hex(t))
            .collect();
            assert_eq!(filter["topics"], json!([topics]));
            let logs = chain
                .logs(quantity(&filter["fromBlock"]), quantity(&filter["toBlock"]))
                .await
                .expect("logs");
            // A real endpoint filters by address; the fixture also holds another contract's logs.
            json!(logs
                .iter()
                .filter(|l| l.address == pool)
                .map(log_json)
                .collect::<Vec<_>>())
        }
        "eth_call" => {
            assert_eq!(params[0]["to"], json!(hex(&pool)));
            assert_eq!(
                unhex(params[0]["data"].as_str().expect("data")).expect("hex"),
                SELECTOR_NEXT_LEAF_INDEX
            );
            let count = chain
                .leaf_count(quantity(&params[1]))
                .await
                .expect("count")
                .expect("some");
            let mut word = [0u8; 32];
            word[24..].copy_from_slice(&count.to_be_bytes());
            json!(hex(&word))
        }
        other => {
            return Json(
                json!({ "jsonrpc": "2.0", "id": request["id"], "error": { "code": -32601, "message": format!("no {other}") } }),
            )
        }
    };
    Json(json!({ "jsonrpc": "2.0", "id": request["id"], "result": result }))
}

async fn serve(chain: FakeChain, pool: [u8; 20]) -> String {
    let app = Router::new()
        .route("/", post(endpoint))
        .with_state((chain, pool));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    format!("http://{address}/")
}

fn config(dir: &std::path::Path, fixture: &Fixture) -> NodeConfig {
    NodeConfig {
        data_dir: dir.to_path_buf(),
        chain_id: fixture.chain_id,
        pool: fixture.pool,
        deployment_block: fixture.first_block,
        max_range: 25,
        sessions: SessionStoreLimits {
            max_sessions: 8,
            ttl: Duration::from_secs(60),
        },
        seed: Some([7; 32]),
    }
}

async fn follow<C: Chain>(
    follower: &mut howl_node::follow::Follower<C>,
    engine: &howl_node::engine::Engine,
) -> Vec<Step> {
    let mut steps = Vec::new();
    loop {
        assert!(
            steps.len() < 5_000,
            "no idle step after {} steps",
            steps.len()
        );
        let step = follower.step().await.expect("step");
        howl_node::publish(follower, engine, &step).expect("publish");
        let idle = matches!(step, Step::Idle { .. });
        steps.push(step);
        if idle {
            return steps;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_rpc_source_builds_the_table_the_chain_holds() {
    let fixture = Fixture::load();
    let (mut tree, _) = fixture_tree(&fixture);
    let ext = extend(fixture.pool, &mut tree, fixture.head + 1, 80, 9, 0x3c);
    let mut logs = fixture.logs.clone();
    logs.extend(ext.logs.clone());
    let chain = FakeChain::new(
        fixture.pool,
        fixture.first_block,
        logs.clone(),
        ext.last_block,
    );
    let url = serve(chain.clone(), fixture.pool).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let (mut follower, engine) = howl_node::open(
        &config(dir.path(), &fixture),
        RpcChain::new(url, fixture.pool).expect("client"),
    )
    .expect("open");
    follow(&mut follower, &engine).await;
    let reference_dir = tempfile::tempdir().expect("tempdir");
    let (mut reference, reference_engine) =
        howl_node::open(&config(reference_dir.path(), &fixture), chain.clone()).expect("open");
    follow(&mut reference, &reference_engine).await;
    let over_rpc = Http(router(Served::new(Arc::clone(&engine), 2)));
    let in_process = Http(router(Served::new(Arc::clone(&reference_engine), 2)));
    let path = "/howl/v1/sync?since=0&upper=0";
    assert_eq!(over_rpc.get(path).await, in_process.get(path).await);
    assert_eq!(over_rpc.answer(path).await.leaf_count, 160 + 80 * 9);

    // A reorganisation seen through the endpoint.
    let (mut fork_tree, _) = fixture_tree(&fixture);
    let fork_block = fixture.head + 1;
    let fork = extend(fixture.pool, &mut fork_tree, fork_block, 30, 5, 0x3d);
    chain.fork(fork_block, fork.logs);
    chain.set_head(fork.last_block);
    let steps = follow(&mut follower, &engine).await;
    assert!(
        matches!(steps.first(), Some(Step::Rewound { .. })),
        "{steps:?}"
    );
    follow(&mut reference, &reference_engine).await;
    assert_eq!(over_rpc.get(path).await, in_process.get(path).await);
    assert_eq!(over_rpc.answer(path).await.leaf_count, 160 + 30 * 5);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_endpoint_error_never_carries_the_url() {
    let secret = "http://127.0.0.1:9/key-0123456789abcdef/";
    let chain = RpcChain::new(secret.to_owned(), [1; 20]).expect("client");
    let error = chain.head().await.expect_err("nothing listens there");
    assert!(
        !error.to_string().contains("key-0123456789abcdef"),
        "{error}"
    );
    assert!(
        !format!("{error:?}").contains("key-0123456789abcdef"),
        "{error:?}"
    );
    assert!(!format!("{chain:?}").contains("key-0123456789abcdef"));
}
