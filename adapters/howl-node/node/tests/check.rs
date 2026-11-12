//! The endpoint check against a stub endpoint: a good one passes every check, and each
//! endpoint fault fails the check that names it and no other.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use howl_indexer::{TOPIC_LEAF_INSERTED, TOPIC_NEW_NOTE};
use howl_node::chain::{unhex, RpcChain};
use howl_node::check::{check, Expect, Finding};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const POOL: [u8; 20] = [0x11; 20];
const CHAIN_ID: u64 = 421_614;
const DEPLOYED: u64 = 1_000;
const HEAD: u64 = 5_000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fault {
    None,
    WrongChain,
    NoBlockHash,
    PrunedState,
    PrunedLogs,
    Unfiltered,
    NoPool,
}

fn hex(bytes: &[u8]) -> String {
    format!(
        "0x{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

fn hash_of(number: u64) -> [u8; 32] {
    Sha256::digest(number.to_be_bytes()).into()
}

fn number_of(hash: &[u8]) -> Option<u64> {
    (0..=HEAD).find(|n| hash_of(*n) == hash)
}

fn quantity(value: &Value) -> u64 {
    u64::from_str_radix(value.as_str().expect("hex").trim_start_matches("0x"), 16)
        .expect("quantity")
}

fn log(number: u64, topic: [u8; 32], address: [u8; 20]) -> Value {
    json!({
        "blockNumber": format!("0x{number:x}"),
        "blockHash": hex(&hash_of(number)),
        "logIndex": "0x0",
        "address": hex(&address),
        "topics": [hex(&topic)],
        "data": "0x",
        "removed": false,
    })
}

async fn endpoint(State(fault): State<Fault>, Json(request): Json<Value>) -> Json<Value> {
    let params = &request["params"];
    let error = |message: &str| {
        Json(
            json!({ "jsonrpc": "2.0", "id": request["id"], "error": { "code": -32000, "message": message } }),
        )
    };
    let result = match request["method"].as_str().expect("method") {
        "eth_chainId" => json!(format!(
            "0x{:x}",
            if fault == Fault::WrongChain {
                1
            } else {
                CHAIN_ID
            }
        )),
        "eth_blockNumber" => json!(format!("0x{HEAD:x}")),
        "eth_getBlockByNumber" => {
            let number = quantity(&params[0]);
            json!({
                "hash": hex(&hash_of(number)),
                "parentHash": hex(&hash_of(number.saturating_sub(1))),
            })
        }
        "eth_call" => {
            let Some(by_hash) = params[1]["blockHash"].as_str() else {
                return error("invalid block param");
            };
            if fault == Fault::NoBlockHash {
                return error("invalid argument 1: hex string has length 66, want 16");
            }
            let number = number_of(&unhex(by_hash).expect("hex")).expect("a known hash");
            if fault == Fault::PrunedState && HEAD - number > 16 {
                return error("missing trie node");
            }
            if fault == Fault::NoPool {
                json!("0x")
            } else {
                json!(hex(&[[0u8; 31].as_slice(), &[3]].concat()))
            }
        }
        "eth_getLogs" => {
            let from = quantity(&params[0]["fromBlock"]);
            let to = quantity(&params[0]["toBlock"]);
            if to - from >= 2_000 {
                return error("block range is too wide");
            }
            if fault == Fault::PrunedLogs && from < HEAD - 128 {
                return error("history has been pruned for this block");
            }
            let mut logs = vec![
                log(DEPLOYED, TOPIC_LEAF_INSERTED, POOL),
                log(DEPLOYED + 1, TOPIC_NEW_NOTE, POOL),
            ];
            if fault == Fault::Unfiltered {
                logs.push(log(DEPLOYED + 2, [0x77; 32], [0x22; 20]));
            }
            json!(logs)
        }
        other => return error(&format!("no {other}")),
    };
    Json(json!({ "jsonrpc": "2.0", "id": request["id"], "result": result }))
}

async fn run(fault: Fault) -> Vec<Finding> {
    let app = Router::new().route("/", post(endpoint)).with_state(fault);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    let chain = RpcChain::new(format!("http://{address}/"), POOL).expect("client");
    check(
        &chain,
        &Expect {
            chain_id: CHAIN_ID,
            pool: POOL,
            deployment_block: DEPLOYED,
            walk_blocks: 64,
        },
    )
    .await
}

fn failed(findings: &[Finding]) -> Vec<&'static str> {
    findings.iter().filter(|f| !f.ok).map(|f| f.name).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_usable_endpoint_passes_every_check() {
    let findings = run(Fault::None).await;
    assert_eq!(failed(&findings), Vec::<&str>::new(), "{findings:?}");
    let names: Vec<_> = findings.iter().map(|f| f.name).collect();
    assert_eq!(
        names,
        [
            "chain_id",
            "head",
            "call_by_hash",
            "state_at_walk_depth",
            "logs_from_deployment",
            "event_filter"
        ]
    );
    let logs = &findings[4].detail;
    assert!(
        logs.starts_with("blocks 1000..="),
        "halved to the range cap: {logs}"
    );
    assert!(
        findings[5].detail.contains("LeafInserted") && findings[5].detail.contains("NewNote"),
        "{findings:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn each_endpoint_fault_fails_the_check_that_names_it() {
    for (fault, names) in [
        (Fault::WrongChain, vec!["chain_id"]),
        (
            Fault::NoBlockHash,
            vec!["call_by_hash", "state_at_walk_depth"],
        ),
        (Fault::PrunedState, vec!["state_at_walk_depth"]),
        (Fault::PrunedLogs, vec!["logs_from_deployment"]),
        (Fault::Unfiltered, vec!["event_filter"]),
        (Fault::NoPool, vec!["call_by_hash", "state_at_walk_depth"]),
    ] {
        let findings = run(fault).await;
        assert_eq!(failed(&findings), names, "{fault:?}: {findings:?}");
    }
}
