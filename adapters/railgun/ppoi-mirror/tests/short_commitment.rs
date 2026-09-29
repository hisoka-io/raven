//! Rows of the Sepolia OFAC list whose commitment upstream serves without its leading zero digits:
//! 62 or 63 hex digits, signed over that short string. Upstream's tree inserts the number they
//! spell, so the feed takes each as that 32-byte big-endian value, and checks the signature over
//! the string exactly as served. Past 64 digits, or not hex, a commitment is still refused.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use axum::routing::post;
use axum::{Json, Router};
use raven_railgun_core::ListKey;
use raven_railgun_persistence::WalEntryPayload;
use raven_railgun_ppoi_mirror::test_signer::TestListSigner;
use raven_railgun_ppoi_mirror::{
    FeedProgress, FeedStatus, MirrorConfig, MirrorError, PreflightFailure, UpstreamPpoiMirror,
};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

const OFAC_LIST_KEY: &str = "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";

/// A wait fails only when nothing changes for this long.
const STALL: Duration = Duration::from_secs(30);

/// `(index, blindedCommitment as served, validatedMerkleroot, signature)`, all Transact, from the
/// Sepolia OFAC list. 4364 is the first row served short. 4442 to 4444 are served short, and 4443
/// is 4440's commitment again, which 4440 carries at full width.
const SEPOLIA_ROWS: [(u64, &str, &str, &str); 6] = [
    (
        4364,
        "0x2fb9e05a0c268b6b8fce0952f6775101bc800c90a81e35dd3b30849709f9f4",
        "1aed52e9bd7ff247b6b3df58244807ec35cd137530286a64f4fd66b112cbcdbf",
        "b8819e58e7fa122dae1e55de652db2b9d049ff28558a59e13632da8def24b3444b1291e7756fc55e07065a1de5ab4bd430c435f4f943c03fe4c3963d619dd208",
    ),
    (
        4440,
        "0x00e63dbac492ba5394e1cd6fbd202d673d76369709ad6f576a2c846b03246324",
        "1eff10d620e0008e2110cd4fc6e8868042b6d0b39f259adbb91ba8751051b7e9",
        "9bcd38e4528bf34ccb1e18f428112a568f0c0c72ce6ad4c69b3424440167a9c7d170b6162358ca9df255e697300863d6e1f97ab0b6e3c25b1e1890819d28a60b",
    ),
    (
        4441,
        "0x21f8b9e16cf4857646b49db587f7e2b828a263061cdb80cb32ab9bb9cdcdfe52",
        "1d7723cc69707863521d0f27ac280e5b04f52c974edde71f776ed8c680f90e27",
        "db787cf5c505f5905d4c8fe550873464ee33742d082849b3f8781f962c802853fe04e20d52c2db984b368531119d8bf1e35e5cc9add1d788908ddf28005c3e08",
    ),
    (
        4442,
        "0x26ef563213c8c0379c15e6960b90deac09026e5559422cfd728679e0548989",
        "014d2c3cc1e90130e41135bd5bffa063a9ed6f96f1b88762fe1d1bd20f25a664",
        "f7d428e9f5bf41b79745a7fa26431cc3f6b712cd7631285f7b94aa3188a833a7494db32032e9d48b666f55711291a5b3db5d3622b9c189f1b158ec7ae23d960c",
    ),
    (
        4443,
        "0xe63dbac492ba5394e1cd6fbd202d673d76369709ad6f576a2c846b03246324",
        "10bdd3378314e5d04a6de8dba6217095862b2a8f1d407f8f569e228225c7202a",
        "3fc83331e31a3544dc49326cc73c9062ee182b04a40a8a422e7db075ead0e4fd69811ab98bd74dbd7e3c594817a5a07c8768f8c724037ee4a7fbb3e9d138ab02",
    ),
    (
        4444,
        "0x5e6612026f312d28512a5afc6fba74f39839dad7a0869a383bcede02e63ae69",
        "09adc358c4e14465d9604e22de01bcd0300f60976a8b92306ce878833f3d3f3a",
        "bb652396693c27bcb08e9b7d08e4524c00a1232cfa0d62209b31dd1f7b13890e928f822822ed1edd4e9d5cc72fc2d7794e184187d86e0627d52dcd4e2e813202",
    ),
];

fn bytes32(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).expect("ascii"), 16).expect("hex");
    }
    out
}

/// The commitment as 64 digits: what the row's leaf is.
fn full_width(served: &str) -> String {
    format!("{:0>64}", served.trim_start_matches("0x"))
}

fn sepolia_row(index: u64) -> Value {
    let (index, commitment, root, signature) = SEPOLIA_ROWS
        .iter()
        .copied()
        .find(|row| row.0 == index)
        .expect("a captured row");
    json!({
        "signedPOIEvent": {
            "index": index,
            "blindedCommitment": commitment,
            "signature": signature,
            "type": "Transact",
        },
        "validatedMerkleroot": root,
    })
}

/// Answers each page with the given rows whose index it covers.
async fn serve(rows: Vec<Value>) -> String {
    let rows = Arc::new(rows);
    let app = Router::new().route(
        "/",
        post(move |Json(request): Json<Value>| {
            let rows = Arc::clone(&rows);
            async move {
                let bound = |name: &str| request["params"][name].as_u64().expect("page bound");
                let range = bound("startIndex")..=bound("endIndex");
                let result: Vec<Value> = rows
                    .iter()
                    .filter(|row| {
                        range.contains(&row["signedPOIEvent"]["index"].as_u64().expect("index"))
                    })
                    .cloned()
                    .collect();
                Json(json!({ "jsonrpc": "2.0", "id": request["id"], "result": result }))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let endpoint = format!("http://{}", listener.local_addr().expect("local addr"));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    endpoint
}

fn mirror(endpoint: String) -> Arc<UpstreamPpoiMirror> {
    Arc::new(
        UpstreamPpoiMirror::new(MirrorConfig {
            endpoint,
            poll_interval_secs: 1,
            ..MirrorConfig::default()
        })
        .expect("mirror builds")
        .with_backfill_interval(Duration::ZERO),
    )
}

type Rx = tokio::sync::mpsc::Receiver<(WalEntryPayload, u64)>;

/// Feeds `list` over `span` from its start, until the feed stops or `done` holds.
async fn feed(
    mirror: Arc<UpstreamPpoiMirror>,
    list: ListKey,
    span: std::ops::Range<u64>,
    done: impl Fn(&FeedProgress) -> bool,
) -> (FeedProgress, Rx, Option<Result<(), MirrorError>>) {
    let status = FeedStatus::default();
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let end = span.end;
    let mut worker = tokio::spawn(mirror.run_feed(
        list,
        span.start,
        move |cursor| cursor..end,
        status.clone(),
        tx,
    ));
    let mut last = status.snapshot();
    let mut since = tokio::time::Instant::now();
    loop {
        tokio::select! {
            outcome = &mut worker => {
                return (status.snapshot(), rx, Some(outcome.expect("feed task")));
            }
            () = tokio::time::sleep(Duration::from_millis(20)) => {
                let now = status.snapshot();
                if done(&now) {
                    worker.abort();
                    return (now, rx, None);
                }
                if now == last {
                    assert!(since.elapsed() < STALL, "the feed stalled at {now:?}");
                } else {
                    (last, since) = (now, tokio::time::Instant::now());
                }
            }
        }
    }
}

fn leaves(rx: &mut Rx) -> Vec<(u64, [u8; 32])> {
    let mut out = Vec::new();
    while let Ok((payload, _)) = rx.try_recv() {
        if let WalEntryPayload::PpoiListLeafAdded {
            list_index,
            blinded_commitment,
            ..
        } = payload
        {
            out.push((u64::from(list_index), blinded_commitment));
        }
    }
    out
}

/// Every captured row verifies over its served string and reaches the engine as its 64-digit
/// number. 4440 and 4443, one commitment served at two widths, reach it as the same leaf.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rows_served_without_leading_zero_digits_verify_and_arrive_as_their_full_width_number() {
    assert!(SEPOLIA_ROWS
        .iter()
        .any(|row| row.1.trim_start_matches("0x").len() == 62));
    let endpoint = serve(SEPOLIA_ROWS.iter().map(|row| sepolia_row(row.0)).collect()).await;
    let mirror = mirror(endpoint);
    let list = ListKey(bytes32(OFAC_LIST_KEY));
    for span in [4364..4365, 4440..4445] {
        let (progress, mut rx, outcome) =
            feed(Arc::clone(&mirror), list, span.clone(), |progress| {
                progress.last_failure.is_some()
            })
            .await;
        assert!(
            matches!(outcome, Some(Err(MirrorError::Unheld { list_index })) if list_index == span.end),
            "{span:?}: the feed must take every row and stop after the last: {outcome:?} {progress:?}"
        );
        assert_eq!(progress.signatures_refused, 0, "{span:?}");
        let expected: Vec<(u64, [u8; 32])> = SEPOLIA_ROWS
            .iter()
            .filter(|row| span.contains(&row.0))
            .map(|row| (row.0, bytes32(&full_width(row.1))))
            .collect();
        let delivered = leaves(&mut rx);
        assert_eq!(delivered, expected, "{span:?}");
        if span.contains(&4443) {
            let leaf = |index| delivered.iter().find(|leaf| leaf.0 == index).unwrap().1;
            assert_eq!(leaf(4440), leaf(4443));
        }
    }
}

/// The signature covers the string as served, so the same number re-spelled at 64 digits is a
/// different signed message, and is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_short_commitment_padded_before_the_signature_check_would_fail_it() {
    let mut padded = sepolia_row(4442);
    padded["signedPOIEvent"]["blindedCommitment"] =
        json!(format!("0x{}", full_width(SEPOLIA_ROWS[3].1)));
    let endpoint = serve(vec![padded]).await;
    let (progress, mut rx, _) = feed(
        mirror(endpoint),
        ListKey(bytes32(OFAC_LIST_KEY)),
        4442..4443,
        |progress| progress.signatures_refused > 0,
    )
    .await;
    assert_eq!(
        progress.last_failure,
        Some(PreflightFailure::BadSignature(4442))
    );
    assert!(leaves(&mut rx).is_empty());
}

/// A signed commitment of 65 digits, or with a character that is not hex, is refused as rows
/// the mirror cannot ingest; one of 1 or 63 digits is taken.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_commitment_past_64_digits_or_not_hex_is_refused_though_signed() {
    let provider = TestListSigner::new(0x3c);
    let list = ListKey(provider.list_key());
    let full = "1f".repeat(32);
    for (commitment, accepted) in [
        (format!("0x{}", &full[1..]), true),
        ("0x7".to_owned(), true),
        (format!("0x0{full}"), false),
        (format!("0x{}g", &full[1..]), false),
    ] {
        let row = provider
            .row(0, &commitment, "Shield", &"aa".repeat(32))
            .expect("signs");
        let mirror = mirror(serve(vec![row]).await);
        let outcome = mirror.preflight(&list, STALL).await;
        if accepted {
            assert!(outcome.is_ok(), "{commitment}: {outcome:?}");
        } else {
            assert_eq!(
                outcome.map_err(|refusal| refusal.failure),
                Err(PreflightFailure::UndecodableRows),
                "{commitment}"
            );
        }
    }
}
