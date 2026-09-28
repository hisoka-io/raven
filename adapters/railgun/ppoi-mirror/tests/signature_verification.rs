//! Rows of the live OFAC list, as the public aggregator served them, checked at ingest against
//! the list key.
//!
//! The provider signs the UTF-8 of `JSON.stringify({index, blindedCommitment, type})` over the
//! strings it serves. Most commitments come with `0x`; five Unshield rows come without it and are
//! signed without it, so a verifier that normalised the string first would refuse real rows. A row
//! whose signature, index, type or commitment differs from what was signed, or whose signature is
//! not 64 bytes of hex, must be refused by index, counted, and never delivered, and the feed must
//! ask for it again.

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
use raven_railgun_ppoi_mirror::{
    FeedProgress, FeedStatus, MirrorConfig, MirrorError, PreflightFailure, UpstreamPpoiMirror,
    TRUST_STATEMENT, UNVERIFIED_TRUST_STATEMENT,
};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

const OFAC_LIST_KEY: &str = "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";

/// A wait fails only when nothing changes for this long.
const STALL: Duration = Duration::from_secs(30);

/// `(index, type, blindedCommitment as served, signature)`. The first four carry `0x` and cover
/// every event type; the last five are the rows upstream serves without it.
const REAL_ROWS: [(u64, &str, &str, &str); 9] = [
    (
        0,
        "Unshield",
        "0x17742644f64a17b601fc4aab4be04c4d0d8d730a23fcb27463b6e8c13020f20f",
        "0bbfe679b12a186df95e92f263903757207fbea882ac00108beb677fdd6851d8f3705aadf94b65a3ce8e84b12eaa499cd5041ae70d3ebac7e7e9361af1bae900",
    ),
    (
        1,
        "Shield",
        "0x2a091023e8878f43fda97bc809ba4bd9557e60cf829d63df107d6451693438d2",
        "99cb342afb3ebc952119d93552647d5f2d3d8867c5797745e461bd42e48fa7974cfbd1af863cb68523a3bc318f6e70acd6dadc7d1aa0641aabde1332ace3580a",
    ),
    (
        5155,
        "LegacyTransact",
        "0x22c847c67848d5e4fa33be34da57205521f18ba29799362034ff1b72ec1bbd35",
        "24fb293b24c1695d027d445e6d1b9eec6ba915b29f5a0846266cc37497076be9e8779c118829b07697318d221732e170a1fd28dd0c18b28b9b8800f87c79620f",
    ),
    (
        5175,
        "Transact",
        "0x1a960b3384948018454eeafc213b7416744f3a354b06190e17600d833bc1c5bc",
        "15a956773083f2e39a2e98488efc22e23ef3c9701c284cfb516d6de685e4a9c25b4e03ea854c5e2ffaa08454643070179ece5a5cc39f66b89975d9b0f373ba09",
    ),
    (
        301_593,
        "Unshield",
        "0141bf51df82a72e6bb6bea220cca42a53a246f4ec1b9ef5f36641db86090278",
        "4fe008b80736f2016adef75aaab699700c227005b80b01ad64a44b692ca2a993db69b4219ebaab9b749049615c4ed55f13ce27043f8961f709506368f6f6c109",
    ),
    (
        319_007,
        "Unshield",
        "2c99ca77b25ddc3f58d86ea1c1ccadaed11975abd0a5f330936c177bc7df98ed",
        "4f8061ab2ce2a208276842f7523219d5734cfcf56fe1afe2e00c40a6d969e6220aaad134ae7b39d17f035967926d850ba4cfbadceb4c68bc3d643398b4988507",
    ),
    (
        319_013,
        "Unshield",
        "2a0cfb981396aa496a8ef846ccb049ffe244b134a45d87c0a08e0135e2bee919",
        "1cd721ae8ccd029ef415587a525e78bd546a51d66e1e2741fca13cae3ec434de58dc58f211109a63737308bcff0bdcee2cb191084757cfffec38e2122a4e5c03",
    ),
    (
        319_232,
        "Unshield",
        "0cf98c721cd9c445427cfc483d5b614f437b0b23d4f548229f2a70060a2aba48",
        "28f2af2c7a177943014af9a77afeaa75d8f97f873effdc2347a9be207ad766f6cea8d9ee151c4f3d70fa06497757d822881edb356bdc57915c95e9086282ac09",
    ),
    (
        319_520,
        "Unshield",
        "11c7ddb962068079e30bf620614cf4f1279d61d9998d93d6e9e94a404e96a82f",
        "b0274f3413c4da010001e1b7696356bed7b9ea977a36df9657aedba19b6d1a615efdf2696d82d167278c5ba86a3d0bef765fe93c41d77155ef058e43aba8d80a",
    ),
];

fn list_key() -> ListKey {
    let mut key = [0u8; 32];
    for (byte, pair) in key.iter_mut().zip(OFAC_LIST_KEY.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).expect("ascii"), 16).expect("hex");
    }
    ListKey(key)
}

/// A served row. The root is not signed; any non-zero root decodes.
fn wire_row(index: u64, event_type: &str, commitment: &str, signature: &str) -> Value {
    json!({
        "signedPOIEvent": {
            "index": index,
            "blindedCommitment": commitment,
            "signature": signature,
            "type": event_type,
        },
        "validatedMerkleroot": "aa".repeat(32),
    })
}

fn real(index: u64) -> Value {
    let (index, event_type, commitment, signature) = REAL_ROWS
        .iter()
        .copied()
        .find(|row| row.0 == index)
        .expect("a real row");
    wire_row(index, event_type, commitment, signature)
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

fn mirror(endpoint: String, verify_signatures: bool) -> Arc<UpstreamPpoiMirror> {
    Arc::new(
        UpstreamPpoiMirror::new(MirrorConfig {
            endpoint,
            poll_interval_secs: 1,
            verify_signatures,
            ..MirrorConfig::default()
        })
        .expect("mirror builds")
        .with_backfill_interval(Duration::ZERO),
    )
}

type Rx = tokio::sync::mpsc::Receiver<(WalEntryPayload, u64)>;

/// Feeds the one row at `index`, from a cursor on it, until the feed stops or `done` holds.
async fn feed_one(
    mirror: Arc<UpstreamPpoiMirror>,
    index: u64,
    done: impl Fn(&FeedProgress) -> bool,
) -> (FeedProgress, Rx, Option<Result<(), MirrorError>>) {
    let status = FeedStatus::default();
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    let end = index + 1;
    let mut feed = tokio::spawn(mirror.run_feed(
        list_key(),
        index,
        move |cursor| cursor..end,
        status.clone(),
        tx,
    ));
    let mut last = status.snapshot();
    let mut since = tokio::time::Instant::now();
    loop {
        tokio::select! {
            outcome = &mut feed => {
                return (status.snapshot(), rx, Some(outcome.expect("feed task")));
            }
            () = tokio::time::sleep(Duration::from_millis(20)) => {
                let now = status.snapshot();
                if done(&now) {
                    feed.abort();
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

fn leaves(rx: &mut Rx) -> Vec<(u32, [u8; 32])> {
    let mut out = Vec::new();
    while let Ok((payload, _)) = rx.try_recv() {
        if let WalEntryPayload::PpoiListLeafAdded {
            list_index,
            blinded_commitment,
            ..
        } = payload
        {
            out.push((list_index, blinded_commitment));
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_real_row_verifies_under_the_list_key_the_unprefixed_five_included() {
    let endpoint = serve(REAL_ROWS.iter().map(|row| real(row.0)).collect()).await;
    let mirror = mirror(endpoint, true);
    for (index, _, commitment, _) in REAL_ROWS {
        let (progress, mut rx, outcome) = feed_one(Arc::clone(&mirror), index, |progress| {
            progress.signatures_refused > 0
        })
        .await;
        assert!(
            matches!(outcome, Some(Err(MirrorError::Unheld { list_index })) if list_index == index + 1),
            "row {index}: the feed must take the row and stop after it: {outcome:?} {progress:?}"
        );
        assert_eq!(
            (
                progress.signatures_refused,
                progress.last_failure,
                progress.rows_delivered
            ),
            (0, None, 1),
            "row {index}"
        );
        let delivered = leaves(&mut rx);
        assert_eq!(delivered.len(), 1, "row {index}");
        let digits = commitment.trim_start_matches("0x");
        let expected: Vec<u8> = (0..32)
            .map(|at| u8::from_str_radix(&digits[at * 2..at * 2 + 2], 16).expect("hex"))
            .collect();
        assert_eq!(
            (u64::from(delivered[0].0), delivered[0].1.to_vec()),
            (index, expected)
        );
    }
}

fn flip_hex_digit(text: &str, at: usize) -> String {
    let mut chars: Vec<char> = text.chars().collect();
    chars[at] = if chars[at] == '0' { '1' } else { '0' };
    chars.into_iter().collect()
}

/// Each tampering of a real row, served at the index the feed asks for.
fn tampered_rows() -> Vec<(&'static str, u64, Value)> {
    let (_, event_type, commitment, signature) = REAL_ROWS[4];
    let (_, prefixed_type, prefixed, prefixed_signature) = REAL_ROWS[1];
    vec![
        (
            "a flipped signature",
            301_593,
            wire_row(
                301_593,
                event_type,
                commitment,
                &flip_hex_digit(signature, 10),
            ),
        ),
        (
            "a row moved to the next index",
            301_594,
            wire_row(301_594, event_type, commitment, signature),
        ),
        (
            "another event type",
            301_593,
            wire_row(301_593, "Shield", commitment, signature),
        ),
        (
            "a flipped commitment",
            301_593,
            wire_row(
                301_593,
                event_type,
                &flip_hex_digit(commitment, 5),
                signature,
            ),
        ),
        (
            "an unprefixed commitment given 0x",
            301_593,
            wire_row(301_593, event_type, &format!("0x{commitment}"), signature),
        ),
        (
            "a truncated signature",
            301_593,
            wire_row(301_593, event_type, commitment, &signature[..126]),
        ),
        (
            "an empty signature",
            301_593,
            wire_row(301_593, event_type, commitment, ""),
        ),
        (
            "a signature that is not hex",
            301_593,
            wire_row(
                301_593,
                event_type,
                commitment,
                &format!("zz{}", &signature[2..]),
            ),
        ),
        (
            "a prefixed commitment stripped of 0x",
            1,
            wire_row(
                1,
                prefixed_type,
                prefixed.trim_start_matches("0x"),
                prefixed_signature,
            ),
        ),
    ]
}

/// The feed refuses the row by index, counts it, sends nothing, keeps its cursor on the row, and
/// asks for it again: a second refusal is the proof it came back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tampered_row_is_refused_by_index_counted_and_never_delivered() {
    for (case, index, row) in tampered_rows() {
        let mirror = mirror(serve(vec![row]).await, true);
        // Every failed request counts, a refusal or not, so two of them end the wait either way.
        let (progress, mut rx, outcome) =
            feed_one(mirror, index, |progress| progress.consecutive_failures >= 2).await;
        assert!(outcome.is_none(), "{case}: the feed stopped: {outcome:?}");
        assert_eq!(
            (
                progress.last_failure,
                progress.next_index,
                progress.rows_delivered
            ),
            (Some(PreflightFailure::BadSignature(index)), index, 0),
            "{case}"
        );
        assert!(progress.signatures_refused >= 2, "{case}: {progress:?}");
        assert!(leaves(&mut rx).is_empty(), "{case}: a refused row was sent");
    }
}

/// Below a refused row the page is taken; the row itself and everything past it are not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rows_below_a_refused_row_are_taken_and_the_rest_wait_for_it() {
    let (_, event_type, commitment, signature) = REAL_ROWS[1];
    let endpoint = serve(vec![
        real(0),
        wire_row(1, event_type, commitment, &flip_hex_digit(signature, 0)),
    ])
    .await;
    let status = FeedStatus::default();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let feed = tokio::spawn(mirror(endpoint, true).run_feed(
        list_key(),
        0,
        |cursor| cursor..u64::MAX,
        status.clone(),
        tx,
    ));
    tokio::time::timeout(STALL, async {
        while status.snapshot().signatures_refused == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the forged row is refused");
    feed.abort();
    let progress = status.snapshot();
    assert_eq!(
        (
            progress.next_index,
            progress.rows_delivered,
            progress.upstream_rows
        ),
        (1, 1, None)
    );
    assert_eq!(
        leaves(&mut rx)
            .iter()
            .map(|leaf| leaf.0)
            .collect::<Vec<_>>(),
        [0]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preflight_refuses_a_forged_first_row_and_names_it() {
    let (_, event_type, commitment, signature) = REAL_ROWS[0];
    let good = mirror(serve(vec![real(0)]).await, true);
    good.preflight(&list_key(), Duration::from_secs(5))
        .await
        .expect("a real first row passes");
    let forged = mirror(
        serve(vec![wire_row(
            0,
            event_type,
            commitment,
            &flip_hex_digit(signature, 3),
        )])
        .await,
        true,
    );
    let refusal = forged
        .preflight(&list_key(), Duration::from_secs(5))
        .await
        .expect_err("a forged first row is refused");
    assert_eq!(refusal.failure, PreflightFailure::BadSignature(0));
    assert!(refusal.detail.contains(OFAC_LIST_KEY), "{refusal}");
}

/// A key that is not a curve point verifies no row, so the list is refused, not taken unchecked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_list_key_that_is_not_a_public_key_verifies_no_row() {
    let not_a_key = (0u8..=255)
        .map(|byte| [byte; 32])
        .find(|bytes| ed25519_dalek::VerifyingKey::from_bytes(bytes).is_err())
        .expect("some byte pattern is off the curve");
    let mirror = mirror(serve(vec![real(0)]).await, true);
    let refusal = mirror
        .preflight(&ListKey(not_a_key), Duration::from_secs(5))
        .await
        .expect_err("no row verifies");
    assert_eq!(refusal.failure, PreflightFailure::BadSignature(0));
}

/// With the check off, a forged row is taken, and the statement the feed logs says so. With it
/// on, the statement names what is still trusted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_the_check_off_a_forged_row_is_taken_and_the_statement_says_so() {
    let (_, event_type, commitment, signature) = REAL_ROWS[1];
    let forged = wire_row(1, event_type, commitment, &flip_hex_digit(signature, 0));
    let unchecked = mirror(serve(vec![forged]).await, false);
    assert_eq!(unchecked.trust_statement(), UNVERIFIED_TRUST_STATEMENT);
    let (progress, mut rx, _) = feed_one(unchecked, 1, |_| false).await;
    assert_eq!(
        (progress.rows_delivered, progress.signatures_refused),
        (1, 0)
    );
    assert_eq!(leaves(&mut rx).len(), 1);
    assert!(UNVERIFIED_TRUST_STATEMENT.contains("not verified"));

    let checked = mirror("http://127.0.0.1:9".to_owned(), true);
    assert_eq!(checked.trust_statement(), TRUST_STATEMENT);
    for still_trusted in [
        "withhold or delay",
        "validatedMerkleroot is not signed",
        "binds neither chain nor txid version",
        "trusted as configured",
    ] {
        assert!(
            TRUST_STATEMENT.contains(still_trusted),
            "the statement must keep naming what the signature does not cover: {still_trusted}"
        );
    }
}
