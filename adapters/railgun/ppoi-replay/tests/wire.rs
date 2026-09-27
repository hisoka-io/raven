//! The replay's answers against upstream's contract: inclusive ranges, the 500 cap and its
//! error, overrides served verbatim, growth, and node status tracking the served prefix.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use common::{generate_rows, hex, list_key, node_status_response, replay, unprefixed_override};
use raven_railgun_ppoi_replay::{
    read_events_bin, write_events_bin, Capture, EventRow, Replay, Reply,
};
use serde_json::{json, Value};

fn events_request(start: Value, end: Value) -> Vec<u8> {
    json!({
        "jsonrpc": "2.0",
        "method": "ppoi_poi_events",
        "params": {
            "chainType": "0",
            "chainID": "1",
            "txidVersion": "V2_PoseidonMerkle",
            "listKey": hex(&list_key()),
            "startIndex": start,
            "endIndex": end,
        },
        "id": 1,
    })
    .to_string()
    .into_bytes()
}

fn indices(reply: &Reply) -> Vec<u64> {
    assert_eq!(reply.status, 200, "{}", reply.body);
    let body: Value = serde_json::from_str(&reply.body).expect("json");
    body["result"]
        .as_array()
        .expect("result array")
        .iter()
        .map(|row| row["signedPOIEvent"]["index"].as_u64().expect("index"))
        .collect()
}

fn status_of(replay: &Replay) -> Value {
    let reply = replay.answer(
        br#"{"jsonrpc":"2.0","method":"ppoi_node_status","params":{},"id":1}"#,
        true,
    );
    assert_eq!(reply.status, 200);
    let body: Value = serde_json::from_str(&reply.body).expect("json");
    body["result"]["forNetwork"]["Ethereum"]["listStatuses"][hex(&list_key())].clone()
}

/// Upstream's own row shape, rebuilt independently of the server's writer.
fn upstream_row(row: &EventRow) -> String {
    format!(
        "{{\"signedPOIEvent\":{{\"index\":{},\"blindedCommitment\":\"0x{}\",\"signature\":\"{}\",\"type\":\"{}\"}},\"validatedMerkleroot\":\"{}\"}}",
        row.index,
        hex(&row.blinded_commitment),
        hex(&row.signature),
        row.event_type.wire_name(),
        hex(&row.validated_merkleroot)
    )
}

#[test]
fn a_generated_list_round_trips_through_events_bin_and_serves_its_own_bytes() {
    let rows = generate_rows(12);
    let image = write_events_bin(&list_key(), &rows);
    let (key, read_back) = read_events_bin(&image).expect("read");
    assert_eq!((key, &read_back), (list_key(), &rows));

    let replay = replay(read_back, BTreeMap::new(), 12);
    let reply = replay.answer(&events_request(json!(2), json!(4)), true);
    let expected: Vec<String> = rows[2..=4].iter().map(upstream_row).collect();
    assert_eq!(
        reply.body,
        format!(
            "{{\"jsonrpc\":\"2.0\",\"result\":[{}],\"id\":1}}",
            expected.join(",")
        )
    );
}

#[test]
fn ranges_are_inclusive_at_both_ends_and_stop_at_the_served_tip() {
    let replay = replay(generate_rows(20), BTreeMap::new(), 20);
    let ask = |start: Value, end: Value| indices(&replay.answer(&events_request(start, end), true));
    assert_eq!(
        ask(json!(5), json!(5)),
        vec![5],
        "a zero-width range is one row"
    );
    assert_eq!(ask(json!(0), json!(3)), vec![0, 1, 2, 3]);
    assert_eq!(ask(json!(18), json!(400)), vec![18, 19]);
    assert!(
        ask(json!(20), json!(20)).is_empty(),
        "past the tip is empty, not an error"
    );
    assert_eq!(
        ask(json!(-4), json!(1)),
        vec![0, 1],
        "upstream filters, it does not refuse"
    );
    assert_eq!(
        ask(json!(1.5), json!(3.5)),
        vec![2, 3],
        "JS numbers compare as doubles"
    );
}

#[test]
fn the_cap_admits_501_rows_and_refuses_502_with_the_aggregators_error() {
    let replay = replay(generate_rows(600), BTreeMap::new(), 600);
    assert_eq!(
        indices(&replay.answer(&events_request(json!(10), json!(510)), true)).len(),
        501
    );
    let over = replay.answer(&events_request(json!(10), json!(511)), true);
    assert_eq!(over.status, 500);
    assert_eq!(
        over.body,
        r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"Max event query range length is 500"},"id":1}"#
    );
    let backwards = replay.answer(&events_request(json!(9), json!(8)), true);
    assert_eq!(backwards.status, 500);
    assert_eq!(
        backwards.body,
        r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"Invalid query range"},"id":1}"#
    );
}

#[test]
fn an_override_row_is_served_as_upstream_spelled_it() {
    let mut rows = generate_rows(6);
    let overrides = unprefixed_override(&mut rows, 4);
    let replay = replay(rows.clone(), overrides, 6);
    let reply = replay.answer(&events_request(json!(3), json!(5)), true);
    let served: Value = serde_json::from_str(&reply.body).expect("json");
    let commitments: Vec<&str> = served["result"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|r| {
            r["signedPOIEvent"]["blindedCommitment"]
                .as_str()
                .expect("bc")
        })
        .collect();
    let bare = hex(&rows[4].blinded_commitment);
    assert_eq!(
        commitments,
        vec![
            format!("0x{}", hex(&rows[3].blinded_commitment)),
            bare.clone(),
            format!("0x{}", hex(&rows[5].blinded_commitment)),
        ]
    );
    assert_eq!(
        served["result"][1]["signedPOIEvent"]["signature"],
        json!(hex(&rows[4].signature)),
        "the signature over the unprefixed string"
    );
}

#[test]
fn growth_moves_the_tip_and_node_status_follows_the_served_prefix() {
    let rows = generate_rows(12);
    let replay = replay(rows.clone(), BTreeMap::new(), 0);

    let empty = status_of(&replay);
    assert_eq!(empty["historicalMerklerootsLength"], json!(0));
    assert_eq!(
        empty["latestHistoricalMerkleroot"],
        json!("No merkleroot found")
    );
    assert!(indices(&replay.answer(&events_request(json!(0), json!(11)), true)).is_empty());

    replay.grow_to(5).expect("grow");
    assert_eq!(
        indices(&replay.answer(&events_request(json!(0), json!(11)), true)),
        vec![0, 1, 2, 3, 4]
    );
    let five = status_of(&replay);
    assert_eq!(five["historicalMerklerootsLength"], json!(5));
    assert_eq!(
        five["latestHistoricalMerkleroot"],
        json!(hex(&rows[4].validated_merkleroot))
    );
    let count = |t: &str| {
        rows[..5]
            .iter()
            .filter(|r| r.event_type.wire_name() == t)
            .count()
    };
    assert_eq!(
        five["poiEventLengths"],
        json!({"Shield": count("Shield"), "Transact": count("Transact"),
               "Unshield": count("Unshield"), "LegacyTransact": count("LegacyTransact")})
    );
    assert_eq!(
        five["blockedShields"],
        json!(12),
        "not derived from the list: passed through"
    );

    replay.grow_to(12).expect("grow");
    assert_eq!(
        indices(&replay.answer(&events_request(json!(0), json!(11)), true)).len(),
        12
    );
    assert!(replay.grow_to(11).is_err(), "a list never shrinks");
    assert!(replay.grow_to(13).is_err(), "nor grows past the capture");
    assert_eq!(replay.served_rows(), 12);
}

#[test]
fn node_status_passes_every_field_it_does_not_derive_through_byte_for_byte() {
    let rows = generate_rows(9);
    let recorded = node_status_response(&list_key(), 9, &hex(&rows[8].validated_merkleroot))
        .replace(
            "\"Shield\":9,\"Transact\":0,\"Unshield\":0,\"LegacyTransact\":0",
            &{
                let count = |t: &str| {
                    rows.iter()
                        .filter(|r| r.event_type.wire_name() == t)
                        .count()
                };
                format!(
                    "\"Shield\":{},\"Transact\":{},\"Unshield\":{},\"LegacyTransact\":{}",
                    count("Shield"),
                    count("Transact"),
                    count("Unshield"),
                    count("LegacyTransact")
                )
            },
        );
    let capture = Capture::new(list_key(), rows, BTreeMap::new()).expect("capture");
    let replay = Replay::new(capture, common::scope(), recorded.as_bytes(), 9).expect("replay");
    let reply = replay.answer(
        br#"{"jsonrpc":"2.0","method":"ppoi_node_status","params":{},"id":1}"#,
        true,
    );
    assert_eq!(reply.body, recorded);
}

#[test]
fn validate_poi_merkleroots_knows_only_served_roots_in_their_stored_spelling() {
    let rows = generate_rows(10);
    let replay = replay(rows.clone(), BTreeMap::new(), 6);
    let ask = |roots: Value| {
        let body = json!({"jsonrpc": "2.0", "method": "ppoi_validate_poi_merkleroots", "id": 3,
            "params": {"chainType": "0", "chainID": "1", "txidVersion": "V2_PoseidonMerkle",
                       "listKey": hex(&list_key()), "poiMerkleroots": roots}});
        replay.answer(body.to_string().as_bytes(), true).body
    };
    let root = |i: usize| hex(&rows[i].validated_merkleroot);
    assert_eq!(
        ask(json!([root(0), root(5)])),
        r#"{"jsonrpc":"2.0","result":true,"id":3}"#
    );
    assert_eq!(
        ask(json!([root(0), root(6)])),
        r#"{"jsonrpc":"2.0","result":false,"id":3}"#
    );
    assert_eq!(
        ask(json!([format!("0x{}", root(1))])),
        r#"{"jsonrpc":"2.0","result":false,"id":3}"#
    );
    assert_eq!(
        ask(json!([root(1).to_uppercase()])),
        r#"{"jsonrpc":"2.0","result":false,"id":3}"#
    );
    assert_eq!(ask(json!([])), r#"{"jsonrpc":"2.0","result":true,"id":3}"#);
    replay.grow_to(10).expect("grow");
    assert_eq!(
        ask(json!([root(6)])),
        r#"{"jsonrpc":"2.0","result":true,"id":3}"#
    );
}

#[test]
fn refusals_carry_upstreams_codes_and_echo_the_id() {
    let replay = replay(generate_rows(3), BTreeMap::new(), 3);
    let other_list = br#"{"jsonrpc":"2.0","method":"ppoi_poi_events","params":{"chainType":"0","chainID":"1","txidVersion":"V2_PoseidonMerkle","listKey":"00000000000000000000000000000000000000000000000000000000000000c2","startIndex":65535,"endIndex":65535},"id":1}"#;
    let reply = replay.answer(other_list, true);
    assert_eq!(
        (reply.status, reply.body.as_str()),
        (
            400,
            r#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params","data":"Invalid listKey"},"id":1}"#
        )
    );
    let per_note = replay.answer(
        br#"{"jsonrpc":"2.0","method":"ppoi_pois_per_blinded_commitment","params":{},"id":"q"}"#,
        true,
    );
    assert_eq!(
        (per_note.status, per_note.body.as_str()),
        (
            404,
            r#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"},"id":"q"}"#
        )
    );
    let not_json = replay.answer(b"method=ppoi_node_status", false);
    assert_eq!(
        not_json.body, r#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"}}"#,
        "a non-JSON body reads as {{}}, and an absent id stays absent"
    );
    let submit = replay.answer(
        br#"{"jsonrpc":"2.0","method":"ppoi_submit_transact_proof","params":{},"id":{"b":1,"a":2}}"#,
        true,
    );
    assert_eq!(submit.status, 500);
    assert!(
        submit.body.ends_with(r#""id":{"b":1,"a":2}}"#),
        "{}",
        submit.body
    );
    let schema = replay.answer(&events_request(json!("0"), json!(3)), true);
    assert_eq!(schema.status, 400);
    assert!(
        schema.body.contains(r#""instancePath":"/startIndex""#),
        "{}",
        schema.body
    );
    let other_chain = replay.answer(
        &String::from_utf8(events_request(json!(0), json!(3)))
            .expect("utf8")
            .replace("\"chainID\":\"1\"", "\"chainID\":\"137\"")
            .into_bytes(),
        true,
    );
    assert_eq!(other_chain.status, 500);
}

#[tokio::test]
async fn the_http_route_serves_the_same_bytes_as_the_answer() {
    let replay = Arc::new(replay(generate_rows(8), BTreeMap::new(), 8));
    let (addr, server) = common::spawn(Arc::clone(&replay)).await;
    let client = reqwest::Client::new();
    let request = events_request(json!(0), json!(7));
    let response = client
        .post(format!("http://{addr}/"))
        .header("content-type", "application/json")
        .body(request.clone())
        .send()
        .await
        .expect("send");
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["content-type"],
        "application/json; charset=utf-8"
    );
    assert_eq!(
        response.text().await.expect("body"),
        replay.answer(&request, true).body
    );
    let over = client
        .post(format!("http://{addr}/"))
        .header("content-type", "application/json")
        .body(events_request(json!(0), json!(501)))
        .send()
        .await
        .expect("send");
    assert_eq!(over.status(), 500);
    server.abort();
}
