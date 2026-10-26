//! The bytes each route answers on the fixture chain, pinned. The node's key material is
//! made from a fixed seed, so the parameters answer is pinned too; a private read's bytes
//! depend on the wallet's fresh secret, so its layout and sizes are pinned instead.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

#[path = "../../../howl/indexer/tests/support/mod.rs"]
mod chain;
mod support;

use std::sync::Arc;
use std::time::Duration;

use chain::Fixture;
use howl_node::http::{router, Served};
use howl_node::NodeConfig;
use howl_wire::{Answer, Body, HEADER_BYTES};
use raven_inspire_session::SessionStoreLimits;
use sha2::{Digest, Sha256};
use support::{FakeChain, Http, Reader};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const PINNED: [(&str, &str); 9] = [
    (
        "/howl/v1/params",
        "47c144e937dd62769c92892c199acc69de0066f2d4bb78444e875235839a0d9c",
    ),
    (
        "/howl/v1/prefixes?since=0",
        "49a44d2ab56fbdfc5f57ba713e98e6a7c76a0904ad38534d9a2b18f8da4f2edc",
    ),
    (
        "/howl/v1/prefixes?since=150",
        "939f311abfd55b30d2ca5bb1e95df34bf520537ab85b3ac35c7e63967ac17bc9",
    ),
    (
        "/howl/v1/block/0",
        "75769077eb6fb0a94b116e5f616c188fbbc60f88242999f3103263bd54fbf83b",
    ),
    // Past the newest block: the stale answer.
    (
        "/howl/v1/block/1",
        "984447469cff283a66b0b9ccc21f491dd67427f7aeef21304cdcd7670eb68014",
    ),
    (
        "/howl/v1/upper?since=0",
        "b6c0471f1b3a5d03ff436b385fe587cd3504396cf3cac691a437915151e7a7bd",
    ),
    (
        "/howl/v1/sync?since=100&upper=0",
        "6dc751b78d9b2a24800ba1efa0354be06413ee148253f3dc5eee86e6e687f49f",
    ),
    // Leaves 150..160 of the newest block only; derived by hand from the fixture as well.
    (
        "/howl/v1/sync?since=160&upper=0&held=150",
        "6162d1d9a6308ab76629bd699ee200481cae4d3b4a46de3d96d4f8117aa0e865",
    ),
    (
        "/howl/v1/prefixes?since=161",
        "984447469cff283a66b0b9ccc21f491dd67427f7aeef21304cdcd7670eb68014",
    ),
];

#[tokio::test(flavor = "multi_thread")]
async fn every_route_answers_the_pinned_bytes() {
    let fixture = Fixture::load();
    let dir = tempfile::tempdir().expect("tempdir");
    let config = NodeConfig {
        data_dir: dir.path().to_path_buf(),
        chain_id: fixture.chain_id,
        pool: fixture.pool,
        deployment_block: fixture.first_block,
        max_range: 40,
        sessions: SessionStoreLimits {
            max_sessions: 8,
            ttl: Duration::from_secs(3_600),
        },
        param_set: howl_wire::PARAM_SET_D2048_CELL256,
        seed: Some([7; 32]),
    };
    let chain = FakeChain::new(
        fixture.pool,
        fixture.first_block,
        fixture.logs.clone(),
        fixture.head,
    );
    let (mut follower, engine) = howl_node::open(&config, chain).expect("open");
    for steps in 0.. {
        assert!(steps < 5_000, "no idle step");
        let step = follower.step().await.expect("step");
        howl_node::publish(&follower, &engine, &step).expect("publish");
        if matches!(step, howl_node::follow::Step::Idle { .. }) {
            break;
        }
    }
    let http = Http(router(Served::new(Arc::clone(&engine), 2)));

    let mut actual = Vec::new();
    for (path, _) in PINNED {
        let (_, body) = http.get(path).await;
        actual.push(hex(&Sha256::digest(&body)));
    }
    for ((path, _), digest) in PINNED.iter().zip(&actual) {
        eprintln!("(\"{path}\", \"{digest}\"),");
    }
    // The header of every answer on this chain, in full.
    let (_, sync) = http.get("/howl/v1/sync?since=100&upper=0").await;
    eprintln!("header {}", hex(&sync[..HEADER_BYTES]));

    // A private read: one response per slot, each its bincode form at the wire modulus.
    let mut reader = Reader::new(&http, 9).await;
    let upload = reader.key_upload();
    reader.register(&http).await;
    let (_, by_handle) = reader.batch(&[5], fixture.leaf_count);
    let (status, answer) = http.post("/howl/v1/notes", by_handle.clone()).await;
    assert!(status.is_success());
    let decoded = Answer::decode(&answer).expect("answer");
    let Body::Notes(notes) = &decoded.body else {
        panic!("notes")
    };
    let response = notes.responses[0].len();
    let mut inline = Reader::new(&http, 10).await;
    let (_, by_key) = inline.batch(&[5, 6, 7, 8], fixture.leaf_count);
    eprintln!(
        "key upload {} B; batch of 1 by handle {} B; batch of 4 inline {} B; response {} B; answer of 1 {} B",
        upload.len(),
        by_handle.len(),
        by_key.len(),
        response,
        answer.len()
    );
    assert_eq!(answer.len(), HEADER_BYTES + 2 + 4 + response);
    for ((path, pinned), digest) in PINNED.iter().zip(&actual) {
        assert_eq!(digest, pinned, "{path}");
    }
    assert_eq!(
        hex(&sync[..HEADER_BYTES]),
        concat!(
            "0001",
            "0001",
            "05",
            "000000",
            "00000000000000a0",
            "0000000000000103",
            "12358d4d451784661d995d7e51a0a4646b985d9eff0927ecf68903d4c810311e"
        ),
        "version 1, set 1, sync; 160 leaves after block 259 under the fixture's root"
    );
    assert_eq!(fixture.root[..], sync[24..HEADER_BYTES]);
    assert_eq!(
        (upload.len(), by_handle.len(), by_key.len(), response),
        (46_256, 15_501, 108_176, 9_870)
    );
}

#[test]
fn a_session_seat_holds_48_kib_of_key() {
    use raven_inspire::inspiring::{ClientPackingKeys, PackParams};
    use raven_inspire::math::GaussianSampler;
    use raven_inspire::params::InspireParams;
    use raven_inspire::rlwe::RlweSecretKey;
    use raven_inspire::PackingKeySeat;

    let params = InspireParams::d2048();
    let gamma = raven_inspire::num_columns(howl_wire::CELL_BYTES);
    let mut sampler = GaussianSampler::with_seed(params.sigma, 3);
    let secret = RlweSecretKey::generate(&params, &mut sampler);
    let keys =
        ClientPackingKeys::generate(&secret, &params, gamma, [5; 32], &mut sampler).expect("keys");
    let pack = PackParams::try_new(&params, gamma).expect("pack params");
    let seat = PackingKeySeat::from_wire(keys, &pack, &params.ntt_context()).expect("seat");
    eprintln!(
        "seat payload {} B, resident {} B",
        seat.payload_bytes(),
        seat.resident_bytes()
    );
    assert_eq!((gamma, seat.payload_bytes()), (128, 49_152));
    assert!(seat.resident_bytes() < 50 * 1024);
}

/// A node of parameter set `set` caught up with the fixture chain, behind its router.
async fn fixture_http(set: u16, dir: &std::path::Path) -> (Fixture, Http) {
    let fixture = Fixture::load();
    let config = NodeConfig {
        data_dir: dir.to_path_buf(),
        chain_id: fixture.chain_id,
        pool: fixture.pool,
        deployment_block: fixture.first_block,
        max_range: 40,
        sessions: SessionStoreLimits {
            max_sessions: 8,
            ttl: Duration::from_secs(3_600),
        },
        param_set: set,
        seed: Some([7; 32]),
    };
    let chain = FakeChain::new(
        fixture.pool,
        fixture.first_block,
        fixture.logs.clone(),
        fixture.head,
    );
    let (mut follower, engine) = howl_node::open(&config, chain).expect("open");
    for steps in 0.. {
        assert!(steps < 5_000, "no idle step");
        let step = follower.step().await.expect("step");
        howl_node::publish(&follower, &engine, &step).expect("publish");
        if matches!(step, howl_node::follow::Step::Idle { .. }) {
            break;
        }
    }
    (fixture, Http(router(Served::new(engine, 2))))
}

fn set_2_request(payload: &[u8]) -> Vec<u8> {
    let mut body = howl_wire::RequestPrefix {
        param_set: howl_wire::PARAM_SET_D2048_CELL256_P16,
    }
    .encode()
    .to_vec();
    body.extend_from_slice(payload);
    body
}

/// Shard 0 of the fixture as the table holds it: each leaf's cell, zero where a leaf has none.
fn shard_0(fixture: &Fixture) -> Vec<u8> {
    let mut cells = vec![0u8; 2_048 * 256];
    for (i, leaf) in fixture.leaves.iter().enumerate() {
        if let Some(cell) = &leaf.cell {
            cells[i * 256..(i + 1) * 256].copy_from_slice(cell);
        }
    }
    cells
}

// An inline read of leaf 5 by the client of seed [9; 32]; equal above to the library's own bytes.
const PINNED_SET_2_NOTES: &str = "03c77a2a4959e3c6d22d9441e20244882d9d8d3e1b7130aecc06d5b142594869";

#[tokio::test(flavor = "multi_thread")]
async fn set_2_answers_the_same_routes_under_its_own_id_and_reads_byte_exact() {
    use howl_wire::{KeySource, P16Batch, P16Query, PARAM_SET_D2048_CELL256_P16};
    use raven_inspire::special_modulus::{Client, Params, Response, Server};

    let one = tempfile::tempdir().expect("tempdir");
    let two = tempfile::tempdir().expect("tempdir");
    let (fixture, set_1) = fixture_http(howl_wire::PARAM_SET_D2048_CELL256, one.path()).await;
    let (_, set_2) = fixture_http(PARAM_SET_D2048_CELL256_P16, two.path()).await;

    // Every plain route: set 1's bytes with the header's parameter set byte reading 2.
    for (path, _) in &PINNED[1..] {
        let (s1, mut b1) = set_1.get(path).await;
        let (s2, b2) = set_2.get(path).await;
        assert_eq!(s1, s2, "{path}");
        assert_eq!(b1[2..4], [0, 1], "{path}");
        b1[3] = 2;
        assert_eq!(b2, b1, "{path}");
    }

    // The params answer carries only the key-mask version keys are seated under.
    let (_, params) = set_2.get("/howl/v1/params").await;
    let decoded = Answer::decode(&params).expect("params");
    assert_eq!(decoded.param_set, PARAM_SET_D2048_CELL256_P16);
    let Body::Params(p) = &decoded.body else {
        panic!("params")
    };
    assert_eq!(
        (
            p.entry_bytes,
            p.rows_per_shard,
            p.ladder_cap,
            p.session_ttl_secs,
            p.crs.as_slice()
        ),
        (256, 2_048, 16, 3_600, &[0u8, 1][..])
    );
    // Written out by hand: version 1, set 2, route 1, the fixture's state after block 259, then
    // 256-byte cells, 2,048 rows, cap 16, an hour, key-mask version 1.
    let mut by_hand = vec![0, 1, 0, 2, 1, 0, 0, 0];
    by_hand.extend_from_slice(&fixture.leaf_count.to_be_bytes());
    by_hand.extend_from_slice(&259u64.to_be_bytes());
    by_hand.extend_from_slice(&fixture.root);
    by_hand.extend_from_slice(&[
        0, 0, 1, 0, 0, 0, 8, 0, 0, 16, 0, 0, 0x0e, 0x10, 0, 0, 0, 2, 0, 1,
    ]);
    assert_eq!(params, by_hand);

    // A read under a fixed seed is the same bytes the library answers on the same cells.
    let set = Params::ring2048_cell256();
    let mut client = Client::from_seed(&set, [9; 32]).expect("client");
    let key = client.packing_key().to_bytes(&set).expect("key");
    let query = client.query(5).expect("query");
    let body = set_2_request(
        &P16Batch {
            key: KeySource::Inline(key.clone()),
            queries: vec![P16Query {
                shard: 0,
                query: query.to_bytes(&set).expect("query bytes"),
            }],
        }
        .encode(),
    );
    let (status, answer) = set_2.post("/howl/v1/notes", body.clone()).await;
    assert!(status.is_success(), "{}", String::from_utf8_lossy(&answer));
    let decoded = Answer::decode(&answer).expect("answer");
    assert_eq!(decoded.param_set, PARAM_SET_D2048_CELL256_P16);
    let Body::Notes(notes) = &decoded.body else {
        panic!("notes")
    };
    let server = Server::new(&set).expect("server");
    let table = server.table(&shard_0(&fixture)).expect("table");
    let seat = server
        .seat(&raven_inspire::special_modulus::PackingKey::from_bytes(&set, &key).expect("key"))
        .expect("seat");
    let library = server
        .respond(&table, &seat, &query)
        .expect("respond")
        .to_bytes(&set)
        .expect("bytes");
    assert_eq!(notes.responses, vec![library.clone()]);
    let record = client
        .decode(&Response::from_bytes(&set, &library).expect("response"))
        .expect("decode");
    let cell = fixture.leaves[5].cell.as_ref().expect("leaf 5 is a note");
    assert_eq!(record[..], cell[..246]);
    assert!(cell[246..].iter().all(|b| *b == 0));

    let notes_digest = hex(&Sha256::digest(&answer));
    eprintln!("set 2 notes {notes_digest}");
    eprintln!(
        "set 2: key upload {} B, inline batch of 1 {} B, response {} B, answer of 1 {} B",
        set_2_request(&key).len(),
        body.len(),
        library.len(),
        answer.len()
    );
    assert_eq!(
        (
            set_2_request(&key).len(),
            body.len(),
            library.len(),
            answer.len()
        ),
        (
            4 + 15_362,
            4 + 1 + 15_362 + 2 + 4 + 7_456,
            9_208,
            HEADER_BYTES + 2 + 4 + 9_208
        )
    );
    assert_eq!(notes_digest, PINNED_SET_2_NOTES);
}

#[tokio::test(flavor = "multi_thread")]
async fn set_2_refusals() {
    use axum::http::StatusCode;
    use howl_wire::{KeySource, P16Batch, P16Query, PARAM_SET_D2048_CELL256_P16};
    use raven_inspire::special_modulus::{Client, Params};

    let one = tempfile::tempdir().expect("tempdir");
    let two = tempfile::tempdir().expect("tempdir");
    let (_, set_1) = fixture_http(howl_wire::PARAM_SET_D2048_CELL256, one.path()).await;
    let (_, set_2) = fixture_http(PARAM_SET_D2048_CELL256_P16, two.path()).await;
    let set = Params::ring2048_cell256();
    let mut client = Client::from_seed(&set, [4; 32]).expect("client");
    let key = client.packing_key().to_bytes(&set).expect("key");
    let mut query = |row: usize| {
        client
            .query(row)
            .expect("query")
            .to_bytes(&set)
            .expect("bytes")
    };
    let batch = |key: KeySource, shards: &[u32], query: &mut dyn FnMut(usize) -> Vec<u8>| {
        set_2_request(
            &P16Batch {
                key,
                queries: shards
                    .iter()
                    .map(|&shard| P16Query {
                        shard,
                        query: query(7),
                    })
                    .collect(),
            }
            .encode(),
        )
    };

    // Each node refuses the other set's bodies before reading them.
    let (status, _) = set_1.post("/howl/v1/session", set_2_request(&key)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let mut set_1_prefix = set_2_request(&key);
    set_1_prefix[3] = 1;
    let (status, text) = set_2.post("/howl/v1/session", set_1_prefix).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&text).contains("parameter set 1 is not the 2"));
    // A key one byte short, one under another key-mask version, and one whose first coefficient
    // is not a residue.
    let (status, _) = set_2
        .post("/howl/v1/session", set_2_request(&key[1..]))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let mut other_mask = key.clone();
    other_mask[..2].copy_from_slice(&[0, 2]);
    let (status, text) = set_2
        .post("/howl/v1/session", set_2_request(&other_mask))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        String::from_utf8_lossy(&text).contains("key-mask version 2"),
        "{}",
        String::from_utf8_lossy(&text)
    );
    let mut not_residue = key.clone();
    not_residue[2..6].copy_from_slice(&[0xff, 0xff, 0xff, 0x1f]);
    let (status, _) = set_2
        .post("/howl/v1/session", set_2_request(&not_residue))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, body) = set_2.post("/howl/v1/session", set_2_request(&key)).await;
    assert_eq!(status, StatusCode::OK);
    let Body::Session(session) = Answer::decode(&body).expect("session").body else {
        panic!("session")
    };
    let (status, _) = set_2
        .post(
            "/howl/v1/notes",
            batch(KeySource::Session(session.handle), &[0, 0], &mut query),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = set_2
        .post(
            "/howl/v1/notes",
            batch(KeySource::Session(session.handle ^ 1), &[0], &mut query),
        )
        .await;
    assert_eq!(status, StatusCode::GONE, "an unknown handle");
    let (status, _) = set_2
        .post(
            "/howl/v1/notes",
            batch(KeySource::Session(session.handle), &[0, 0, 0], &mut query),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "three is no step");
    let (status, stale) = set_2
        .post(
            "/howl/v1/notes",
            batch(KeySource::Session(session.handle), &[1], &mut query),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "shard 1 is past the table");
    assert!(matches!(
        Answer::decode(&stale).expect("stale").body,
        Body::Stale
    ));
    let mut bad_query = batch(KeySource::Session(session.handle), &[0], &mut query);
    let at = 4 + 1 + 8 + 2 + 4 + 32;
    bad_query[at..at + 4].copy_from_slice(&[0xff, 0xff, 0xff, 0x1f]);
    let (status, _) = set_2.post("/howl/v1/notes", bad_query).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a query coefficient past q"
    );

    // Eight seats: the ninth registration waits for one to expire.
    for _ in 1..8 {
        let (status, _) = set_2.post("/howl/v1/session", set_2_request(&key)).await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, _) = set_2.post("/howl/v1/session", set_2_request(&key)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}
