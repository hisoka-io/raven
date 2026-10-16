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

    let params = InspireParams::secure_128_d2048();
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
