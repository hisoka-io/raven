//! HTTP wire-shape tests for the synthetic PPOI surface.

#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;

use raven_railgun_mock_ppoi::{
    bind_listener, list_key_from_hex, load_blocked_csv, seed_from_hex, serve_on, AppState, Corpus,
    CorpusConfig, DEFAULT_CORPUS_SEED_HEX, DEFAULT_LIST_KEY_HEX, SYNTHETIC_BANNER,
};
use serde_json::Value;

async fn spawn_with_corpus(corpus: Corpus) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let state = AppState::new(corpus);
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let (listener, local) = bind_listener(addr).await.expect("bind");
    let handle = tokio::spawn(async move {
        let _ = serve_on(listener, state).await;
    });
    (local, handle)
}

fn fixture_corpus(size: u32, blocked: Vec<[u8; 32]>) -> Corpus {
    let list_key = list_key_from_hex(DEFAULT_LIST_KEY_HEX).expect("list key").0;
    let seed = seed_from_hex(DEFAULT_CORPUS_SEED_HEX).expect("seed");
    Corpus::generate(CorpusConfig {
        list_key,
        seed,
        size,
        blocked,
    })
    .expect("generate")
}

/// Mirrors the private `mask_to_fr`: top nibble cleared so the buffer stays
/// below the BN254 modulus. Part of the deterministic-signature contract.
fn mask_to_fr(input: &[u8; 32]) -> [u8; 32] {
    let mut out = *input;
    if let Some(byte) = out.first_mut() {
        *byte &= 0x0F;
    }
    out
}

/// Independent recomputation of the server's deterministic placeholder
/// signature; locks its derivation as part of the wire contract.
fn expected_synthetic_signature(bc: &[u8; 32], index: u32) -> String {
    let mut idx_buf = [0u8; 32];
    idx_buf[28..].copy_from_slice(&index.to_be_bytes());
    let mut domain_a = [0u8; 32];
    domain_a[31] = 0x01;
    let mut domain_b = [0u8; 32];
    domain_b[31] = 0x02;
    let bc_masked = mask_to_fr(bc);
    let part_a = raven_railgun_poseidon::hash_n(&[domain_a, bc_masked, idx_buf]).expect("hash_n a");
    let part_b = raven_railgun_poseidon::hash_n(&[domain_b, bc_masked, idx_buf]).expect("hash_n b");
    format!("{}{}", hex_lower(&part_a), hex_lower(&part_b))
}

/// Byte-exact against the corpus, not shape-only: a server corrupting the
/// blindedCommitment bytes on the wire passed the previous (length-checking)
/// version of this test.
#[tokio::test]
async fn mock_ppoi_serves_poi_events_route_with_synthetic_corpus() {
    // Deterministic generator: this reference is byte-identical to the served corpus.
    let reference = fixture_corpus(20, Vec::new());
    let corpus = fixture_corpus(20, Vec::new());
    let (addr, handle) = spawn_with_corpus(corpus).await;

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/poi-events/0/1");
    let body = serde_json::json!({
        "txidVersion": "V2_PoseidonMerkle",
        "listKey": DEFAULT_LIST_KEY_HEX,
        "startIndex": 0,
        "endIndex": 10,
    });
    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .expect("send")
        .json::<Value>()
        .await
        .expect("json");
    let arr = resp.as_array().expect("array");
    assert_eq!(arr.len(), 10, "10 events requested");
    for (i, ev) in arr.iter().enumerate() {
        let expected = reference.events_view().get(i).expect("reference event");
        let signed = ev.get("signedPOIEvent").expect("signedPOIEvent field");
        let idx = signed.get("index").and_then(Value::as_u64).expect("index");
        assert_eq!(idx, i as u64, "monotone index at slot {i}");
        let bc = signed
            .get("blindedCommitment")
            .and_then(Value::as_str)
            .expect("blindedCommitment");
        assert_eq!(
            bc,
            hex_lower(&expected.blinded_commitment),
            "served blindedCommitment bytes must match the corpus at slot {i}"
        );
        let sig = signed
            .get("signature")
            .and_then(Value::as_str)
            .expect("signature");
        assert_eq!(
            sig,
            expected_synthetic_signature(&expected.blinded_commitment, expected.index),
            "served signature must match the deterministic derivation at slot {i}"
        );
        let root = ev
            .get("validatedMerkleroot")
            .and_then(Value::as_str)
            .expect("validatedMerkleroot");
        assert_eq!(
            root,
            hex_lower(&expected.validated_merkleroot),
            "served validatedMerkleroot bytes must match the corpus at slot {i}"
        );
    }

    handle.abort();
}

#[tokio::test]
async fn mock_ppoi_pois_per_blinded_commitment_returns_valid_for_seeded_bcs() {
    let corpus = fixture_corpus(8, Vec::new());
    let known_bc_bytes = corpus
        .events_view()
        .get(2)
        .expect("third event")
        .blinded_commitment;
    let (addr, handle) = spawn_with_corpus(corpus).await;

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/pois-per-blinded-commitment/0/1");
    let bc_hex = hex_lower(&known_bc_bytes);
    let body = serde_json::json!({
        "txidVersion": "V2_PoseidonMerkle",
        "listKey": DEFAULT_LIST_KEY_HEX,
        "blindedCommitmentDatas": [
            {"blindedCommitment": bc_hex, "type": "Shield"}
        ],
    });
    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .expect("send")
        .json::<HashMap<String, String>>()
        .await
        .expect("map");
    let status = resp.get(&bc_hex).expect("bc present");
    assert_eq!(status, "Valid");

    handle.abort();
}

#[tokio::test]
async fn mock_ppoi_returns_blocked_for_csv_overridden_bc() {
    let baseline = fixture_corpus(8, Vec::new());
    let target = baseline
        .events_view()
        .get(3)
        .expect("fourth event")
        .blinded_commitment;
    drop(baseline);

    let tmp = tempdir_under_target();
    let csv_path = tmp.join("blocked.csv");
    let mut f = std::fs::File::create(&csv_path).expect("create csv");
    writeln!(f, "# synthetic block list").expect("comment");
    writeln!(f, "{}", hex_lower(&target)).expect("entry");
    drop(f);

    let blocked = load_blocked_csv(&csv_path).expect("load csv");
    assert_eq!(blocked, vec![target]);

    let corpus = fixture_corpus(8, blocked);
    let (addr, handle) = spawn_with_corpus(corpus).await;

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/pois-per-blinded-commitment/0/1");
    let bc_hex = hex_lower(&target);
    let body = serde_json::json!({
        "txidVersion": "V2_PoseidonMerkle",
        "listKey": DEFAULT_LIST_KEY_HEX,
        "blindedCommitmentDatas": [
            {"blindedCommitment": bc_hex, "type": "Shield"}
        ],
    });
    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .expect("send")
        .json::<HashMap<String, String>>()
        .await
        .expect("map");
    assert_eq!(resp.get(&bc_hex).map(String::as_str), Some("ShieldBlocked"));

    handle.abort();
    let _ = std::fs::remove_file(&csv_path);
    let _ = std::fs::remove_dir(&tmp);
}

#[tokio::test]
async fn mock_ppoi_returns_404_on_unknown_route() {
    let corpus = fixture_corpus(2, Vec::new());
    let (addr, handle) = spawn_with_corpus(corpus).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/unknown"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 404);

    handle.abort();
}

/// The served roots must BE the per-list IMT roots, slot by slot: pairwise
/// distinctness alone survived a server corrupting every root byte on the
/// wire (a constant XOR keeps distinct values distinct).
#[tokio::test]
async fn mock_ppoi_validatedmerkleroot_advances_with_event_count() {
    let reference = fixture_corpus(6, Vec::new());
    let corpus = fixture_corpus(6, Vec::new());
    let (addr, handle) = spawn_with_corpus(corpus).await;

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/poi-events/0/1");
    let body = serde_json::json!({
        "txidVersion": "V2_PoseidonMerkle",
        "listKey": DEFAULT_LIST_KEY_HEX,
        "startIndex": 0,
        "endIndex": 6,
    });
    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .expect("send")
        .json::<Value>()
        .await
        .expect("json");
    let arr = resp.as_array().expect("array");
    assert_eq!(arr.len(), 6);
    let mut prev: Option<String> = None;
    for (i, ev) in arr.iter().enumerate() {
        let curr = ev
            .get("validatedMerkleroot")
            .and_then(Value::as_str)
            .expect("root")
            .to_owned();
        let expected = hex_lower(
            &reference
                .events_view()
                .get(i)
                .expect("reference event")
                .validated_merkleroot,
        );
        assert_eq!(
            curr, expected,
            "served root at slot {i} must equal the post-insert IMT root"
        );
        if let Some(p) = &prev {
            assert_ne!(p, &curr, "merkleroot must advance after each insert");
        }
        prev = Some(curr);
    }

    handle.abort();
}

#[test]
fn mock_ppoi_emits_synthetic_banner_on_startup() {
    // Source-level, not runtime: dispatcher propagation across `tokio::spawn`
    // flakes under parallel test ordering.
    assert_eq!(
        SYNTHETIC_BANNER,
        "raven-railgun-mock-ppoi: SYNTHETIC corpus, do not pass off as real OFAC"
    );
    let lib_src = include_str!("../src/lib.rs");
    assert!(
        lib_src.contains("tracing::info!(%addr, \"{SYNTHETIC_BANNER}\")"),
        "serve(...) must emit the synthetic banner via tracing::info!"
    );
    assert!(
        lib_src.contains("tracing::info!(\"{SYNTHETIC_BANNER}\")"),
        "serve_on(...) must emit the synthetic banner via tracing::info!"
    );
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let hi = HEX.get(usize::from(byte >> 4)).copied().unwrap_or(b'0');
        let lo = HEX.get(usize::from(byte & 0x0F)).copied().unwrap_or(b'0');
        s.push(hi as char);
        s.push(lo as char);
    }
    s
}

fn tempdir_under_target() -> std::path::PathBuf {
    let base = std::env::var("CARGO_TARGET_TMPDIR")
        .ok()
        .map_or_else(std::env::temp_dir, std::path::PathBuf::from);
    let unique = format!(
        "raven-railgun-mock-ppoi-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    );
    let path = base.join(unique);
    std::fs::create_dir_all(&path).expect("mkdir tmp");
    path
}
