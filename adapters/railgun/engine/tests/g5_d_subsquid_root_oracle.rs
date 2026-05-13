//! Subsquid root oracle test (real-Sepolia checkpoint flavour).
//! Three-oracle (chain / upstream / subsquid) byte-identity check, escalating
//! to a 4-oracle assertion when `real_subsquid_root` is present in the fixture.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::items_after_statements,
    clippy::indexing_slicing,
    clippy::needless_range_loop,
    clippy::too_many_lines,
    clippy::print_stderr
)]

mod oracle_aggregator;

use raven_railgun_engine::imt::Imt;
use raven_railgun_indexer::subsquid::{
    decode_bytes32_hex, FixtureSubsquidSource, SubsquidError, SubsquidRootSource,
};

use oracle_aggregator::{assert_three_oracle_byte_identity, OracleSource};

const FIXTURE_PATH: &str = "tests/fixtures/subsquid_canonical_roots.json";

#[derive(Debug)]
struct TreeCheckpoint {
    label: String,
    tree_number: u32,
    leaf_count: u64,
    block_height: u64,
    leaves: Vec<[u8; 32]>,
    subsquid_root: [u8; 32],
    chain_root: Option<[u8; 32]>,
    upstream_root: Option<[u8; 32]>,
    /// Optional REAL Subsquid GraphQL `Transaction.merkleRoot` capture
    /// (separate from the canonical `subsquid_root` field which holds
    /// a self-derived fixture value). When present, the test enables
    /// the 4-oracle byte-identity assertion path
    /// (Imt::root == chain_root == upstream_root == real_subsquid_root)
    /// for this checkpoint.
    real_subsquid_root: Option<[u8; 32]>,
}

#[derive(Debug)]
struct ListCheckpoint {
    label: String,
    list_key: [u8; 32],
    leaf_count: u64,
    block_height: u64,
    leaves: Vec<[u8; 32]>,
    subsquid_root: [u8; 32],
    upstream_root: Option<[u8; 32]>,
}

#[derive(Debug)]
struct Fixture {
    chain_id: u64,
    tree_checkpoints: Vec<TreeCheckpoint>,
    list_checkpoints: Vec<ListCheckpoint>,
}

fn parse_optional_root(v: &serde_json::Value, key: &str) -> Option<[u8; 32]> {
    v.get(key)
        .and_then(serde_json::Value::as_str)
        .and_then(|s| decode_bytes32_hex(s).ok())
}

fn parse_required_root(v: &serde_json::Value, key: &str, ctx: &str) -> [u8; 32] {
    let s = v
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("{ctx}: missing required field {key}"));
    decode_bytes32_hex(s).unwrap_or_else(|e| panic!("{ctx}: {key} decode failed: {e:?}"))
}

fn parse_leaves(v: &serde_json::Value, ctx: &str) -> Vec<[u8; 32]> {
    let arr = v
        .get("leaves")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("{ctx}: missing leaves array"));
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        let s = item
            .as_str()
            .unwrap_or_else(|| panic!("{ctx}: leaves[{i}] not a string"));
        out.push(
            decode_bytes32_hex(s)
                .unwrap_or_else(|e| panic!("{ctx}: leaves[{i}] decode failed: {e:?}")),
        );
    }
    out
}

fn load_fixture() -> Fixture {
    let raw = std::fs::read_to_string(FIXTURE_PATH).expect("fixture file present");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("fixture is valid JSON");
    assert_eq!(
        v.get("_oracle_protocol_version")
            .and_then(serde_json::Value::as_u64),
        Some(2),
        "fixture must be oracle protocol version 2"
    );
    let chain_id = v
        .get("_chain_id")
        .and_then(serde_json::Value::as_u64)
        .expect("_chain_id present");

    let tree_arr = v
        .get("tree_checkpoints")
        .and_then(serde_json::Value::as_array)
        .expect("tree_checkpoints array present");
    assert!(
        tree_arr.len() >= 2,
        "fixture must carry at least 2 tree checkpoints (had {})",
        tree_arr.len()
    );
    let mut tree_checkpoints = Vec::with_capacity(tree_arr.len());
    for (i, entry) in tree_arr.iter().enumerate() {
        let label = entry
            .get("_label")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("(unnamed)")
            .to_owned();
        let ctx = format!("tree_checkpoints[{i}] (label='{label}')");
        let tree_number: u32 = entry
            .get("tree_number")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(|| panic!("{ctx}: tree_number missing"))
            .try_into()
            .unwrap_or_else(|_| panic!("{ctx}: tree_number out of u32 range"));
        let leaf_count: u64 = entry
            .get("leaf_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(|| panic!("{ctx}: leaf_count missing"));
        let block_height: u64 = entry
            .get("block_height")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(|| panic!("{ctx}: block_height missing"));
        let leaves = parse_leaves(entry, &ctx);
        assert_eq!(
            leaves.len() as u64,
            leaf_count,
            "{ctx}: leaves.len() must equal leaf_count"
        );
        let subsquid_root = parse_required_root(entry, "subsquid_root", &ctx);
        let chain_root = parse_optional_root(entry, "chain_root");
        let upstream_root = parse_optional_root(entry, "upstream_root");
        let real_subsquid_root = parse_optional_root(entry, "real_subsquid_root");
        tree_checkpoints.push(TreeCheckpoint {
            label,
            tree_number,
            leaf_count,
            block_height,
            leaves,
            subsquid_root,
            chain_root,
            upstream_root,
            real_subsquid_root,
        });
    }

    let list_arr = v
        .get("list_checkpoints")
        .and_then(serde_json::Value::as_array)
        .expect("list_checkpoints array present");
    assert!(
        list_arr.len() >= 2,
        "fixture must carry at least 2 list checkpoints (had {})",
        list_arr.len()
    );
    let mut list_checkpoints = Vec::with_capacity(list_arr.len());
    for (i, entry) in list_arr.iter().enumerate() {
        let label = entry
            .get("_label")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("(unnamed)")
            .to_owned();
        let ctx = format!("list_checkpoints[{i}] (label='{label}')");
        let list_key_hex = entry
            .get("list_key_hex")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("{ctx}: list_key_hex missing"));
        let list_key = decode_bytes32_hex(list_key_hex)
            .unwrap_or_else(|e| panic!("{ctx}: list_key_hex decode: {e:?}"));
        let leaf_count: u64 = entry
            .get("leaf_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(|| panic!("{ctx}: leaf_count missing"));
        let block_height: u64 = entry
            .get("block_height")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(|| panic!("{ctx}: block_height missing"));
        let leaves = parse_leaves(entry, &ctx);
        assert_eq!(
            leaves.len() as u64,
            leaf_count,
            "{ctx}: leaves.len() must equal leaf_count"
        );
        let subsquid_root = parse_required_root(entry, "subsquid_root", &ctx);
        let upstream_root = parse_optional_root(entry, "upstream_root");
        list_checkpoints.push(ListCheckpoint {
            label,
            list_key,
            leaf_count,
            block_height,
            leaves,
            subsquid_root,
            upstream_root,
        });
    }

    Fixture {
        chain_id,
        tree_checkpoints,
        list_checkpoints,
    }
}

/// Replay `leaves` into a fresh `Imt` and return its root. Asserts
/// the IMT is internally consistent (leaf_count matches input).
fn replay_into_imt(leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut imt = Imt::new().expect("imt new");
    for (i, leaf) in leaves.iter().enumerate() {
        imt.insert_leaves(i, &[*leaf])
            .unwrap_or_else(|e| panic!("imt insert_leaves[{i}]: {e:?}"));
    }
    assert_eq!(
        imt.leaf_count(),
        leaves.len(),
        "imt leaf_count drifted from input"
    );
    imt.root()
}

/// Populate the in-memory subsquid source with the fixture's
/// per-tree + per-list `subsquid_root` literals so the source can be
/// queried via the `SubsquidRootSource` trait. The trait is what
/// production code consumes; using it in the test prevents trait-
/// boundary drift.
fn populate_subsquid_source(fixture: &Fixture) -> FixtureSubsquidSource {
    let mut src = FixtureSubsquidSource::new();
    for cp in &fixture.tree_checkpoints {
        src.insert_tree_root(
            cp.tree_number,
            cp.block_height,
            cp.leaf_count,
            cp.subsquid_root,
        );
    }
    for cp in &fixture.list_checkpoints {
        src.insert_list_root(cp.list_key, cp.block_height, cp.subsquid_root);
    }
    src
}

#[test]
fn g5d_three_oracle_byte_identity_holds_for_every_checkpoint() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.chain_id, 11_155_111,
        "fixture must target Sepolia (chain_id = 11155111)"
    );

    let src = populate_subsquid_source(&fixture);
    let rt = tokio::runtime::Runtime::new().expect("tokio rt");

    let mut tree_ok = 0usize;
    for cp in &fixture.tree_checkpoints {
        let our_root = replay_into_imt(&cp.leaves);
        // Production-trait round-trip: the subsquid root must come
        // back through the SubsquidRootSource impl, NOT a direct
        // map read. This catches a future trait-shape drift.
        let resp = rt
            .block_on(src.commitment_root_at_height(cp.tree_number, cp.block_height))
            .unwrap_or_else(|e| {
                panic!("subsquid trait read for {}: {e:?}", cp.label);
            });
        assert_eq!(
            resp.tree_number, cp.tree_number,
            "{}: subsquid response tree_number mismatch",
            cp.label
        );
        assert_eq!(
            resp.leaf_count, cp.leaf_count,
            "{}: subsquid response leaf_count mismatch",
            cp.label
        );
        let context = format!(
            "{} (tree={}, leaf_count={}, block={})",
            cp.label, cp.tree_number, cp.leaf_count, cp.block_height
        );
        assert_three_oracle_byte_identity(
            our_root,
            cp.chain_root,
            cp.upstream_root,
            Some(resp.root),
            &context,
        )
        .map_err(|e| {
            format!(
                "subsquid root oracle disagreement at {context}: source={:?} our={:?} other={:?}",
                e.source, e.our_root, e.other_root
            )
        })
        .expect("all oracles agree for the checkpoint");

        // 4-oracle escalation: when ALL of {chain_root, upstream_root,
        // real_subsquid_root} are present (i.e. the operator-driven
        // capture script populated them), the test asserts full
        // byte-identity across every external oracle slot. The
        // self-derived `subsquid_root` fixture value is verified above
        // (it's the canonical local-IMT root); the 4-oracle path adds
        // an INDEPENDENT cross-check against the real Subsquid GraphQL
        // response so a fixture-vs-real-network disagreement surfaces
        // as a hard failure rather than silently passing.
        if let (Some(_), Some(_), Some(real_subsquid)) =
            (cp.chain_root, cp.upstream_root, cp.real_subsquid_root)
        {
            eprintln!(
                "{context}: 4-oracle escalation ENGAGED (chain_root + upstream_root + real_subsquid_root all present)"
            );
            let four_oracle_context = format!("{context} [4-oracle escalation]");
            assert_three_oracle_byte_identity(
                our_root,
                cp.chain_root,
                cp.upstream_root,
                Some(real_subsquid),
                &four_oracle_context,
            )
            .map_err(|e| {
                format!(
                    "4-oracle disagreement at {four_oracle_context}: source={:?} our={:?} other={:?}",
                    e.source, e.our_root, e.other_root
                )
            })
            .expect("4 oracles agree (Imt + chain + upstream + real Subsquid)");
            assert_eq!(
                real_subsquid, resp.root,
                "{context}: real Subsquid root must equal canonical fixture subsquid_root"
            );
        } else {
            eprintln!(
                "{context}: 4-oracle escalation SKIPPED (chain_root={} upstream_root={} real_subsquid_root={}); \
                 running 3-oracle assertion only. Run scripts/capture-real-oracle-roots.sh against operator's RPC to populate.",
                cp.chain_root.is_some(),
                cp.upstream_root.is_some(),
                cp.real_subsquid_root.is_some()
            );
        }
        tree_ok += 1;
    }
    assert_eq!(
        tree_ok,
        fixture.tree_checkpoints.len(),
        "every tree checkpoint must pass"
    );

    let mut list_ok = 0usize;
    for cp in &fixture.list_checkpoints {
        let our_root = replay_into_imt(&cp.leaves);
        let subsquid_root = rt
            .block_on(src.ppoi_list_root_at_height(cp.list_key, cp.block_height))
            .unwrap_or_else(|e| panic!("subsquid trait read for {}: {e:?}", cp.label));
        let context = format!(
            "{} (list_key={:?}, leaf_count={}, block={})",
            cp.label, cp.list_key, cp.leaf_count, cp.block_height
        );
        // Per-list path: chain root is structurally None (chain
        // doesn't store per-list IMT). Subsquid + Upstream cover.
        assert_three_oracle_byte_identity(
            our_root,
            None,
            cp.upstream_root,
            Some(subsquid_root),
            &context,
        )
        .map_err(|e| {
            format!(
                "subsquid list-oracle disagreement at {context}: source={:?} our={:?} other={:?}",
                e.source, e.our_root, e.other_root
            )
        })
        .expect("per-list oracles agree");
        list_ok += 1;
    }
    assert_eq!(
        list_ok,
        fixture.list_checkpoints.len(),
        "every list checkpoint must pass"
    );

    // Production subsquid client surface for per-list root queries
    // returns NotIndexed (upstream subsquid schema does not expose
    // per-list IMT roots; see SubsquidError::NotIndexed docstring).
    // Asserting this here catches a future schema-shape drift in
    // the trait impl that would silently start returning a wrong
    // value.
    let prod_client =
        raven_railgun_indexer::subsquid::SubsquidClient::new("https://squid.example.io/graphql");
    let any_list_key = fixture
        .list_checkpoints
        .first()
        .map_or([0u8; 32], |c| c.list_key);
    let prod_err = rt
        .block_on(prod_client.ppoi_list_root_at_height(any_list_key, 200))
        .expect_err("prod client returns NotIndexed for per-list root");
    assert!(
        matches!(prod_err, SubsquidError::NotIndexed(_)),
        "prod client must surface NotIndexed; got {prod_err:?}"
    );
}

#[test]
fn g5d_corrupt_subsquid_response_fails_oracle_assertion() {
    let fixture = load_fixture();
    let mut src = populate_subsquid_source(&fixture);
    let rt = tokio::runtime::Runtime::new().expect("tokio rt");

    let cp = fixture
        .tree_checkpoints
        .first()
        .expect("at least one tree checkpoint");
    let our_root = replay_into_imt(&cp.leaves);
    let mut corrupted = cp.subsquid_root;
    corrupted[7] ^= 0x01;
    let was_present = src.corrupt_tree_root(cp.tree_number, cp.block_height, corrupted);
    assert!(
        was_present,
        "fixture must have a populated entry for the corruption target"
    );

    let resp = rt
        .block_on(src.commitment_root_at_height(cp.tree_number, cp.block_height))
        .expect("corrupted source root present");
    assert_eq!(
        resp.root, corrupted,
        "subsquid corruption must take effect via the trait read"
    );

    let result = assert_three_oracle_byte_identity(
        our_root,
        cp.chain_root,
        cp.upstream_root,
        Some(resp.root),
        "subsquid-corruption-guard",
    );
    let err = result.expect_err("aggregator must catch the subsquid corruption");
    assert_eq!(
        err.source,
        OracleSource::Subsquid,
        "corruption attribution must name Subsquid"
    );
    assert_eq!(
        err.other_root, corrupted,
        "disagreement carries the corrupted byte"
    );
    assert_ne!(
        err.other_root, our_root,
        "disagreement is not byte-identical to local root"
    );
}

#[test]
fn g5d_corrupt_chain_root_fails_oracle_assertion() {
    let fixture = load_fixture();
    let cp = fixture
        .tree_checkpoints
        .first()
        .expect("at least one tree checkpoint");
    let our_root = replay_into_imt(&cp.leaves);
    let mut corrupted_chain = our_root;
    corrupted_chain[0] ^= 0x01;
    let result = assert_three_oracle_byte_identity(
        our_root,
        Some(corrupted_chain),
        cp.upstream_root,
        Some(cp.subsquid_root),
        "chain-corruption-guard",
    );
    let err = result.expect_err("aggregator must catch the chain corruption");
    assert_eq!(
        err.source,
        OracleSource::Chain,
        "corruption attribution must name Chain"
    );
    assert_eq!(
        err.other_root, corrupted_chain,
        "chain disagreement carries the corrupted byte"
    );
}

#[test]
fn g5d_corrupt_upstream_root_fails_oracle_assertion() {
    let fixture = load_fixture();
    let cp = fixture
        .list_checkpoints
        .first()
        .expect("at least one list checkpoint");
    let our_root = replay_into_imt(&cp.leaves);
    let mut corrupted_upstream = our_root;
    corrupted_upstream[15] ^= 0x10;
    let result = assert_three_oracle_byte_identity(
        our_root,
        None,
        Some(corrupted_upstream),
        Some(cp.subsquid_root),
        "upstream-corruption-guard",
    );
    let err = result.expect_err("aggregator must catch the upstream corruption");
    assert_eq!(
        err.source,
        OracleSource::Upstream,
        "corruption attribution must name Upstream"
    );
    assert_eq!(
        err.other_root, corrupted_upstream,
        "upstream disagreement carries the corrupted byte"
    );
}
