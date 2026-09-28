//! Every `EncoderKind` label is nameable from every entry point that can reach that encoder.

#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::io::Write;

use raven_railgun_cli::auto_spawn_driver::AutoSpawnRuntime;
use raven_railgun_cli::serve_production_multi::load_options_from_toml;
use raven_railgun_engine::pir_table::EncoderKind;

const LIST_KEY_HEX: &str = "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";
const TREE_NUMBER: u32 = 3;

fn list_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    for (slot, pair) in key.iter_mut().zip(LIST_KEY_HEX.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).expect("ascii hex");
        *slot = u8::from_str_radix(pair, 16).expect("hex byte");
    }
    key
}

fn every_encoder_kind() -> Vec<EncoderKind> {
    let list_key = list_key();
    let kinds = vec![
        EncoderKind::PerLeafBc {
            tree_number: TREE_NUMBER,
        },
        EncoderKind::PerLeafPath {
            tree_number: TREE_NUMBER,
        },
        EncoderKind::PerNode {
            tree_number: TREE_NUMBER,
        },
        EncoderKind::PerListPath10 { list_key },
    ];
    // No wildcard: a new variant must fail to compile here until it joins the list above.
    for kind in &kinds {
        match kind {
            EncoderKind::PerLeafBc { .. }
            | EncoderKind::PerLeafPath { .. }
            | EncoderKind::PerNode { .. }
            | EncoderKind::PerListPath10 { .. } => {}
        }
    }
    kinds
}

fn ppoi_kinds() -> Vec<EncoderKind> {
    every_encoder_kind()
        .into_iter()
        .filter(|kind| kind.chain_tree_number().is_none())
        .collect()
}

fn chain_kinds() -> Vec<EncoderKind> {
    every_encoder_kind()
        .into_iter()
        .filter(|kind| kind.chain_tree_number().is_some())
        .collect()
}

#[test]
fn auto_spawn_resolves_every_chain_encoder_and_no_ppoi_encoder() {
    let runtime = |encoder: &str| AutoSpawnRuntime {
        data_dir_template: "/tmp/raven-unused-{tree_number}".to_owned(),
        encoder: encoder.to_owned(),
        scheme_tag: "test".to_owned(),
        entries: 65_536,
        entry_bytes: 512,
        channel_capacity: 16,
        verification_cadence_n: 0,
        max_instance_count: None,
        cooldown: None,
        session_limits: raven_railgun_engine::session_pool::SessionStoreLimits::default(),
    };
    for kind in chain_kinds() {
        let resolved = runtime(kind.label())
            .resolve_encoder(TREE_NUMBER)
            .unwrap_or_else(|e| panic!("{} must resolve: {e}", kind.label()));
        assert_eq!(resolved, kind);
    }
    for kind in ppoi_kinds() {
        runtime(kind.label())
            .resolve_encoder(TREE_NUMBER)
            .expect_err("a PPOI label is not an auto-spawn encoder");
    }
}

/// The chain settings only when `tables` indexes a commit tree; the loader refuses them otherwise.
fn config_with(tables: &str) -> tempfile::NamedTempFile {
    let chain = if tables.contains(r#"kind = "indexer""#) {
        "rpc_url = \"http://127.0.0.1:1\"\n\
         railgun_proxy = \"0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9\"\nstart_block = 0"
    } else {
        ""
    };
    let mut file = tempfile::NamedTempFile::new().expect("tempfile");
    write!(
        file,
        r#"
[global]
bind = "127.0.0.1:0"
token = "encoder-label-test-token-padded-long"
chain_id = 1
mirror_endpoint = "http://127.0.0.1:1"
{chain}
{tables}
"#
    )
    .expect("write config");
    file
}

fn instance_table(kind: EncoderKind) -> String {
    let label = kind.label();
    match kind.chain_tree_number() {
        Some(tree) => format!(
            r#"
[[instance]]
id = "under-test"
role = "live"
encoder = "{label}"
tree_number = {tree}
data_dir = "/tmp/raven-unused"
data_source = {{ kind = "indexer", filter = {{ tree_number = {tree} }} }}
"#
        ),
        None => format!(
            r#"
[[instance]]
id = "under-test"
role = "live"
encoder = "{label}"
list_key = "{LIST_KEY_HEX}"
data_dir = "/tmp/raven-unused"
data_source = {{ kind = "mirror", list_key = "{LIST_KEY_HEX}", block = 0 }}
"#
        ),
    }
}

#[test]
fn config_file_instance_names_every_encoder() {
    for kind in every_encoder_kind() {
        let file = config_with(&instance_table(kind));
        let opts = load_options_from_toml(file.path())
            .unwrap_or_else(|e| panic!("{} must load: {e:#}", kind.label()));
        assert_eq!(opts.instances[0].encoder, kind);
    }
}
