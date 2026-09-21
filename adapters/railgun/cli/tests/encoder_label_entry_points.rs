//! Every `EncoderKind` label is nameable from every entry point that can reach that encoder.

#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::io::Write;
use std::process::Command;

use raven_railgun_cli::auto_spawn_driver::{AutoSpawnRuntime, PpoiListTemplateRuntime};
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
        EncoderKind::PerListStatus { list_key },
        EncoderKind::PerListPath { list_key },
        EncoderKind::PerListPath10 { list_key },
        EncoderKind::PerListNode { list_key },
    ];
    // No wildcard: a new variant must fail to compile here until it joins the list above.
    for kind in &kinds {
        match kind {
            EncoderKind::PerLeafBc { .. }
            | EncoderKind::PerLeafPath { .. }
            | EncoderKind::PerNode { .. }
            | EncoderKind::PerListStatus { .. }
            | EncoderKind::PerListPath { .. }
            | EncoderKind::PerListPath10 { .. }
            | EncoderKind::PerListNode { .. } => {}
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

fn raven_railgun(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_raven-railgun"))
        .args(args)
        .env_remove("RAVEN_BEARER_TOKEN")
        .env_remove("RAVEN_RPC_URL")
        .output()
        .expect("spawn raven-railgun");
    assert!(
        !output.status.success(),
        "{args:?} must stop before doing any work"
    );
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// An unknown label is refused, so reaching the NEXT refusal proves the label parsed.
#[test]
fn migrate_encoder_names_every_encoder() {
    let data_dir = tempfile::tempdir().expect("tempdir");
    let data_dir = data_dir.path().to_str().expect("utf-8 tempdir");
    let tree_number = TREE_NUMBER.to_string();
    for kind in every_encoder_kind() {
        let label = kind.label();
        let stderr = raven_railgun(&[
            "migrate-encoder",
            "--data-dir",
            data_dir,
            "--to",
            label,
            "--tree-number",
            &tree_number,
            "--list-key",
            LIST_KEY_HEX,
        ]);
        assert!(
            stderr.contains("no manifest at"),
            "--to {label} must parse and stop at the empty data_dir: {stderr}"
        );
    }
    let stderr = raven_railgun(&[
        "migrate-encoder",
        "--data-dir",
        data_dir,
        "--to",
        "per-list-path11",
    ]);
    assert!(stderr.contains("unknown --encoder"), "{stderr}");
    assert!(
        stderr.contains("per-list-path10"),
        "the refusal must list every nameable label: {stderr}"
    );
}

#[test]
fn single_instance_serve_names_every_encoder() {
    let data_dir = tempfile::tempdir().expect("tempdir");
    let data_dir = data_dir.path().to_str().expect("utf-8 tempdir");
    let tree_number = TREE_NUMBER.to_string();
    for kind in every_encoder_kind() {
        let label = kind.label();
        let stderr = raven_railgun(&[
            "serve-production",
            "--rpc-url",
            "http://127.0.0.1:1",
            "--data-dir",
            data_dir,
            "--encoder",
            label,
            "--tree-number",
            &tree_number,
            "--list-key",
            LIST_KEY_HEX,
        ]);
        assert!(
            stderr.contains("no bearer token"),
            "--encoder {label} must parse and stop at the missing token: {stderr}"
        );
    }
}

fn ppoi_list_template(encoder: &str) -> PpoiListTemplateRuntime {
    PpoiListTemplateRuntime {
        template_id: "ppoi-template".to_owned(),
        list_key: list_key(),
        encoder: encoder.to_owned(),
        scheme_tag: "test".to_owned(),
        data_dir_template: "/tmp/raven-unused-{list_key}".to_owned(),
        entries: 65_536,
        entry_bytes: 512,
        channel_capacity: 16,
    }
}

#[test]
fn ppoi_list_template_resolves_every_ppoi_encoder_and_no_chain_encoder() {
    for kind in ppoi_kinds() {
        let resolved = ppoi_list_template(kind.label())
            .resolve_encoder()
            .unwrap_or_else(|e| panic!("{} must resolve: {e}", kind.label()));
        assert_eq!(resolved, kind);
    }
    for kind in chain_kinds() {
        let err = ppoi_list_template(kind.label())
            .resolve_encoder()
            .expect_err("a chain-tree label is not a PPOI template encoder");
        assert!(err.to_string().contains("per-list-path10"), "{err}");
    }
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

fn config_with(tables: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("tempfile");
    write!(
        file,
        r#"
[global]
bind = "127.0.0.1:0"
token = "encoder-label-test-token-padded-long"
rpc_url = "http://127.0.0.1:1"
railgun_proxy = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
chain_id = 1
start_block = 0
mirror_endpoint = "http://127.0.0.1:1"
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
verification_mode = "chain-root-history"
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
verification_mode = "upstream-signature"
data_source = {{ kind = "mirror", list_key = "{LIST_KEY_HEX}" }}
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

/// The loader vets a template's label at boot and the driver resolves it at spawn time,
/// possibly weeks later. A label the first accepts and the second refuses boots clean and
/// then never spawns.
#[test]
fn every_template_label_the_loader_accepts_resolves_at_spawn_time() {
    for kind in ppoi_kinds() {
        let label = kind.label();
        let tables = format!(
            r#"
[[ppoi_list_template]]
template_id = "ppoi-template"
list_key = "{LIST_KEY_HEX}"
encoder = "{label}"
data_dir_template = "/tmp/raven-unused-{{list_key}}"
{}"#,
            instance_table(EncoderKind::PerLeafBc { tree_number: 0 })
        );
        let file = config_with(&tables);
        let opts = load_options_from_toml(file.path())
            .unwrap_or_else(|e| panic!("template {label} must load: {e:#}"));
        let accepted = &opts.ppoi_list_templates[0];
        let resolved = ppoi_list_template(&accepted.encoder)
            .resolve_encoder()
            .unwrap_or_else(|e| panic!("loader accepted {label} but the driver refuses it: {e}"));
        assert_eq!(resolved, kind);
    }
}
