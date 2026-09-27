//! Boot-path rejection of illegal PIR cell shapes.
//!
//! An illegal record width returns every byte wrong with no query-time error, so
//! boot is the only place it can be caught.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::Path;

use raven_railgun_cli::serve_production_multi::{load_options_from_toml, run_with_listener};

const NOTE_RECORD_BYTES: usize = 328;
/// `InspireParams::secure_128_d2048().ring_dim`, the only legal rows-per-shard.
const ROWS_PER_SHARD: u32 = 2048;
const LIST_KEY_HEX: &str = "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";

/// Boots `config` with no workers and returns the refusal it must end in.
async fn boot_error(config: &Path) -> String {
    let mut opts = load_options_from_toml(config).expect("parse config");
    opts.entries = 65_536;
    opts.skip_chain_workers = true;
    opts.skip_mirror_workers = true;
    for inst in &mut opts.instances {
        inst.use_flock = false;
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let err = run_with_listener(opts, listener, std::future::ready(()))
        .await
        .expect_err("an illegal cell shape must refuse to boot");
    format!("{err:#}")
}

#[tokio::test]
async fn serve_production_multi_rejects_an_illegal_global_record_size() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = write_single_instance_config(tmp.path(), NOTE_RECORD_BYTES, ROWS_PER_SHARD);
    let msg = boot_error(&config).await;
    // 328 induces 164 columns, off the power-of-two law; 512 is the next legal width.
    for needle in ["328", "164", "512", "leaf-bc-gate"] {
        assert!(
            msg.contains(needle),
            "rejection must name {needle} (width, columns, next legal width, instance): {msg}"
        );
    }
}

/// An encoder whose row layout pins its width must refuse a cell of another width instead of
/// serving rows of its own width out of it.
#[tokio::test]
async fn serve_production_multi_rejects_a_path10_block_at_a_width_its_rows_do_not_have() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = tmp.path().join("config.toml");
    let body = format!(
        r#"
[global]
bind = "127.0.0.1:0"
token = "cell-width-boot-gate-token-padded"
chain_id = 1
mirror_endpoint = "http://127.0.0.1:1"
use_flock = false

[[instance]]
id = "ppoi-paths-gate"
role = "live"
encoder = "per-list-path10"
list_key = "{LIST_KEY_HEX}"
record_size = 32
data_dir = "{data_dir}/ppoi-paths-gate"
data_source = {{ kind = "mirror", list_key = "{LIST_KEY_HEX}", block = 0 }}
"#,
        data_dir = tmp.path().display()
    );
    std::fs::write(&config, body).expect("write config");
    restrict_to_owner(&config);
    let msg = boot_error(&config).await;
    for needle in ["ppoi-paths-gate", "per-list-path10", "512", "requested 32"] {
        assert!(
            msg.contains(needle),
            "rejection must name {needle} (instance, encoder, its width, the configured one): {msg}"
        );
    }
}

/// Rows-per-shard below `ring_dim` narrows every shard's row window while both the
/// re-encode and query paths still return success.
#[tokio::test]
async fn serve_production_multi_rejects_an_under_width_rows_per_shard() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = write_single_instance_config(tmp.path(), 512, ROWS_PER_SHARD / 2);
    let msg = boot_error(&config).await;
    for needle in ["1024", "2048", "leaf-bc-gate", "entries_per_shard"] {
        assert!(
            msg.contains(needle),
            "rejection must name {needle} (supplied rows, required rows, instance, config key): {msg}"
        );
    }
}

/// `per-leaf-bc` takes `[global].record_size` as given; every PPOI encoder pins its own width.
fn write_single_instance_config(
    dir: &Path,
    record_size: usize,
    entries_per_shard: u32,
) -> std::path::PathBuf {
    let body = format!(
        r#"
[global]
bind = "127.0.0.1:0"
token = "cell-width-boot-gate-token-padded"
rpc_url = "http://127.0.0.1:1"
railgun_proxy = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
chain_id = 1
start_block = 0
mirror_endpoint = "http://127.0.0.1:1"
record_size = {record_size}
entries_per_shard = {entries_per_shard}
use_flock = false

[[instance]]
id = "leaf-bc-gate"
role = "live"
encoder = "per-leaf-bc"
tree_number = 0
data_dir = "{data_dir}/leaf-bc-gate"
data_source = {{ kind = "indexer", filter = {{ tree_number = 0 }} }}
"#,
        data_dir = dir.display()
    );
    let path = dir.join("config.toml");
    std::fs::write(&path, body).expect("write config");
    restrict_to_owner(&path);
    path
}

/// The parser refuses a group- or world-readable config carrying an inline token.
fn restrict_to_owner(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("fixture config must be owner-only");
    }
    #[cfg(not(unix))]
    let _ = path;
}
