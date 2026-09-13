#![allow(clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;

use raven_inspire::params::InspireVariant;
use raven_railgun_cli::serve_production::{
    build_http_config as build_single_http_config, ProductionServeOptions,
};
use raven_railgun_cli::serve_production_multi::{
    build_http_config as build_multi_http_config, load_options_from_toml,
};
use raven_railgun_cli::toy_server::{build_toy_pieces, ToyDbConfig, TOY_INSTANCE_ID};
use raven_railgun_engine::pir_table::EncoderKind;
use raven_railgun_http::{inspire_router, HttpConfig};

const TOKEN: &str = "fanout-operator-wiring-token";

async fn fanout_status(config: HttpConfig) -> reqwest::StatusCode {
    let mut pieces = build_toy_pieces(
        TOKEN.to_owned(),
        ToyDbConfig {
            entries: 256,
            entry_bytes: 32,
            variant: InspireVariant::TwoPacking,
        },
    )
    .expect("toy pieces");
    pieces.app_state.config = Arc::new(config);
    let router = inspire_router(pieces.app_state).expect("router");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let address = listener.local_addr().expect("local address");
    let server = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    let response = reqwest::Client::new()
        .post(format!(
            "http://{address}/v1/instance/{TOY_INSTANCE_ID}/fanout"
        ))
        .bearer_auth(TOKEN)
        .body(Vec::<u8>::new())
        .send()
        .await
        .expect("fanout request");
    server.abort();
    let _ = server.await;
    response.status()
}

fn single_options(dir: &std::path::Path) -> ProductionServeOptions {
    ProductionServeOptions {
        bind: "127.0.0.1:0".parse().expect("address"),
        token: TOKEN.to_owned(),
        rpc_url: "http://127.0.0.1:1".to_owned(),
        railgun_proxy: "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9".to_owned(),
        chain_id: 1,
        start_block: 0,
        mirror_endpoint: "http://127.0.0.1:1".to_owned(),
        list_key: "0".repeat(64),
        data_dir: dir.to_path_buf(),
        instance_id: TOY_INSTANCE_ID.to_owned(),
        max_concurrent_queries: 4,
        respond_timeout_secs: 30,
        entries: 256,
        entry_bytes: 32,
        encoder: EncoderKind::PerLeafBc { tree_number: 0 },
        session_eviction_interval_secs: 0,
        metrics_public: false,
        enable_fanout: true,
        max_fanout_shards: 32,
    }
}

fn multi_config() -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("config file");
    write!(
        file,
        r#"
[global]
bind = "127.0.0.1:0"
token = "{TOKEN}"
rpc_url = "http://127.0.0.1:1"
railgun_proxy = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
chain_id = 1
start_block = 0
mirror_endpoint = "http://127.0.0.1:1"
enable_fanout = true
max_fanout_shards = 32

[[instance]]
id = "toy"
role = "static"
encoder = "per-leaf-bc"
tree_number = 0
record_size = 32
entries = 256
data_dir = "/tmp/raven-fanout-operator-wiring"
verification_mode = "chain-root-history"
data_source = {{ kind = "indexer", filter = {{ tree_number = 0 }} }}
"#
    )
    .expect("write config");
    file.flush().expect("flush config");
    file
}

#[test]
fn serve_production_clap_exposes_explicit_fanout_controls() {
    let output = Command::new(env!("CARGO_BIN_EXE_raven-railgun"))
        .args(["serve-production", "--help"])
        .output()
        .expect("run help");
    assert!(output.status.success(), "serve-production --help failed");
    let stdout = String::from_utf8(output.stdout).expect("utf8 help");
    let option_names = stdout
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|token| token.starts_with("--"))
        .collect::<Vec<_>>();
    assert!(option_names.contains(&"--enable-fanout"), "{stdout}");
    assert!(option_names.contains(&"--max-fanout-shards"), "{stdout}");
}

#[test]
fn operator_wiring_keeps_fanout_disabled_by_default_and_preserves_cap_validation() {
    let dir = tempfile::tempdir().expect("data dir");
    let mut options = single_options(dir.path());
    options.enable_fanout = false;
    options.max_fanout_shards = 16;
    let defaulted = build_single_http_config(&options);
    assert!(!defaulted.enable_fanout);
    assert_eq!(defaulted.max_fanout_shards, 16);
    defaulted.validate().expect("documented defaults are valid");

    options.max_fanout_shards = 0;
    let error = build_single_http_config(&options)
        .validate()
        .expect_err("zero fanout cap must retain HttpConfig refusal");
    assert!(error.contains("max_fanout_shards must be > 0"), "{error}");
}

#[tokio::test]
async fn single_instance_opt_in_reaches_the_router_with_the_configured_cap() {
    let dir = tempfile::tempdir().expect("data dir");
    let config = build_single_http_config(&single_options(dir.path()));
    assert!(config.enable_fanout);
    assert_eq!(config.max_fanout_shards, 32);
    assert_eq!(
        fanout_status(config).await,
        reqwest::StatusCode::BAD_REQUEST,
        "a mounted fanout route must decode/refuse the empty body instead of returning 404"
    );
}

#[tokio::test]
async fn multi_instance_toml_opt_in_reaches_the_router_with_the_configured_cap() {
    let file = multi_config();
    let options = load_options_from_toml(file.path()).expect("load TOML");
    let config = build_multi_http_config(&options);
    assert!(config.enable_fanout);
    assert_eq!(config.max_fanout_shards, 32);
    assert_eq!(
        fanout_status(config).await,
        reqwest::StatusCode::BAD_REQUEST,
        "a mounted fanout route must decode/refuse the empty body instead of returning 404"
    );
}
