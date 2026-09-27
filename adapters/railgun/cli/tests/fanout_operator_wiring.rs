#![allow(clippy::expect_used, clippy::panic)]

#[path = "support/toy_server.rs"]
mod toy_server;

use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;

use raven_inspire::params::InspireVariant;
use raven_railgun_cli::serve_production_multi::{build_http_config, load_options_from_toml};
use raven_railgun_http::{inspire_router, HttpConfig};
use toy_server::{build_toy_pieces, ToyDbConfig, TOY_INSTANCE_ID};

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

/// One instance, with `fanout` appended to `[global]`.
fn multi_config(fanout: &str) -> tempfile::NamedTempFile {
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
{fanout}

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
fn operator_wiring_keeps_fanout_disabled_by_default_and_preserves_cap_validation() {
    let file = multi_config("");
    let defaulted = build_http_config(&load_options_from_toml(file.path()).expect("load TOML"));
    assert!(!defaulted.enable_fanout);
    assert_eq!(defaulted.max_fanout_shards, 16);
    defaulted.validate().expect("documented defaults are valid");

    let file = multi_config("max_fanout_shards = 0");
    let error = build_http_config(&load_options_from_toml(file.path()).expect("load TOML"))
        .validate()
        .expect_err("zero fanout cap must retain HttpConfig refusal");
    assert!(error.contains("max_fanout_shards must be > 0"), "{error}");
}

#[tokio::test]
async fn multi_instance_toml_opt_in_reaches_the_router_with_the_configured_cap() {
    let file = multi_config("enable_fanout = true\nmax_fanout_shards = 32");
    let options = load_options_from_toml(file.path()).expect("load TOML");
    let config = build_http_config(&options);
    assert!(config.enable_fanout);
    assert_eq!(config.max_fanout_shards, 32);
    assert_eq!(
        fanout_status(config).await,
        reqwest::StatusCode::BAD_REQUEST,
        "a mounted fanout route must decode/refuse the empty body instead of returning 404"
    );
}
