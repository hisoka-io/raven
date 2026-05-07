//! Toy in-memory PIR-engine wiring used by `serve` + the walking-skeleton test.
//!
//! Record size 256 B: even sizes ≥ 32 B decrypt cleanly under TwoPacking + InspiRING.
//! 33 B fails due to slot-alignment (each 16-bit slot encodes 2 bytes; odd record_bytes leaves a
//! half-slot unrecoverable), not a γ-calibration bug.

#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]
#![allow(missing_docs)]

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::rlwe::RlweSecretKey;
use raven_inspire::ClientSession;
use raven_railgun_core::{AdapterError, InstanceId, Result};
use raven_railgun_engine::{
    inspire::{build_client_session, register_client_session, setup_state, RavenInspireScheme},
    Engine, InstanceRole, PirInstance,
};
use raven_railgun_http::{AppState, HttpConfig};

pub const TOY_DB_ENTRIES: usize = 256;
pub const TOY_ENTRY_BYTES: usize = 256;
pub const TOY_INSTANCE_ID: &str = "toy";
pub const SCHEME_NAME: &str = "raven-inspire";

#[derive(Clone, Debug)]
pub struct ToyDbConfig {
    pub entries: usize,
    pub entry_bytes: usize,
    pub variant: InspireVariant,
}

impl Default for ToyDbConfig {
    fn default() -> Self {
        Self {
            entries: TOY_DB_ENTRIES,
            entry_bytes: TOY_ENTRY_BYTES,
            variant: InspireVariant::TwoPacking,
        }
    }
}

#[allow(clippy::cast_possible_truncation)]
pub fn build_toy_database(entries: usize, entry_bytes: usize) -> Vec<u8> {
    (0..entries)
        .flat_map(|i| (0..entry_bytes).map(move |j| ((i + j) % 251) as u8))
        .collect()
}

pub struct ToyPieces {
    pub app_state: AppState<RavenInspireScheme>,
    pub client_session: ClientSession,
    pub secret_key: RlweSecretKey,
    pub params: InspireParams,
    pub config: ToyDbConfig,
    pub db: Vec<u8>,
}

impl std::fmt::Debug for ToyPieces {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToyPieces")
            .field("config", &self.config)
            .field("db_len", &self.db.len())
            .finish_non_exhaustive()
    }
}

pub fn build_toy_pieces(token: String, config: ToyDbConfig) -> Result<ToyPieces> {
    let params = InspireParams::secure_128_d2048();
    let db = build_toy_database(config.entries, config.entry_bytes);

    let (server_state, secret_key) = setup_state(&params, &db, config.entry_bytes, config.variant)?;

    let mut client_session =
        build_client_session((*server_state.crs).clone(), secret_key.clone(), &params)?;
    register_client_session(&mut client_session, &server_state)?;

    let mut engine: Engine<RavenInspireScheme> = Engine::new();
    engine.add_instance(PirInstance::new(
        InstanceId::new(TOY_INSTANCE_ID),
        InstanceRole::Static,
        server_state,
    ))?;

    let mut http_config = HttpConfig::demo(token);
    SCHEME_NAME.clone_into(&mut http_config.scheme_name);
    let app_state = AppState::new(engine, http_config)
        .map_err(|e| AdapterError::Internal(format!("AppState init: {e}")))?;

    Ok(ToyPieces {
        app_state,
        client_session,
        secret_key,
        params,
        config,
        db,
    })
}

pub fn build_toy_state(token: String) -> Result<AppState<RavenInspireScheme>> {
    let pieces = build_toy_pieces(token, ToyDbConfig::default())?;
    Ok(pieces.app_state)
}

#[derive(Clone, Debug)]
pub struct ToyServerOverrides {
    pub token: String,
    pub max_concurrent_queries: usize,
    pub rate_limit_rps: u64,
    pub rate_limit_burst: u32,
    pub session_ttl_secs: u64,
    pub session_lru_cap: usize,
}

pub fn build_toy_state_with_overrides(
    overrides: ToyServerOverrides,
) -> Result<AppState<RavenInspireScheme>> {
    let params = InspireParams::secure_128_d2048();
    let config = ToyDbConfig::default();
    let db = build_toy_database(config.entries, config.entry_bytes);
    let (server_state, secret_key) = raven_railgun_engine::inspire::setup_state(
        &params,
        &db,
        config.entry_bytes,
        config.variant,
    )?;

    let mut client_session = raven_railgun_engine::inspire::build_client_session(
        (*server_state.crs).clone(),
        secret_key,
        &params,
    )?;
    raven_railgun_engine::inspire::register_client_session(&mut client_session, &server_state)?;
    drop(client_session); // binary path discards: real wallets establish their own

    let mut engine: raven_railgun_engine::Engine<RavenInspireScheme> =
        raven_railgun_engine::Engine::new();
    engine.add_instance(raven_railgun_engine::PirInstance::new(
        InstanceId::new(TOY_INSTANCE_ID),
        raven_railgun_engine::InstanceRole::Static,
        server_state,
    ))?;

    let mut http_config = HttpConfig::demo(overrides.token);
    SCHEME_NAME.clone_into(&mut http_config.scheme_name);
    http_config.max_concurrent_queries = overrides.max_concurrent_queries.max(1);
    http_config.rate_limit_rps = overrides.rate_limit_rps;
    http_config.rate_limit_burst = overrides.rate_limit_burst;
    http_config.session_ttl_secs = overrides.session_ttl_secs;
    http_config.session_lru_cap = overrides.session_lru_cap;

    AppState::new(engine, http_config)
        .map_err(|e| AdapterError::Internal(format!("AppState init: {e}")))
}

pub fn into_internal<E: std::fmt::Display>(err: E) -> AdapterError {
    AdapterError::Internal(err.to_string())
}
