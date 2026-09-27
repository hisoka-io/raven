//! Toy in-memory PIR-engine wiring for the HTTP integration tests.
//!
//! Record size must be even: each 16-bit TwoPacking slot encodes 2 bytes, so an
//! odd record_bytes leaves a half-slot unrecoverable on decrypt.

// `#[path]`-included by several targets; each uses a different subset.
#![allow(dead_code, unreachable_pub)]

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::rlwe::RlweSecretKey;
use raven_inspire::ClientSession;
use raven_railgun_core::{AdapterError, InstanceId, Result};
use raven_railgun_engine::{
    inspire::{
        build_client_session, build_seeded_query, register_client_session, setup_state,
        RavenInspireScheme,
    },
    Engine, InstanceRole, PirInstance,
};
use raven_railgun_http::{write_versioned, AppState, HttpConfig};

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
    pub session_registration_body: Vec<u8>,
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
    let (_, registration_query) =
        build_seeded_query(&client_session, server_state.shard_config(), 0, &params)?;
    let registration_keys = registration_query.inspiring_packing_keys.ok_or_else(|| {
        AdapterError::Internal(
            "toy client session produced no packing keys for HTTP registration".to_owned(),
        )
    })?;
    let session_registration_body = write_versioned(&registration_keys).map_err(|error| {
        AdapterError::Internal(format!("toy session registration wire: {error}"))
    })?;
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
        session_registration_body,
        secret_key,
        params,
        config,
        db,
    })
}
