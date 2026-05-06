//! Library surface: toy-server bootstrap + production serve paths for integration tests.

#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]
#![allow(missing_docs)]

pub mod auto_spawn;
pub mod auto_spawn_driver;
pub mod migrate_encoder;
pub mod serve_production;
pub mod serve_production_multi;
pub mod snapshot_port;
pub mod toy_server;

pub use toy_server::{
    build_toy_state, build_toy_state_with_overrides, ToyDbConfig, ToyServerOverrides,
    TOY_DB_ENTRIES, TOY_ENTRY_BYTES,
};
