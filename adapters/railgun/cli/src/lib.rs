//! Library surface: the production serve path and its helpers, for the binary and integration tests.

#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]
#![allow(missing_docs)]

pub mod auto_spawn;
pub mod auto_spawn_driver;
pub mod bearer_token;
pub mod bootstrap_subsquid;
pub mod rpc_pool_array_config;
pub mod serve_production_multi;
