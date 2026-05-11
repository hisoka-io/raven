#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
    )
)]
#![allow(missing_docs)]
//! Pure-Rust iSimplePIR (eprint 2026/030 Construction 1), ported
//! from the `simplepir/` Go reference. Single-server PIR with
//! native incremental updates preserving `H = D . A` exactly
//! (Theorem 3).

pub mod error;
pub mod extract;
pub mod hint;
pub mod params;
pub mod query;
pub mod respond;
pub mod setup;
pub mod squish;
pub mod state;
pub mod update;
pub mod version;

pub use error::{IsimplePirError, Result};
pub use extract::extract;
pub use hint::ClientHint;
pub use params::{for_cell, LweParams, Table16Row, TABLE_16};
pub use query::{query, ClientQuery, ClientState};
pub use respond::{respond, ServerResponse};
pub use setup::{setup, setup_owned, ServerState, SetupOutput, SEED_BYTES};
pub use squish::{
    respond_packed, squish_db, unsquish_db, SquishedDatabase, SQUISH_BASIS, SQUISH_COMPRESSION,
};
pub use state::verify_hint_matches_db;
pub use update::{
    db_update_batch, db_update_delete, db_update_insert, db_update_modify, db_update_row_deletions,
    db_update_row_modifications, state_update_batch, state_update_entry, state_update_insert,
    state_update_row, DbBatchOp, EntryUpdate, InsertDelta, RowUpdate, UpdateBatch,
};
pub use version::HintVersion;
