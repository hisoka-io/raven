//! Serves a recorded capture of one Railgun PPOI list over the upstream node's JSON-RPC
//! methods, so tests, benchmarks and a local cold sync read real list data without loading the
//! live aggregator.
//!
//! The rows are the capture's own: signatures, roots and wire strings are what upstream served,
//! and nothing is generated. A [`Replay`] serves a prefix of the list and can be grown, so a
//! mirror can be driven through catch-up and then growth.
//!
//! Methods answered, each to the upstream node's contract (`packages/node/src/api` of
//! `private-proof-of-innocence`) and the aggregator's measured behaviour:
//! `ppoi_poi_events`, `ppoi_node_status`, `ppoi_validate_poi_merkleroots`, and the two proof
//! submissions, which a recording cannot accept and so refuses. No method reports a status for
//! an individual commitment.

#![deny(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::panic,
        clippy::unwrap_used,
        clippy::indexing_slicing
    )
)]

mod capture;
mod json;
mod server;

pub use capture::{
    parse_noncanonical_jsonl, read_events_bin, write_events_bin, Capture, ChainScope, EventRow,
    EventType, WireOverride, EVENTS_BIN_HEADER_BYTES, EVENTS_BIN_MAGIC, EVENTS_BIN_ROW_BYTES,
    EVENTS_BIN_VERSION,
};
pub use server::{bind, router, serve, Replay, Reply, MAX_EVENT_QUERY_RANGE_LENGTH};

/// Why a capture could not be loaded or served.
#[derive(thiserror::Error, Debug)]
pub enum ReplayError {
    /// A capture file could not be read.
    #[error("read {path}: {source}")]
    Io {
        /// The file.
        path: String,
        /// The OS error.
        source: std::io::Error,
    },
    /// `events.bin` is malformed or not a contiguous list from index 0.
    #[error("events.bin: {0}")]
    EventsBin(String),
    /// A `noncanonical.jsonl` override is malformed or disagrees with its row.
    #[error("noncanonical overrides: {0}")]
    Noncanonical(String),
    /// `manifest.json` is malformed or describes another list.
    #[error("{0}")]
    Manifest(String),
    /// The node-status recording cannot carry this list's status.
    #[error("node-status recording: {0}")]
    NodeStatus(String),
    /// A served row count outside what the capture allows.
    #[error("{0}")]
    Rows(String),
    /// Binding or serving the socket failed.
    #[error("{0}")]
    Bind(String),
}

/// Result alias for this crate.
pub type Result<T, E = ReplayError> = core::result::Result<T, E>;
