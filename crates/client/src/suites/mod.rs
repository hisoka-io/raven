//! Suites that run at ring dimension 256, below the parameter floors, so they build only here.

mod client_entropy_kat;
mod crs_binding;
mod panic_safety;
mod parity_native_vs_wasm;
mod query_generation_budget;
mod session_handshake;
mod session_params_drift;
mod session_serde_round_trip;
mod wasm_client_roundtrip;
