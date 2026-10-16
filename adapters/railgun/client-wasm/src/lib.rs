//! WASM client surface: `raven-client`'s PIR query/extract exports, byte-stable
//! through the re-export.
//!
//! A client builds its packing key only under a secret it draws itself. Two keys under one
//! secret share the CRS mask and leak it, so this build links no entry point that takes a
//! caller's secret. The session the client builds:
//!
//! ```
//! # use raven_inspire::{math::GaussianSampler, params::InspireParams, setup, ClientSession};
//! # let params = InspireParams { ring_dim: 256, ..InspireParams::secure_128_d2048() };
//! # let mut sampler = GaussianSampler::new(params.sigma);
//! # let (crs, _, secret) = setup(&params, &vec![0u8; params.ring_dim * 32], 32, &mut sampler)?;
//! # drop(secret);
//! let session = ClientSession::with_fresh_secret(crs)?;
//! # assert!(session.has_inspiring_packing());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! and the one it cannot:
//!
//! ```compile_fail,E0599
//! # use raven_inspire::{math::GaussianSampler, params::InspireParams, setup, ClientSession};
//! # let params = InspireParams { ring_dim: 256, ..InspireParams::secure_128_d2048() };
//! # let mut sampler = GaussianSampler::new(params.sigma);
//! # let (crs, _, secret) = setup(&params, &vec![0u8; params.ring_dim * 32], 32, &mut sampler)?;
//! let session = ClientSession::new(crs, secret, &mut sampler)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub use raven_client::*;
