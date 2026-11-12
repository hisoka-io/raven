//! The body a session uploads to register its packing keys, pinned to bytes recorded from the
//! key build that expanded every rotation. A faster build must upload the same key.
//!
//! These run at the shipped ring, where the upload is the one a wallet sends, natively and
//! as wasm.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use raven_inspire::math::GaussianSampler;
use raven_inspire::params::InspireParams;
use raven_inspire::rgsw::GadgetVector;
use raven_inspire::rlwe::RlweSecretKey;
use raven_inspire::{num_columns, ClientSession, ServerCrs};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;

/// `(entry bytes, seed, body length, FNV-1a 64 of the body)`.
const RECORDED_UPLOADS: [(usize, u64, usize, u64); 9] = [
    (32, 1, 46_254, 0x6081_d01b_d465_d0f3),
    (32, 2, 46_254, 0xa302_261a_b8e8_b45a),
    (32, 3, 46_254, 0x6c73_c6bf_7401_cfc1),
    (256, 1, 46_254, 0x81c6_0d33_745a_63b7),
    (256, 2, 46_254, 0x3133_e64c_33d2_c15a),
    (256, 3, 46_254, 0x627c_7b56_5661_aaac),
    (512, 1, 46_254, 0x0825_3511_66b4_6a0b),
    (512, 2, 46_254, 0x9ea1_0fa7_c735_97e5),
    (512, 3, 46_254, 0x7ad1_b7be_bc0e_5dba),
];

fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

fn upload(entry_bytes: usize, seed: u64) -> Vec<u8> {
    let params = InspireParams::d2048();
    // The CRS as a wallet receives it: parameters and public seeds, no server-side tables.
    let crs = ServerCrs {
        rgsw_gadget: GadgetVector::new(params.gadget_base, params.query_gadget_len, params.q),
        galois_keys: Vec::new(),
        inspiring_pack_params: None,
        inspiring_packing_key: None,
        inspiring_w_seed: [u8::try_from(seed).expect("small seed"); 32],
        inspiring_v_seed: [0; 32],
        inspiring_num_columns: num_columns(entry_bytes),
        params: params.clone(),
    };
    let mut sampler = GaussianSampler::with_seed(params.sigma, seed + 1000);
    let secret_key = RlweSecretKey::generate(&params, &mut sampler);
    let session = ClientSession::new(crs, secret_key, &mut sampler).expect("session");
    crate::session_registration_body(&session).expect("registration body")
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn the_uploaded_packing_keys_are_the_recorded_bytes() {
    for (entry_bytes, seed, len, digest) in RECORDED_UPLOADS {
        let body = upload(entry_bytes, seed);
        assert_eq!(
            (body.len(), fnv1a(&body)),
            (len, digest),
            "{entry_bytes} B rows, seed {seed}"
        );
    }
}

/// The comparison above must be able to fail: one flipped bit anywhere in the key moves it.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn the_recorded_digest_moves_with_one_bit_of_the_key() {
    let (entry_bytes, seed, len, digest) = RECORDED_UPLOADS[8];
    let body = upload(entry_bytes, seed);
    for at in [2, len / 2, len - 1] {
        let mut flipped = body.clone();
        flipped[at] ^= 1;
        assert_ne!(fnv1a(&flipped), digest, "byte {at}");
    }
    assert_ne!(
        fnv1a(&upload(entry_bytes, seed + 1)),
        digest,
        "another key under another seed"
    );
}
