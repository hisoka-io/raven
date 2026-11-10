//! `POST /v1/instance/{id}/session`: the packing-key upload. The decode path is in src/lib.rs.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _ = raven_fuzz::railgun_session_body(bytes);
});
