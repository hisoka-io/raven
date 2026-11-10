//! The versioned CRS a wallet decodes from a node. The decode path is in src/lib.rs.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _ = raven_fuzz::inspire_crs_blob(bytes);
});
