//! Every answer a Howl node sends, as a wallet decodes it. The decode path is in src/lib.rs.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _ = raven_fuzz::howl_answer(bytes);
});
