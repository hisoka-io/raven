//! The publicly exported X-Raven-Client-Id surface; the SessionMap and sweeper
//! internals are `pub(crate)` and covered by unit tests in `auth.rs`, which also
//! hold the `parse_client_id_header` cases formerly duplicated here byte for byte.

use raven_railgun_http::auth::X_RAVEN_CLIENT_ID;

// Owner ruling pending: no in-tree client sends this header and
// `HeaderMap::get` is case-insensitive, so the exact spelling has no in-tree
// oracle. Kept until the owner rules whether it pins an off-tree wire contract.
#[test]
fn header_name_constant_matches_canonical_spelling() {
    assert_eq!(X_RAVEN_CLIENT_ID, "X-Raven-Client-Id");
}
