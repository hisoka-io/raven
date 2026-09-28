//! The shipped example's list, re-keyed to a provider whose signing key is public, so a test
//! upstream can serve rows the mirror accepts. The mirror verifies every row against the list
//! key, and no one outside the list's provider can sign for the shipped one.

// `#[path]`-included by several targets; each uses a different subset.
#![allow(dead_code, unreachable_pub)]

use raven_railgun_ppoi_mirror::test_signer::TestListSigner;
use serde_json::Value;

/// The list key the shipped example declares.
pub const SHIPPED_LIST_HEX: &str =
    "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";

/// [`provider`]'s list key, spelled out so a format string can name it.
pub const LIST_HEX: &str = "d9bf2148748a85c89da5aad8ee0b0fc2d105fd39d41a4c796536354f0ae2900c";

pub fn provider() -> TestListSigner {
    let provider = TestListSigner::new(0x0f);
    assert_eq!(
        provider.list_key_hex(),
        LIST_HEX,
        "LIST_HEX names another key"
    );
    provider
}

pub fn list_key() -> [u8; 32] {
    provider().list_key()
}

/// `body`, a config naming the shipped list, naming [`provider`]'s instead.
pub fn rekeyed(body: &str) -> String {
    assert!(
        body.contains(SHIPPED_LIST_HEX),
        "the config no longer names the shipped list {SHIPPED_LIST_HEX}"
    );
    body.replace(SHIPPED_LIST_HEX, LIST_HEX)
}

/// Row `index` of [`provider`]'s list, served with these strings and a type of `Shield`.
pub fn signed_row(index: u64, blinded_commitment: &str, validated_merkleroot: &str) -> Value {
    provider()
        .row(index, blinded_commitment, "Shield", validated_merkleroot)
        .expect("a row signs")
}
