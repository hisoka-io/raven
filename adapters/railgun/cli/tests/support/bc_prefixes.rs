//! Reads `GET /v1/poi/:list_key_hex/bc-prefixes`, the list index a wallet walks: one block's
//! rows per response, each the first bytes of its blinded commitment, in global index order
//! from the `since` cursor.

// `#[path]`-included by several targets; each uses a different subset.
#![allow(dead_code, unreachable_pub)]

use raven_railgun_http::poi_shim::BC_INDEX_PREFIX_BYTES;
use reqwest::StatusCode;

pub type Prefix = [u8; BC_INDEX_PREFIX_BYTES];

/// One response. A cursor the route did not send is `None`: a refusal carries none, and a
/// sealed segment no list-wide total.
#[derive(Debug)]
pub struct Segment {
    pub status: StatusCode,
    pub base: Option<u64>,
    pub next: Option<u64>,
    pub total: Option<u64>,
    pub rows: Vec<Prefix>,
}

pub fn prefix_of(bc: &[u8; 32]) -> Prefix {
    *bc.first_chunk().expect("a prefix is shorter than a row")
}

pub async fn read_segment(response: reqwest::Response) -> Segment {
    let status = response.status();
    let cursor = |name: &str| {
        response.headers().get(name).map(|value| {
            value
                .to_str()
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or_else(|| panic!("{name} is not an integer: {value:?}"))
        })
    };
    let (base, next, total) = (
        cursor("x-raven-index-base"),
        cursor("x-raven-index-next"),
        cursor("x-raven-index-total"),
    );
    let body = response.bytes().await.expect("bc-prefixes body");
    let (rows, partial) = body.as_chunks::<BC_INDEX_PREFIX_BYTES>();
    assert!(partial.is_empty(), "a bc-prefixes body is whole rows");
    let rows = rows.to_vec();
    Segment {
        status,
        base,
        next,
        total,
        rows,
    }
}
