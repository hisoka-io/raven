//! Integration tests for the publicly exported X-Raven-Client-Id surface.
//!
//! The SessionMap + sweeper internals live behind `pub(crate)` and are
//! covered by unit tests in `auth.rs`. This integration suite exercises
//! the public re-exports the orchestrator and external consumers rely on:
//!
//! - [`raven_railgun_http::auth::X_RAVEN_CLIENT_ID`] header name.
//! - [`raven_railgun_http::auth::parse_client_id_header`] parser.

use http::{HeaderMap, HeaderName, HeaderValue};
use raven_railgun_http::auth::{parse_client_id_header, X_RAVEN_CLIENT_ID};

#[test]
fn header_name_constant_matches_canonical_spelling() {
    assert_eq!(X_RAVEN_CLIENT_ID, "X-Raven-Client-Id");
}

#[test]
fn parse_client_id_header_accepts_hyphenated_uuid() {
    let mut headers = HeaderMap::new();
    let name = HeaderName::from_static("x-raven-client-id");
    let value = HeaderValue::from_static("550e8400-e29b-41d4-a716-446655440000");
    headers.insert(name, value);
    let id = parse_client_id_header(&headers);
    assert_eq!(
        id,
        [
            0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44,
            0x00, 0x00,
        ]
    );
}

#[test]
fn parse_client_id_header_accepts_unhyphenated_hex() {
    let mut headers = HeaderMap::new();
    let name = HeaderName::from_static("x-raven-client-id");
    let value = HeaderValue::from_static("550e8400e29b41d4a716446655440000");
    headers.insert(name, value);
    let id = parse_client_id_header(&headers);
    assert_eq!(
        id,
        [
            0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44,
            0x00, 0x00,
        ]
    );
}

#[test]
fn parse_client_id_header_absent_returns_zero() {
    let headers = HeaderMap::new();
    assert_eq!(parse_client_id_header(&headers), [0u8; 16]);
}

#[test]
fn parse_client_id_header_short_returns_zero() {
    // 30 hex chars - below the 32-char floor.
    let mut headers = HeaderMap::new();
    let name = HeaderName::from_static("x-raven-client-id");
    let value = HeaderValue::from_static("0102030405060708090a0b0c0d0e0f");
    headers.insert(name, value);
    assert_eq!(parse_client_id_header(&headers), [0u8; 16]);
}

#[test]
fn parse_client_id_header_garbage_returns_zero() {
    let mut headers = HeaderMap::new();
    let name = HeaderName::from_static("x-raven-client-id");
    let value = HeaderValue::from_static("not-a-uuid");
    headers.insert(name, value);
    assert_eq!(parse_client_id_header(&headers), [0u8; 16]);
}
