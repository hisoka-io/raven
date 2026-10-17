//! Every route's bytes, written out by hand from the documented layout and compared with
//! the encoder; then decoded back. A layout change fails here before it reaches a wallet.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use howl_wire::{
    padded_len, Answer, Body, Header, KeySource, Kind, LeafBlock, Notes, P16Batch, P16Query,
    Params, PrefixSegment, RequestPrefix, Session, UpperNodes, WireError, HEADER_BYTES, LADDER,
    P16_KEY_BYTES, P16_QUERY_BYTES, P16_RESPONSE_BYTES, PARAM_SET_D2048_CELL256,
    PARAM_SET_D2048_CELL256_P16, RECORD_BYTES,
};

const LEAF_COUNT: u64 = 0x0102_0304_0506_0708;
const BLOCK: u64 = 0x1112_1314_1516_1718;
const ROOT: [u8; 32] = [0xaa; 32];

/// The header written out field by field: version 1, parameter set 1, the route, three
/// zero bytes, the leaf count, the block and the root, all big-endian.
fn header(kind: u8) -> Vec<u8> {
    let mut out = vec![0x00, 0x01, 0x00, 0x01, kind, 0x00, 0x00, 0x00];
    out.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    out.extend_from_slice(&[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]);
    out.extend_from_slice(&ROOT);
    out
}

fn answer(body: Body) -> Answer {
    Answer {
        param_set: PARAM_SET_D2048_CELL256,
        leaf_count: LEAF_COUNT,
        block: BLOCK,
        root: ROOT,
        body,
    }
}

fn pinned(body: Body, kind: u8, tail: &[u8]) {
    let answer = answer(body);
    let mut expected = header(kind);
    expected.extend_from_slice(tail);
    let encoded = answer.encode();
    assert_eq!(encoded, expected, "route {kind}");
    assert_eq!(Answer::decode(&encoded).expect("decodes"), answer);
    // Every strict prefix is refused, and so is one byte more.
    for cut in [0, 1, HEADER_BYTES - 1, encoded.len() - 1] {
        if cut < encoded.len() && !(kind == 8 && cut == HEADER_BYTES) {
            assert!(
                Answer::decode(&encoded[..cut]).is_err(),
                "route {kind} cut at {cut}"
            );
        }
    }
    let mut longer = encoded;
    longer.push(0);
    assert!(matches!(
        Answer::decode(&longer),
        Err(WireError::Trailing { .. })
    ));
}

#[test]
fn the_header_is_56_bytes_in_a_fixed_order() {
    let h = Header {
        param_set: PARAM_SET_D2048_CELL256,
        kind: Kind::Sync,
        leaf_count: LEAF_COUNT,
        block: BLOCK,
        root: ROOT,
    };
    assert_eq!(h.encode().to_vec(), header(5));
    assert_eq!(HEADER_BYTES, 56);
    let mut other_version = header(5);
    other_version[1] = 2;
    assert_eq!(
        Header::decode(&other_version),
        Err(WireError::Version { got: 2 })
    );
    let mut reserved = header(5);
    reserved[6] = 1;
    assert!(Header::decode(&reserved).is_err());
    let mut unknown = header(5);
    unknown[4] = 99;
    assert_eq!(Header::decode(&unknown), Err(WireError::Kind(99)));
}

#[test]
fn params_bytes() {
    pinned(
        Body::Params(Params {
            entry_bytes: 256,
            rows_per_shard: 2_048,
            ladder_cap: 16,
            session_ttl_secs: 3_600,
            crs: vec![0xc0, 0xc1, 0xc2],
        }),
        1,
        &[
            0, 0, 1, 0, // entry bytes
            0, 0, 8, 0, // rows per shard
            0, 16, // ladder cap
            0, 0, 0x0e, 0x10, // ttl
            0, 0, 0, 3, // crs length
            0xc0, 0xc1, 0xc2,
        ],
    );
}

#[test]
fn prefix_segment_bytes() {
    let mut tail = vec![0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 9];
    tail.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    pinned(
        Body::Prefixes(PrefixSegment {
            base: 7,
            next: 9,
            rows: (1..=12).collect(),
        }),
        2,
        &tail,
    );
}

#[test]
fn leaf_block_bytes() {
    let mut tail = vec![0, 0, 0, 3, 0, 0, 0, 2];
    tail.extend_from_slice(&[0x31; 32]);
    tail.extend_from_slice(&[0x32; 32]);
    let mut leaves = vec![0x31; 32];
    leaves.extend_from_slice(&[0x32; 32]);
    pinned(
        Body::Block(LeafBlock {
            block_index: 3,
            leaves,
        }),
        3,
        &tail,
    );
}

#[test]
fn upper_bytes() {
    let mut tail = vec![0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 5];
    tail.extend_from_slice(&[0x44; 32]);
    pinned(
        Body::Upper(UpperNodes {
            base: 4,
            next: 5,
            nodes: vec![0x44; 32],
        }),
        4,
        &tail,
    );
}

#[test]
fn sync_bytes() {
    let mut tail = vec![0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2];
    tail.extend_from_slice(&[9; 6]);
    tail.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    tail.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
    tail.extend_from_slice(&[0x55; 32]);
    pinned(
        Body::Sync {
            prefixes: PrefixSegment {
                base: 1,
                next: 2,
                rows: vec![9; 6],
            },
            upper: UpperNodes {
                base: 0,
                next: 0,
                nodes: Vec::new(),
            },
            newest: LeafBlock {
                block_index: 0,
                leaves: vec![0x55; 32],
            },
        },
        5,
        &tail,
    );
}

#[test]
fn session_bytes() {
    pinned(
        Body::Session(Session {
            handle: 0x0a0b,
            ttl_secs: 3_600,
        }),
        6,
        &[0, 0, 0, 0, 0, 0, 0x0a, 0x0b, 0, 0, 0x0e, 0x10],
    );
}

#[test]
fn notes_bytes() {
    pinned(
        Body::Notes(Notes {
            responses: vec![vec![0xd0, 0xd1], vec![0xd2]],
        }),
        7,
        &[0, 2, 0, 0, 0, 2, 0xd0, 0xd1, 0, 0, 0, 1, 0xd2],
    );
}

#[test]
fn stale_is_the_header_alone() {
    pinned(Body::Stale, 8, &[]);
}

#[test]
fn a_request_starts_with_version_and_parameter_set() {
    let prefix = RequestPrefix {
        param_set: PARAM_SET_D2048_CELL256,
    };
    assert_eq!(prefix.encode(), [0, 1, 0, 1]);
    let (decoded, rest) = RequestPrefix::decode(&[0, 1, 0, 1, 0xee]).expect("decodes");
    assert_eq!((decoded, rest), (prefix, &[0xee][..]));
    assert_eq!(
        RequestPrefix::decode(&[0, 2, 0, 1]),
        Err(WireError::Version { got: 2 })
    );
    assert!(RequestPrefix::decode(&[0, 1, 0]).is_err());
}

#[test]
fn malformed_runs_are_refused() {
    // A segment that ends before it starts, and a block claiming more than 1,024 leaves.
    let mut backwards = header(2);
    backwards.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 7]);
    assert!(Answer::decode(&backwards).is_err());
    let mut huge = header(3);
    huge.extend_from_slice(&[0, 0, 0, 0, 0, 0, 4, 1]);
    assert!(Answer::decode(&huge).is_err());
}

#[test]
fn the_ladder_pads_to_powers_of_two_and_stops_at_sixteen() {
    assert_eq!(LADDER, [1, 2, 4, 8, 16]);
    let padded: Vec<Option<usize>> = (0..=17).map(padded_len).collect();
    assert_eq!(padded[0], None);
    assert_eq!(
        &padded[1..=5],
        &[Some(1), Some(2), Some(4), Some(4), Some(8)]
    );
    assert_eq!(padded[9], Some(16));
    assert_eq!(padded[16], Some(16));
    assert_eq!(padded[17], None);
}

#[test]
fn parameter_set_2_is_a_header_field_and_a_request_prefix() {
    assert_eq!(
        (PARAM_SET_D2048_CELL256, PARAM_SET_D2048_CELL256_P16),
        (1, 2)
    );
    let h = Header {
        param_set: PARAM_SET_D2048_CELL256_P16,
        kind: Kind::Sync,
        leaf_count: LEAF_COUNT,
        block: BLOCK,
        root: ROOT,
    };
    let mut expected = header(5);
    expected[3] = 2;
    assert_eq!(h.encode().to_vec(), expected);
    assert_eq!(Header::decode(&expected).expect("decodes").0, h);
    let prefix = RequestPrefix {
        param_set: PARAM_SET_D2048_CELL256_P16,
    };
    assert_eq!(prefix.encode(), [0, 1, 0, 2]);
}

#[test]
fn parameter_set_2_sizes() {
    assert_eq!(
        (
            P16_KEY_BYTES,
            P16_QUERY_BYTES,
            P16_RESPONSE_BYTES,
            RECORD_BYTES
        ),
        (15_360, 7_456, 9_208, 246)
    );
}

fn filled(len: usize, from: u8) -> Vec<u8> {
    (0..len).map(|i| from.wrapping_add(i as u8)).collect()
}

#[test]
fn set_2_batch_bytes() {
    let q0 = filled(P16_QUERY_BYTES, 0x10);
    let q1 = filled(P16_QUERY_BYTES, 0x80);
    let by_handle = P16Batch {
        key: KeySource::Session(0x0102_0304_0506_0708),
        queries: vec![
            P16Query {
                shard: 0x0a0b_0c0d,
                query: q0.clone(),
            },
            P16Query {
                shard: 3,
                query: q1.clone(),
            },
        ],
    };
    // source 1 | handle | count 2 | (shard | query) x 2
    let mut expected = vec![1, 1, 2, 3, 4, 5, 6, 7, 8, 0, 2, 0x0a, 0x0b, 0x0c, 0x0d];
    expected.extend_from_slice(&q0);
    expected.extend_from_slice(&[0, 0, 0, 3]);
    expected.extend_from_slice(&q1);
    assert_eq!(by_handle.encode(), expected);
    assert_eq!(P16Batch::decode(&expected).expect("decodes"), by_handle);

    let key = filled(P16_KEY_BYTES, 0x33);
    let inline = P16Batch {
        key: KeySource::Inline(key.clone()),
        queries: vec![P16Query {
            shard: 0,
            query: q1.clone(),
        }],
    };
    // source 2 | key | count 1 | shard | query
    let mut expected = vec![2];
    expected.extend_from_slice(&key);
    expected.extend_from_slice(&[0, 1, 0, 0, 0, 0]);
    expected.extend_from_slice(&q1);
    assert_eq!(inline.encode(), expected);
    assert_eq!(expected.len(), 1 + P16_KEY_BYTES + 2 + 4 + P16_QUERY_BYTES);
    assert_eq!(P16Batch::decode(&expected).expect("decodes"), inline);

    // One byte short or long, an unknown source, a count past the queries carried.
    assert!(P16Batch::decode(&expected[..expected.len() - 1]).is_err());
    let mut longer = expected.clone();
    longer.push(0);
    assert!(matches!(
        P16Batch::decode(&longer),
        Err(WireError::Trailing { .. })
    ));
    let mut source = expected.clone();
    source[0] = 3;
    assert_eq!(
        P16Batch::decode(&source),
        Err(WireError::Invalid("unknown key source"))
    );
    let mut count = expected;
    count[1 + P16_KEY_BYTES + 1] = 2;
    assert!(matches!(
        P16Batch::decode(&count),
        Err(WireError::Short { .. })
    ));
}
