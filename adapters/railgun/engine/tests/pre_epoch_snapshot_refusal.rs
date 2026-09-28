//! Bytes an older build wrote are REFUSED, by a typed error that names the arm that read them.
//!
//! The corpus below is RECOVERED, not minted: [`RECOVERED_V5_SNAPSHOT_HEAD`] is the first 100
//! bytes of the decompressed snapshot payload of a restored production instance
//! (`ppoi-paths-ofac`, manifest `schema_version: 5`, written 2026-05). The full artifact is
//! 35,205,991 bytes compressed and lives outside the repository; 100 bytes is where this build
//! stops reading it, so committing more would pin nothing extra.
//!
//! Why it stops at 100: the payload opens with `InspireParams`, whose serialized field list
//! gained one `usize` mid-struct. Bincode is positional, so every field after `gadget_base`
//! shifts eight bytes, and the first length prefix read at the wrong offset declares
//! 958,663,751,023,254,534 bytes against a 16 MiB cap. That length field sits at offset 92.
//!
//! WHAT THIS PROVES: pre-epoch bytes are refused, cleanly, by a typed error an operator can act
//! on, and a V6 or V7 body is refused unread: every body behind either magic, well-formed or with
//! two same-width fields swapped or retyped, gets the byte-identical refusal, so no
//! reinterpretation under that magic can decode to a value. A data_dir the V7 build wrote is
//! refused by name at open. A snapshot carrying bytes past its envelope is refused on both live
//! arms rather than decoded with the tail discarded.
//!
//! WHAT IT DOES NOT PROVE: the same for the no-magic V5 arm. That arm still decodes, because
//! `InspirePersistence::commit` still writes V5, so a same-length reinterpretation inside
//! `InspireParams` behind no magic would leave the V5 assertions below green.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;

use raven_railgun_core::{AdapterError, InstanceId};
use raven_railgun_engine::inspire::{
    restore_inspire_state_v6, snapshot_inspire_state, snapshot_inspire_state_v8, LogicalLeafStore,
    SNAPSHOT_V6_MAGIC, SNAPSHOT_V7_MAGIC, SNAPSHOT_V8_MAGIC,
};
use raven_railgun_engine::persistence::{InspirePersistence, SnapshotPolicy};
use raven_railgun_engine::pir_table::{EncoderKind, PirTableEncoder};
use raven_railgun_persistence::{
    Manifest, Snapshot, SnapshotId, StoreLayout, MANIFEST_SCHEMA_VERSION, SNAPSHOT_MAGIC,
};

/// Verbatim head of `ppoi-paths-ofac/snapshots/snap-000001/data.bincode`, zstd-decompressed.
/// Decoded against the layout that wrote it: `ring_dim 2048`, `q 1152921504606830593`,
/// `crt_moduli [q]`, `p 65537`, `sigma 6.4`, `gadget_base 1048576`, `gadget_len 3`,
/// `security_level 0` -- every value self-consistent, which is how a shift is told from damage.
const RECOVERED_V5_SNAPSHOT_HEAD: [u8; 100] = [
    0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc0, //
    0xff, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x01, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x01, 0xc0, 0xff, 0xff, 0xff, 0xff, //
    0xff, 0x0f, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x9a, 0x99, 0x99, 0x99, 0x99, 0x99, 0x19, 0x40, 0x00, 0x00, //
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x07, 0x1f, 0x6e, 0x47, 0x94, 0xb1, //
    0x3b, 0x08, 0x06, 0xdc, 0xc8, 0x32, 0x9a, 0xdb, 0x4d, 0x0d, //
];

/// The whole 35 MB artifact refuses with this exact clause, so the 100 bytes above stand in for
/// it faithfully. Drop this and the head is indistinguishable from any truncated buffer.
const SHIFTED_LENGTH_FINGERPRINT: &str =
    "tight coefficient payload declares 958663751023254534 bytes, cap is 16777216";

/// bincode's own wording when a decode ends before the buffer does.
const SURPLUS_FINGERPRINT: &str = "bytes remaining after deserialization";

/// The restored instance's own manifest fields, so the boot path validates the identity it
/// actually shipped with rather than one invented here.
const RECOVERED_SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-cache-session";
const RECOVERED_INSTANCE_ID: &str = "ppoi-paths-ofac";
const RECOVERED_MANIFEST_SCHEMA_VERSION: u32 = 5;
const _: () = assert!(RECOVERED_MANIFEST_SCHEMA_VERSION < MANIFEST_SCHEMA_VERSION);
const TOY_ENTRY_SIZE: usize = 32;
const ENTRIES_PER_SHARD: u32 = 2048;

/// The store half of a V7 snapshot, minted by the last build that wrote V7: one commitment leaf
/// and two PPOI list leaves, each with its status byte and signature.
const FROZEN_V7_STORE: &[u8] = include_bytes!("fixtures/logical_store_v7.bin");

fn recovered_encoder() -> Arc<dyn PirTableEncoder> {
    EncoderKind::PerNode { tree_number: 0 }
        .build(TOY_ENTRY_SIZE, ENTRIES_PER_SHARD)
        .expect("build per-node encoder")
}

/// Refusal is a claim about the error's TYPE as much as its text: `Serialization` is what the
/// decode path owes, and `Internal` is what a lazily-wrapped one produces.
fn refusal_text(error: AdapterError, whose: &str) -> String {
    match error {
        AdapterError::Serialization(detail) => detail,
        other => panic!("{whose} must refuse with a typed Serialization error, got: {other:?}"),
    }
}

fn assert_names_arm_and_helps_the_operator(detail: &str, arm: &str) {
    assert!(
        detail.contains(&format!("{arm} snapshot deserialize")),
        "refusal must name the {arm} arm: {detail}"
    );
    assert!(
        detail.contains("no in-place migration exists"),
        "refusal must say these bytes cannot be migrated in place: {detail}"
    );
    assert!(
        detail.contains("RAVEN_PROBE_DATA_DIR"),
        "refusal must hand the operator the probe command: {detail}"
    );
}

/// Guards the corpus itself. If these bytes ever stopped falling through to the V5 arm, every
/// other assertion here would be about a different decoder.
#[test]
fn the_recovered_head_carries_neither_version_magic() {
    let head = &RECOVERED_V5_SNAPSHOT_HEAD[..4];
    assert_ne!(head, SNAPSHOT_V6_MAGIC.as_slice());
    assert_ne!(head, SNAPSHOT_V7_MAGIC.as_slice());
    assert_ne!(head, SNAPSHOT_V8_MAGIC.as_slice());
    assert_eq!(
        u64::from_le_bytes(
            RECOVERED_V5_SNAPSHOT_HEAD[..8]
                .try_into()
                .expect("eight bytes")
        ),
        2048,
        "offset 0 is InspireParams::ring_dim, which is what makes this the V5 arm"
    );
}

#[test]
fn recovered_pre_epoch_bytes_are_refused_by_a_typed_error_naming_the_v5_arm() {
    let error = restore_inspire_state_v6(&RECOVERED_V5_SNAPSHOT_HEAD)
        .expect_err("recovered pre-epoch bytes must not decode under this build");
    let detail = refusal_text(error, "the V5 arm");
    assert_names_arm_and_helps_the_operator(&detail, "v5");
    assert!(
        detail.contains(SHIFTED_LENGTH_FINGERPRINT),
        "the head must refuse for the SHIFT, not for running out of bytes: {detail}"
    );
}

/// Behind the V8 magic the same recovered bytes refuse the same way, naming the arm that read
/// them.
#[test]
fn the_recovered_bytes_behind_the_v8_magic_are_refused_naming_that_arm() {
    let mut bytes = SNAPSHOT_V8_MAGIC.to_vec();
    bytes.extend_from_slice(&RECOVERED_V5_SNAPSHOT_HEAD);
    let error =
        restore_inspire_state_v6(&bytes).expect_err("v8 arm must not decode pre-epoch bytes");
    assert_names_arm_and_helps_the_operator(&refusal_text(error, "v8"), "v8");
}

/// Nine empty collections and a zero height: the store half of a V8 snapshot of an empty store,
/// each field one `u64`.
const EMPTY_V8_STORE_BYTES: usize = 10 * 8;
/// The V7 store had two more collections, the per-commitment statuses and their heights.
const EMPTY_V7_STORE_BYTES: usize = 12 * 8;

/// The state half this build writes, which every epoch shares.
fn state_half() -> Vec<u8> {
    let state = raven_railgun_testkit::toy_state(TOY_ENTRY_SIZE);
    let v8 = snapshot_inspire_state_v8(&state, &LogicalLeafStore::new()).expect("v8 serialize");
    restore_inspire_state_v6(&v8).expect("control: the same state half decodes under V8");
    let body = v8
        .strip_prefix(SNAPSHOT_V8_MAGIC.as_slice())
        .expect("v8 magic");
    let (state_half, store_half) = body.split_at(body.len() - EMPTY_V8_STORE_BYTES);
    assert!(
        store_half.iter().all(|b| *b == 0),
        "the empty store half must be all zero, or the layouts below are not what they claim"
    );
    state_half.to_vec()
}

/// A V6 envelope a V6 reader would have accepted: the state half, then the eleven V6 store
/// fields empty. V6 lacked only `ppoi_event_metadata` of the V7 store.
fn well_formed_v6_body() -> Vec<u8> {
    let mut v6 = state_half();
    v6.extend_from_slice(&[0; EMPTY_V7_STORE_BYTES - 8]);
    v6
}

/// A V7 envelope the V7 reader accepted: the state half, then its twelve store fields empty.
fn well_formed_v7_body() -> Vec<u8> {
    let mut v7 = state_half();
    v7.extend_from_slice(&[0; EMPTY_V7_STORE_BYTES]);
    v7
}

fn retired_refusal(magic: [u8; 4], body: &[u8]) -> String {
    let mut bytes = magic.to_vec();
    bytes.extend_from_slice(body);
    let error = restore_inspire_state_v6(&bytes)
        .err()
        .unwrap_or_else(|| panic!("a {}-byte retired body decoded to a state", body.len()));
    refusal_text(error, "a retired arm")
}

fn v6_refusal(body: &[u8]) -> String {
    retired_refusal(SNAPSHOT_V6_MAGIC, body)
}

fn assert_names_the_retired_epoch_and_helps_the_operator(detail: &str, epoch: &str) {
    for needle in [
        &format!("{epoch} snapshot refused"),
        "V8 snapshot epoch",
        "no in-place migration exists",
        "re-bootstrap",
    ] {
        assert!(
            detail.contains(needle),
            "{needle:?} missing from {detail:?}"
        );
    }
    // A V6 body can never reopen under this build, so the probe cannot go green and no
    // matching build exists to ship.
    for futile in ["RAVEN_PROBE_DATA_DIR", "ship a build"] {
        assert!(
            !detail.contains(futile),
            "{futile:?} sends the operator nowhere: {detail:?}"
        );
    }
}

/// The reinterpretation half, closed by refusal: a decoder cannot tell a swapped or retyped
/// same-width field from a value, so the V6 arm runs none, and a body read under any retyped
/// reader is the well-formed body itself. Every body gets one byte-identical answer.
#[test]
fn a_v6_body_is_refused_unread_whatever_it_contains() {
    let well_formed = well_formed_v6_body();

    let mut swapped = well_formed.clone();
    let (ring_dim, rest) = swapped.split_at_mut(8);
    let (q, _) = rest.split_at_mut(8);
    ring_dim.swap_with_slice(q);

    let mut rewritten = well_formed.clone();
    *rewritten.get_mut(7).expect("ring_dim's top byte") ^= 0x80;

    let v7_shaped = well_formed_v7_body();

    let expected = v6_refusal(&well_formed);
    assert_names_the_retired_epoch_and_helps_the_operator(&expected, "v6");
    for (label, body) in [
        ("empty", Vec::new()),
        (
            "recovered pre-epoch head",
            RECOVERED_V5_SNAPSHOT_HEAD.to_vec(),
        ),
        ("ring_dim and q swapped", swapped),
        ("ring_dim rewritten at the same width", rewritten),
        ("a V7-shaped store", v7_shaped),
    ] {
        assert_eq!(
            v6_refusal(&body),
            expected,
            "{label}: the body must not reach a decoder"
        );
    }
}

/// A decoder that accepts a truncation reports success over bytes it never read. No prefix of a
/// recorded pre-epoch snapshot is a valid one.
#[test]
fn no_prefix_of_the_recovered_bytes_is_ever_accepted() {
    for len in 0..=RECOVERED_V5_SNAPSHOT_HEAD.len() {
        let prefix = RECOVERED_V5_SNAPSHOT_HEAD
            .get(..len)
            .unwrap_or_else(|| panic!("{len} is within the head"));
        let error = restore_inspire_state_v6(prefix)
            .err()
            .unwrap_or_else(|| panic!("a {len}-byte prefix decoded to a state"));
        let detail = refusal_text(error, &format!("a {len}-byte prefix"));
        assert!(
            detail.contains("v5 snapshot deserialize"),
            "{len}-byte prefix: {detail}"
        );
    }
}

fn data_dir_holding(snapshot: Vec<u8>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");

    let snapshot_id = SnapshotId(1);
    Snapshot::build(snapshot, SNAPSHOT_MAGIC)
        .save(&layout, snapshot_id)
        .expect("save recovered snapshot");
    Manifest {
        schema_version: RECOVERED_MANIFEST_SCHEMA_VERSION,
        scheme_tag: RECOVERED_SCHEME_TAG.to_owned(),
        instance_id: RECOVERED_INSTANCE_ID.to_owned(),
        current_snapshot_id: snapshot_id,
        current_snapshot_seq: 0,
        current_marker: 0,
        encoder_label: recovered_encoder().label().to_owned(),
        prev_encoder_label: None,
        entry_size_bytes: None,
        rows_per_shard: None,
    }
    .save(&layout)
    .expect("save recovered manifest");
    dir
}

fn boot_refusal(dir: &tempfile::TempDir) -> String {
    let error = InspirePersistence::open(
        StoreLayout::open(dir.path()).expect("layout reopen"),
        RECOVERED_SCHEME_TAG,
        InstanceId::new(RECOVERED_INSTANCE_ID),
        SnapshotPolicy::default(),
        recovered_encoder(),
    )
    .expect_err("opening a data_dir of pre-epoch bytes must fail closed");
    refusal_text(error, "the boot path")
}

/// The arm production boots through is the cached twin, reached only from `open`. Same bytes,
/// same refusal, on the path a deploy actually meets.
#[test]
fn the_boot_path_refuses_a_data_dir_holding_recovered_pre_epoch_bytes() {
    let dir = data_dir_holding(RECOVERED_V5_SNAPSHOT_HEAD.to_vec());
    let detail = boot_refusal(&dir);
    assert_names_arm_and_helps_the_operator(&detail, "v5");
    assert!(
        detail.contains(SHIFTED_LENGTH_FINGERPRINT),
        "the boot path must reach the snapshot decode, not stop at manifest identity: {detail}"
    );
}

/// A data_dir the V7 build wrote: its manifest, and a snapshot whose store half that build
/// minted, with a status byte per commitment and each row's signature.
fn v7_data_dir() -> (tempfile::TempDir, Vec<u8>) {
    let state = raven_railgun_testkit::toy_state(TOY_ENTRY_SIZE);
    let mut body = snapshot_inspire_state(&state).expect("state half");
    body.extend_from_slice(FROZEN_V7_STORE);
    let mut snapshot = SNAPSHOT_V7_MAGIC.to_vec();
    snapshot.extend_from_slice(&body);

    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");
    Snapshot::build(snapshot, SNAPSHOT_MAGIC)
        .save(&layout, SnapshotId(1))
        .expect("save v7 snapshot");
    Manifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        scheme_tag: RECOVERED_SCHEME_TAG.to_owned(),
        instance_id: RECOVERED_INSTANCE_ID.to_owned(),
        current_snapshot_id: SnapshotId(1),
        current_snapshot_seq: 0,
        current_marker: 0,
        encoder_label: recovered_encoder().label().to_owned(),
        prev_encoder_label: None,
        entry_size_bytes: Some(TOY_ENTRY_SIZE),
        rows_per_shard: Some(u64::from(ENTRIES_PER_SHARD)),
    }
    .save(&layout)
    .expect("save v7 manifest");
    (dir, body)
}

/// The previous on-disk format is refused by name at open, never read: the V8 store dropped the
/// per-commitment statuses and the stored signatures, so the V7 bytes are not a V8 layout.
#[test]
fn the_boot_path_refuses_a_data_dir_the_v7_build_wrote_by_name() {
    let (dir, body) = v7_data_dir();
    let detail = boot_refusal(&dir);
    assert_names_the_retired_epoch_and_helps_the_operator(&detail, "v7");
    assert_eq!(detail, retired_refusal(SNAPSHOT_V7_MAGIC, &body));
    let mut as_v8 = SNAPSHOT_V8_MAGIC.to_vec();
    as_v8.extend_from_slice(&body);
    assert!(
        restore_inspire_state_v6(&as_v8).is_err(),
        "control: the V7 body does not read as V8, so the refusal is not the only barrier"
    );
}

/// Every body behind the V7 magic gets one byte-identical answer, as the V6 magic does.
#[test]
fn a_v7_body_is_refused_unread_whatever_it_contains() {
    let expected = retired_refusal(SNAPSHOT_V7_MAGIC, &well_formed_v7_body());
    assert_names_the_retired_epoch_and_helps_the_operator(&expected, "v7");
    for body in [
        Vec::new(),
        RECOVERED_V5_SNAPSHOT_HEAD.to_vec(),
        v7_data_dir().1,
    ] {
        assert_eq!(retired_refusal(SNAPSHOT_V7_MAGIC, &body), expected);
    }
}

#[test]
fn the_boot_path_refuses_a_well_formed_v6_snapshot_unread() {
    let body = well_formed_v6_body();
    let mut snapshot = SNAPSHOT_V6_MAGIC.to_vec();
    snapshot.extend_from_slice(&body);
    let dir = data_dir_holding(snapshot);
    assert_eq!(boot_refusal(&dir), v6_refusal(&body));
}

/// Surplus past the envelope means the writer and the reader disagree about the shape. Decoding
/// the prefix and discarding the rest is how a longer layout once read as a shorter one returned
/// `Ok`, so both live arms refuse it, on the uncached path and on the one a boot takes.
#[test]
fn a_snapshot_carrying_surplus_bytes_is_refused_on_both_paths_naming_its_arm() {
    let state = raven_railgun_testkit::toy_state(TOY_ENTRY_SIZE);
    let v8 = snapshot_inspire_state_v8(&state, &LogicalLeafStore::new()).expect("v8 serialize");
    let v5 = snapshot_inspire_state(&state).expect("v5 serialize");
    for (arm, exact) in [("v8", v8), ("v5", v5)] {
        restore_inspire_state_v6(&exact)
            .unwrap_or_else(|e| panic!("control: the exact {arm} bytes must decode: {e}"));
        let mut surplus = exact;
        surplus.push(0);
        let uncached = restore_inspire_state_v6(&surplus)
            .err()
            .unwrap_or_else(|| panic!("{arm}: a trailing byte was decoded and discarded"));
        let boot = boot_refusal(&data_dir_holding(surplus));
        for (path, detail) in [("uncached", refusal_text(uncached, arm)), ("boot", boot)] {
            assert!(
                detail.contains(&format!("{arm} snapshot deserialize"))
                    && detail.contains(SURPLUS_FINGERPRINT),
                "{arm} on the {path} path must refuse for the surplus, naming the arm: {detail}"
            );
        }
    }
}
