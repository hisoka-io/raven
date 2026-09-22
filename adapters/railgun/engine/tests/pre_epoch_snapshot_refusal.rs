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
//! on. WHAT IT DOES NOT PROVE: that any legacy arm still decodes legacy bytes to the values they
//! decoded to before. No bytes this build can decode past `InspireParams` survive anywhere, so
//! that property has no corpus and is not asserted here. A same-length reinterpretation inside
//! `InspireParams` would leave every assertion below green.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;

use raven_railgun_core::{AdapterError, InstanceId};
use raven_railgun_engine::inspire::{
    restore_inspire_state_v6, SNAPSHOT_V6_MAGIC, SNAPSHOT_V7_MAGIC,
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

/// The restored instance's own manifest fields, so the boot path validates the identity it
/// actually shipped with rather than one invented here.
const RECOVERED_SCHEME_TAG: &str = "raven-inspire-twopacking-inspiring-wp3-cache-session";
const RECOVERED_INSTANCE_ID: &str = "ppoi-paths-ofac";
const RECOVERED_MANIFEST_SCHEMA_VERSION: u32 = 5;
const _: () = assert!(RECOVERED_MANIFEST_SCHEMA_VERSION < MANIFEST_SCHEMA_VERSION);
const TOY_ENTRY_SIZE: usize = 32;
const ENTRIES_PER_SHARD: u32 = 2048;

fn recovered_encoder() -> Arc<dyn PirTableEncoder> {
    EncoderKind::PerListNode { list_key: [0; 32] }
        .build(TOY_ENTRY_SIZE, ENTRIES_PER_SHARD)
        .expect("build per-list-node encoder")
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

/// The V6 and V7 arms are the reference decoders and stay; behind their own magic the same
/// recovered bytes must refuse the same way, naming the arm that read them.
#[test]
fn the_recovered_bytes_behind_each_version_magic_are_refused_naming_that_arm() {
    for (magic, arm) in [(SNAPSHOT_V6_MAGIC, "v6"), (SNAPSHOT_V7_MAGIC, "v7")] {
        let mut bytes = magic.to_vec();
        bytes.extend_from_slice(&RECOVERED_V5_SNAPSHOT_HEAD);
        let error = restore_inspire_state_v6(&bytes)
            .err()
            .unwrap_or_else(|| panic!("{arm} arm must not decode pre-epoch bytes"));
        assert_names_arm_and_helps_the_operator(&refusal_text(error, arm), arm);
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

/// The arm production boots through is the cached twin, reached only from `open`. Same bytes,
/// same refusal, on the path a deploy actually meets.
#[test]
fn the_boot_path_refuses_a_data_dir_holding_recovered_pre_epoch_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = StoreLayout::open(dir.path()).expect("layout");

    let snapshot_id = SnapshotId(1);
    Snapshot::build(RECOVERED_V5_SNAPSHOT_HEAD.to_vec(), SNAPSHOT_MAGIC)
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

    let error = InspirePersistence::open(
        StoreLayout::open(dir.path()).expect("layout reopen"),
        RECOVERED_SCHEME_TAG,
        InstanceId::new(RECOVERED_INSTANCE_ID),
        SnapshotPolicy::default(),
        recovered_encoder(),
    )
    .expect_err("opening a data_dir of pre-epoch bytes must fail closed");
    let detail = refusal_text(error, "the boot path");
    assert_names_arm_and_helps_the_operator(&detail, "v5");
    assert!(
        detail.contains(SHIFTED_LENGTH_FINGERPRINT),
        "the boot path must reach the snapshot decode, not stop at manifest identity: {detail}"
    );
}
