//! A list generated the way a list provider builds one: each leaf appended to Raven's depth-16
//! tree with the root read after it, each event signed over upstream's signed message.

#![allow(dead_code, unreachable_pub)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use raven_railgun_engine::imt::Imt;
use raven_railgun_ppoi_replay::{
    bind, serve, Capture, ChainScope, EventRow, EventType, Replay, WireOverride,
};

pub const TXID_VERSION: &str = "V2_PoseidonMerkle";

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

pub fn scope() -> ChainScope {
    ChainScope {
        chain_type: 0,
        chain_id: 1,
        network: "Ethereum".to_owned(),
        txid_version: TXID_VERSION.to_owned(),
    }
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x5a; 32])
}

pub fn list_key() -> [u8; 32] {
    signing_key().verifying_key().to_bytes()
}

/// Upstream signs the UTF-8 of `JSON.stringify({index, blindedCommitment, type})`.
fn sign(index: u32, blinded_commitment: &str, event_type: EventType) -> [u8; 64] {
    let message = format!(
        "{{\"index\":{index},\"blindedCommitment\":\"{blinded_commitment}\",\"type\":\"{}\"}}",
        event_type.wire_name()
    );
    signing_key().sign(message.as_bytes()).to_bytes()
}

/// `rows` events of every type; row 7 repeats row 3's commitment, as the real list repeats one.
pub fn generate_rows(rows: u32) -> Vec<EventRow> {
    let mut tree = Imt::new().expect("empty tree");
    (0..rows)
        .map(|index| {
            let source = if index == 7 { 3 } else { index };
            let mut commitment = [0u8; 32];
            commitment[0] = 0x1c;
            commitment[27..31].copy_from_slice(&source.to_be_bytes());
            commitment[31] = 0x5d;
            tree.insert_leaves(index as usize, &[commitment])
                .expect("leaf fits the tree");
            let event_type = EventType::ALL[(index as usize * 7 + 1) % 4];
            EventRow {
                index,
                event_type,
                blinded_commitment: commitment,
                validated_merkleroot: tree.root(),
                signature: sign(index, &format!("0x{}", hex(&commitment)), event_type),
            }
        })
        .collect()
}

/// The upstream quirk: a commitment served without `0x`, its signature over that string.
pub fn unprefixed_override(rows: &mut [EventRow], index: u32) -> BTreeMap<u32, WireOverride> {
    let row = &mut rows[index as usize];
    row.signature = sign(index, &hex(&row.blinded_commitment), row.event_type);
    BTreeMap::from([(
        index,
        WireOverride {
            blinded_commitment: hex(&row.blinded_commitment),
            signature: hex(&row.signature),
            event_type: row.event_type.wire_name().to_owned(),
            validated_merkleroot: hex(&row.validated_merkleroot),
        },
    )])
}

/// A recorded-shape status body: this list beside another list and another network, whose
/// fields the replay must pass through untouched.
pub fn node_status_response(
    list_key: &[u8; 32],
    recorded_rows: u32,
    recorded_root: &str,
) -> String {
    let status = |rows: u32, root: &str| {
        format!(
            "{{\"poiEventLengths\":{{\"Shield\":{rows},\"Transact\":0,\"Unshield\":0,\"LegacyTransact\":0}},\
             \"pendingTransactProofs\":0,\"blockedShields\":12,\"historicalMerklerootsLength\":{rows},\
             \"latestHistoricalMerkleroot\":\"{root}\"}}"
        )
    };
    let other = "55".repeat(32);
    let key = hex(list_key);
    format!(
        "{{\"jsonrpc\":\"2.0\",\"result\":{{\"forNetwork\":{{\
         \"Ethereum\":{{\"txidStatus\":{{\"currentTxidIndex\":9}},\"listStatuses\":{{\"{key}\":{},\"{other}\":{}}},\
         \"shieldQueueStatus\":{{\"latestShield\":null}},\"legacyTransactProofs\":3}},\
         \"Polygon\":{{\"txidStatus\":{{\"currentTxidIndex\":4}},\"listStatuses\":{{\"{key}\":{}}},\"legacyTransactProofs\":1}}\
         }},\"listKeys\":[\"{key}\",\"{other}\"]}},\"id\":1}}",
        status(recorded_rows, recorded_root),
        status(5, &"ab".repeat(32)),
        status(8, &"cd".repeat(32)),
    )
}

pub fn replay(
    rows: Vec<EventRow>,
    overrides: BTreeMap<u32, WireOverride>,
    served: usize,
) -> Replay {
    let capture = Capture::new(list_key(), rows, overrides).expect("generated list is contiguous");
    let status = node_status_response(&list_key(), 0, "No merkleroot found");
    Replay::new(capture, scope(), status.as_bytes(), served).expect("replay")
}

pub async fn spawn(replay: Arc<Replay>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let (listener, local) = bind("127.0.0.1:0".parse().expect("loopback"))
        .await
        .expect("bind");
    let handle = tokio::spawn(async move {
        let _ = serve(listener, replay).await;
    });
    (local, handle)
}
