//! Fixture-based decoder reconciliation: topic-0 hash locking, real-Sepolia chain-truth
//! triangulation, and synthetic ABI round-trips for all four Railgun event types.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::doc_lazy_continuation,
    clippy::items_after_statements,
    clippy::print_stderr
)]

use alloy::primitives::{Address, B256, U256};
use alloy::sol_types::{SolEvent, SolValue};
use raven_railgun_indexer::abi;

const FIXTURE_PATH: &str = "tests/fixtures/sepolia_events.json";
const REAL_SHIELD_FIXTURE: &str = "tests/fixtures/sepolia_shield_real.json";

/// Locked Shield topic[0] — triangulated via `cast logs` against a real Sepolia log.
const LOCKED_SHIELD_TOPIC0: &str =
    "0x3a5b9dc26075a3801a6ddccf95fec485bb7500a91b44cec1add984c21ee6db3b";

#[test]
fn real_sepolia_shield_log_triangulates_topic0_and_decodes_clean() {
    let raw = std::fs::read_to_string(REAL_SHIELD_FIXTURE).expect("real fixture readable");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("real fixture parse");
    let logs = v["logs"].as_array().expect("logs array");
    assert!(!logs.is_empty(), "at least one Shield log captured");
    let first = &logs[0];

    let literal: B256 = LOCKED_SHIELD_TOPIC0.parse().expect("locked literal parse");
    assert_eq!(
        literal,
        abi::Shield::SIGNATURE_HASH,
        "locked literal must equal alloy SIGNATURE_HASH; struct shape drifted?"
    );

    let chain_topic_hex = first["topics"][0].as_str().expect("topic0 string");
    assert_eq!(
        chain_topic_hex, LOCKED_SHIELD_TOPIC0,
        "chain-captured topic[0] mismatches locked literal; \
         either chain has a different ABI shape OR contract source we read is wrong"
    );
    let chain_topic: B256 = chain_topic_hex.parse().expect("chain topic0 parse");
    assert_eq!(chain_topic, abi::Shield::SIGNATURE_HASH);

    let data_hex = first["data"].as_str().expect("data string");
    let data_bytes = hex_decode(data_hex);
    let log_data = alloy::primitives::LogData::new_unchecked(
        vec![abi::Shield::SIGNATURE_HASH],
        data_bytes.into(),
    );
    let decoded = abi::Shield::decode_log_data(&log_data).expect("Shield decode on real chain log");
    assert!(
        !decoded.commitments.is_empty(),
        "real Shield log must carry ≥1 commitment"
    );

    let preimage = &decoded.commitments[0];
    let weth_sepolia: Address = "0xfff9976782d46cc05630d1f6ebab18b2324d6b14"
        .parse()
        .expect("weth parse");
    assert_eq!(
        preimage.token.tokenAddress, weth_sepolia,
        "first Shield commitment's token must be WETH on Sepolia"
    );
    assert_eq!(preimage.token.tokenType, 0, "WETH is ERC-20 → tokenType 0");

    let npk_bytes: [u8; 32] = preimage.npk.0;
    let addr_bytes: [u8; 20] = preimage.token.tokenAddress.0 .0;
    let token_hash = raven_railgun_poseidon::token_data_hash_erc20(addr_bytes);
    let value_u256 = alloy::primitives::U256::from(preimage.value);
    let value_be = value_u256.to_be_bytes::<32>();
    let commitment_hash =
        raven_railgun_poseidon::shield_commitment_hash(npk_bytes, token_hash, value_be)
            .expect("poseidon shield_commitment_hash on real chain inputs");
    assert!(
        commitment_hash.iter().any(|b| *b != 0),
        "commitment_hash for real Sepolia Shield log must be non-zero"
    );
    eprintln!(
        "real-sepolia chain-truth: Shield commitment_hash = 0x{}",
        hex_encode_lower(&commitment_hash)
    );
}

fn hex_decode(s: &str) -> Vec<u8> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    let mut out = Vec::with_capacity(trimmed.len() / 2);
    let bytes = trimmed.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = hex_nibble(bytes[i]);
        let lo = hex_nibble(bytes[i + 1]);
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

fn hex_encode_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[((b >> 4) & 0x0f) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[test]
fn fixture_topic0_matches_alloy_signature_hash() {
    let raw = std::fs::read_to_string(FIXTURE_PATH).expect("fixture readable");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("fixture parse");
    let logs = v["logs"].as_array().expect("logs array");

    let cases = [
        ("Nullified", abi::Nullified::SIGNATURE_HASH),
        ("Unshield", abi::Unshield::SIGNATURE_HASH),
        ("Shield", abi::Shield::SIGNATURE_HASH),
        ("Transact", abi::Transact::SIGNATURE_HASH),
    ];
    for (label, expected) in cases {
        let log = logs
            .iter()
            .find(|l| l["_label"].as_str().is_some_and(|s| s.starts_with(label)))
            .unwrap_or_else(|| panic!("missing fixture entry for {label}"));
        let topic_hex = log["topics"][0].as_str().expect("topic0 string");
        let actual: B256 = topic_hex.parse().expect("topic0 parse");
        assert_eq!(
            actual, expected,
            "fixture topic0 for {label} disagrees with alloy::abi::{label}::SIGNATURE_HASH; \
             fixture says {topic_hex}, alloy says {expected:?}"
        );
    }
}

#[test]
fn nullified_decodes_round_trip() {
    let tree_number: u16 = 0;
    let nullifiers: Vec<B256> = vec![B256::from([0x11u8; 32]), B256::from([0x22u8; 32])];

    let data = (tree_number, nullifiers.clone()).abi_encode_params();
    let log_data = alloy::primitives::LogData::new_unchecked(
        vec![abi::Nullified::SIGNATURE_HASH],
        data.into(),
    );

    let decoded = abi::Nullified::decode_log_data(&log_data).expect("Nullified decode");
    assert_eq!(decoded.treeNumber, tree_number);
    assert_eq!(decoded.nullifier.len(), nullifiers.len());
    for (got, want) in decoded.nullifier.iter().zip(nullifiers.iter()) {
        assert_eq!(got, want);
    }
}

#[test]
fn unshield_decodes_round_trip() {
    let to: Address = Address::from([0xab; 20]);
    let token_addr: Address = Address::from([0xcd; 20]);
    let token = abi::TokenData {
        tokenType: 1,
        tokenAddress: token_addr,
        tokenSubID: U256::from(0u64),
    };
    let amount = U256::from(1_000_000_000_000_000_000u128);
    let fee = U256::from(25_000_000_000_000_000u128);

    let data = (to, token.clone(), amount, fee).abi_encode_params();
    let log_data =
        alloy::primitives::LogData::new_unchecked(vec![abi::Unshield::SIGNATURE_HASH], data.into());

    let decoded = abi::Unshield::decode_log_data(&log_data).expect("Unshield decode");
    assert_eq!(decoded.to, to);
    assert_eq!(decoded.token.tokenType, token.tokenType);
    assert_eq!(decoded.token.tokenAddress, token.tokenAddress);
    assert_eq!(decoded.token.tokenSubID, token.tokenSubID);
    assert_eq!(decoded.amount, amount);
    assert_eq!(decoded.fee, fee);
}

#[test]
fn transact_decodes_round_trip() {
    let tree = U256::from(0u64);
    let start = U256::from(42u64);
    let hashes: Vec<B256> = vec![B256::from([0xaau8; 32])];
    let ct = abi::CommitmentCiphertext {
        ciphertext: [
            B256::from([0x01u8; 32]),
            B256::from([0x02u8; 32]),
            B256::from([0x03u8; 32]),
            B256::from([0x04u8; 32]),
        ],
        blindedSenderViewingKey: B256::from([0x05u8; 32]),
        blindedReceiverViewingKey: B256::from([0x06u8; 32]),
        annotationData: vec![0xde, 0xad].into(),
        memo: vec![0xbe, 0xef].into(),
    };

    let data = (tree, start, hashes.clone(), vec![ct.clone()]).abi_encode_params();
    let log_data =
        alloy::primitives::LogData::new_unchecked(vec![abi::Transact::SIGNATURE_HASH], data.into());

    let decoded = abi::Transact::decode_log_data(&log_data).expect("Transact decode");
    assert_eq!(decoded.treeNumber, tree);
    assert_eq!(decoded.startPosition, start);
    assert_eq!(decoded.hash.len(), 1);
    assert_eq!(decoded.hash[0], hashes[0]);
    assert_eq!(decoded.ciphertext.len(), 1);
    let got_ct = &decoded.ciphertext[0];
    assert_eq!(got_ct.ciphertext, ct.ciphertext);
    assert_eq!(got_ct.blindedSenderViewingKey, ct.blindedSenderViewingKey);
    assert_eq!(got_ct.annotationData.as_ref(), ct.annotationData.as_ref());
    assert_eq!(got_ct.memo.as_ref(), ct.memo.as_ref());
}

#[test]
fn shield_decoder_commitment_hash_matches_poseidon_helper() {
    use alloy::primitives::Address as AlloyAddress;
    let tree = U256::from(0u64);
    let start = U256::from(7u64);
    let token_address: [u8; 20] = [0x42; 20];
    let token = abi::TokenData {
        tokenType: 0, // ERC-20
        tokenAddress: AlloyAddress::from(token_address),
        tokenSubID: U256::from(0u64),
    };
    let mut npk_be = [0u8; 32];
    npk_be[24..].copy_from_slice(&0x1234_5678_u64.to_be_bytes());
    let npk_b256 = B256::from(npk_be);
    let value_u120 = 1_000_000u64;
    let commitments = vec![abi::CommitmentPreimage {
        npk: npk_b256,
        token: token.clone(),
        value: alloy::primitives::Uint::<120, 2>::from(value_u120),
    }];
    let shield_ct = vec![abi::ShieldCiphertext {
        encryptedBundle: [B256::ZERO, B256::ZERO, B256::ZERO],
        shieldKey: B256::ZERO,
    }];
    let fees: Vec<U256> = vec![U256::from(0u64)];

    let data = (tree, start, commitments, shield_ct, fees).abi_encode_params();
    let log_data =
        alloy::primitives::LogData::new_unchecked(vec![abi::Shield::SIGNATURE_HASH], data.into());

    use alloy::sol_types::SolEvent;
    let decoded = abi::Shield::decode_log_data(&log_data).expect("decode");
    let preimage = decoded.commitments.first().expect("commitment present");

    let npk_bytes = preimage.npk.0;
    let token_hash = raven_railgun_poseidon::token_data_hash_erc20(token_address);
    let value_u256 = alloy::primitives::U256::from(preimage.value);
    let value_be = value_u256.to_be_bytes::<32>();
    let expected_hash =
        raven_railgun_poseidon::shield_commitment_hash(npk_bytes, token_hash, value_be)
            .expect("poseidon");

    assert!(
        expected_hash.iter().any(|&b| b != 0),
        "commitment_hash should be non-zero"
    );

    let recompute = raven_railgun_poseidon::shield_commitment_hash(npk_bytes, token_hash, value_be)
        .expect("recompute");
    assert_eq!(
        expected_hash, recompute,
        "Poseidon must be deterministic on identical inputs"
    );
}

#[test]
fn shield_decodes_round_trip() {
    let tree = U256::from(0u64);
    let start = U256::from(7u64);
    let token = abi::TokenData {
        tokenType: 0,
        tokenAddress: Address::from([0x10u8; 20]),
        tokenSubID: U256::from(0u64),
    };
    let mut npk_be = [0u8; 32];
    npk_be[24..].copy_from_slice(&0xfeed_face_u64.to_be_bytes());
    let commitments = vec![abi::CommitmentPreimage {
        npk: B256::from(npk_be),
        token: token.clone(),
        value: alloy::primitives::Uint::<120, 2>::from(1_000_000u64),
    }];
    let shield_ct = vec![abi::ShieldCiphertext {
        encryptedBundle: [
            B256::from([0x11u8; 32]),
            B256::from([0x22u8; 32]),
            B256::from([0x33u8; 32]),
        ],
        shieldKey: B256::from([0x44u8; 32]),
    }];
    let fees: Vec<U256> = vec![U256::from(2500u64)];

    let data = (
        tree,
        start,
        commitments.clone(),
        shield_ct.clone(),
        fees.clone(),
    )
        .abi_encode_params();
    let log_data =
        alloy::primitives::LogData::new_unchecked(vec![abi::Shield::SIGNATURE_HASH], data.into());

    let decoded = abi::Shield::decode_log_data(&log_data).expect("Shield decode");
    assert_eq!(decoded.treeNumber, tree);
    assert_eq!(decoded.startPosition, start);
    assert_eq!(decoded.commitments.len(), 1);
    assert_eq!(decoded.commitments[0].npk, commitments[0].npk);
    assert_eq!(
        decoded.commitments[0].token.tokenAddress,
        token.tokenAddress
    );
    assert_eq!(decoded.shieldCiphertext.len(), 1);
    assert_eq!(
        decoded.shieldCiphertext[0].shieldKey,
        shield_ct[0].shieldKey
    );
    assert_eq!(decoded.fees, fees);
}
