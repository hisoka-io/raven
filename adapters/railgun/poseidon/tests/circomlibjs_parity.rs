//! Byte-equality checks between `light-poseidon` and known circomlibjs reference vectors.
//! If these tests fail, light-poseidon's parameters have drifted from circomlibjs.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::items_after_statements
)]

use raven_railgun_poseidon::hash_n;

fn fr_be_from_decimal(s: &str) -> [u8; 32] {
    use ark_ff::{BigInteger, PrimeField};
    let fr: ark_bn254::Fr = s.parse().expect("decimal parses to BN254 Fr");
    let bytes = fr.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let copy_len = bytes.len().min(32);
    if let Some(dst) = out.get_mut(32 - copy_len..) {
        if let Some(src) = bytes.get(..copy_len) {
            dst.copy_from_slice(src);
        }
    }
    out
}

fn fr_from_u64(n: u64) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[24..].copy_from_slice(&n.to_be_bytes());
    buf
}

#[test]
fn poseidon_arity_2_matches_circomlibjs_known_vector() {
    // Source: circomlibjs/test/poseidon.js (iden3 canonical vector).
    let inputs = [fr_from_u64(1), fr_from_u64(2)];
    let got = hash_n(&inputs).expect("hash");
    let expected = fr_be_from_decimal(
        "7853200120776062878684798364095072458815029376092732009249414926327459813530",
    );
    assert_eq!(
        got, expected,
        "poseidon([1,2]) circomlibjs parity FAILED. \
         If this fires, light-poseidon's circomlibjs compatibility \
         has drifted; pin a working version or switch deps."
    );
}

#[test]
fn poseidon_arity_4_matches_circomlibjs_known_vector() {
    let inputs = [
        fr_from_u64(1),
        fr_from_u64(2),
        fr_from_u64(3),
        fr_from_u64(4),
    ];
    let got = hash_n(&inputs).expect("hash");
    let expected = fr_be_from_decimal(
        "18821383157269793795438455681495246036402687001665670618754263018637548127333",
    );
    assert_eq!(got, expected, "poseidon([1,2,3,4]) circomlibjs parity");
}

#[test]
fn poseidon_arity_6_matches_circomlibjs_known_vector() {
    let inputs: [[u8; 32]; 6] = core::array::from_fn(|i| fr_from_u64(i as u64 + 1));
    let got = hash_n(&inputs).expect("hash");
    let expected = fr_be_from_decimal(
        "20400040500897583745843009878988256314335038853985262692600694741116813247201",
    );
    assert_eq!(got, expected, "poseidon([1..=6]) circomlibjs parity");
}

#[test]
fn token_data_hash_erc20_pads_address_left() {
    let dai_address: [u8; 20] = [
        0x6b, 0x17, 0x54, 0x74, 0xe8, 0x90, 0x94, 0xc4, 0x4d, 0xa9, 0x8b, 0x95, 0x4e, 0xed, 0xea,
        0xc4, 0x95, 0x27, 0x1d, 0x0f,
    ];
    let h = raven_railgun_poseidon::token_data_hash_erc20(dai_address);
    let expected: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x6b, 0x17, 0x54, 0x74, 0xe8, 0x90, 0x94, 0xc4, 0x4d,
        0xa9, 0x8b, 0x95, 0x4e, 0xed, 0xea, 0xc4, 0x95, 0x27, 0x1d, 0x0f,
    ];
    assert_eq!(
        h, expected,
        "ERC20 tokenHash must be the address left-padded to 32 bytes"
    );
}

#[test]
fn token_data_hash_nft_keccak_then_mod_snark_prime() {
    use tiny_keccak::{Hasher, Keccak};
    let token_address: [u8; 20] = [0x42; 20];
    let token_sub_id: [u8; 32] = [0x07; 32];

    let mut buf = [0u8; 96];
    buf[31] = 1; // tokenType = 1 (ERC721)
    buf[44..64].copy_from_slice(&token_address);
    buf[64..96].copy_from_slice(&token_sub_id);

    let mut hasher = Keccak::v256();
    hasher.update(&buf);
    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);
    use ark_ff::{BigInteger, PrimeField};
    let expected_fr = ark_bn254::Fr::from_be_bytes_mod_order(&digest);
    let mut expected = [0u8; 32];
    let bytes = expected_fr.into_bigint().to_bytes_be();
    let copy_len = bytes.len().min(32);
    expected[32 - copy_len..].copy_from_slice(&bytes[..copy_len]);

    let got = raven_railgun_poseidon::token_data_hash_nft(1, token_address, token_sub_id);
    assert_eq!(
        got, expected,
        "NFT tokenHash must be keccak256(type||addr||subid) mod SNARK_PRIME"
    );

    let via_dispatch = raven_railgun_poseidon::token_data_hash(
        raven_railgun_poseidon::TokenType::Erc721,
        token_address,
        token_sub_id,
    );
    assert_eq!(got, via_dispatch);
}

#[test]
fn shield_commitment_hash_railgun_known_vector() {
    // npk=1, tokenHash=2, valueAfterFee=1_000_000.
    // Source: @railgun-community/circomlibjs Node oracle.
    let npk = fr_from_u64(1);
    let token = fr_from_u64(2);
    let value = fr_from_u64(1_000_000);
    let via_helper =
        raven_railgun_poseidon::shield_commitment_hash(npk, token, value).expect("shield");

    let expected_hex = "0a2161b423d7c3e51089062558fbb8ab175493c89395381ddd483608228664b1";
    let mut expected = [0u8; 32];
    for (i, byte) in expected.iter_mut().enumerate() {
        let hi = u8::from_str_radix(&expected_hex[(i * 2)..=(i * 2)], 16).expect("hex hi");
        let lo = u8::from_str_radix(&expected_hex[(i * 2 + 1)..=(i * 2 + 1)], 16).expect("hex lo");
        *byte = (hi << 4) | lo;
    }
    assert_eq!(
        via_helper, expected,
        "shield_commitment_hash(1, 2, 1_000_000) must match the circomlibjs-derived reference; \
         if this fires, light-poseidon's circomlibjs parity has drifted"
    );

    let via_hash_n = hash_n(&[npk, token, value]).expect("hash_n");
    assert_eq!(via_helper, via_hash_n);
}
