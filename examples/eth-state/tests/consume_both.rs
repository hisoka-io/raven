//! The fan-out selects on decrypted content, never on arrival order. The companion
//! both-legs-extracted invariant is asserted by `both_legs_extracted` in src/lib.rs.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use eth_state::harness::Demo;
use eth_state::AnsweringEngine;

#[test]
fn consume_both() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut demo = Demo::new(3000, 1_000_000, dir.path(), 0x0000_C0DE).expect("demo");

    let changed_a = demo.accounts[42];
    let changed_b = demo.accounts[2500]; // a different shard
    demo.apply_block(1, &[(changed_a, 777_777), (changed_b, 888_888)])
        .expect("apply block");

    let (ok_a, eng_a) = demo.read_verify(&changed_a).expect("read a");
    assert!(ok_a, "C1: changed account a byte-identical to ledger");
    assert_eq!(
        eng_a,
        AnsweringEngine::Sidecar,
        "fresh account selects sidecar on content"
    );

    let (ok_b, eng_b) = demo.read_verify(&changed_b).expect("read b");
    assert!(ok_b, "C1: changed account b byte-identical to ledger");
    assert_eq!(
        eng_b,
        AnsweringEngine::Sidecar,
        "fresh account (other shard) selects sidecar"
    );

    let untouched = demo.accounts[100];
    let (ok_m, eng_m) = demo.read_verify(&untouched).expect("read main");
    assert!(ok_m, "C1: untouched account byte-identical to ledger");
    assert_eq!(
        eng_m,
        AnsweringEngine::Main,
        "untouched account falls back to main"
    );

    demo.fold().expect("fold");
    let (ok_post, eng_post) = demo.read_verify(&changed_a).expect("read post-fold");
    assert!(
        ok_post,
        "C1: post-fold changed account still byte-identical to ledger"
    );
    assert_eq!(
        eng_post,
        AnsweringEngine::Main,
        "post-fold the folded account is served by main"
    );
}
