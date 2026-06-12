//! C3 gate: the consume-both timing-leak invariant has its own barrier.
//!
//! A timing leak could pass the stress gate if a sidecar hit were never exercised, so C3 is
//! a distinct asserting test: both engine legs are decoded and the answer is selected on
//! decrypted CONTENT (a present sidecar value wins; an absent one falls back to main),
//! never on arrival order. Both selection paths working proves both legs are extracted.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic, clippy::print_stdout, clippy::print_stderr)]


use eth_state::harness::Demo;
use eth_state::AnsweringEngine;

#[test]
fn consume_both() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut demo = Demo::new(3000, 1_000_000, dir.path(), 0x0000_C0DE).expect("demo");

    // Change two accounts at block 1 (they land in the sidecar, fresher than main).
    let changed_a = demo.accounts[42];
    let changed_b = demo.accounts[2500]; // a different shard
    demo.apply_block(1, &[(changed_a, 777_777), (changed_b, 888_888)])
        .expect("apply block");

    // A changed account: the sidecar holds the fresh value -> selected on content, and the
    // decoded value is byte-identical to the ledger (proves the sidecar leg was extracted).
    let (ok_a, eng_a) = demo.read_verify(&changed_a).expect("read a");
    assert!(ok_a, "C1: changed account a byte-identical to ledger");
    assert_eq!(eng_a, AnsweringEngine::Sidecar, "fresh account selects sidecar on content");

    let (ok_b, eng_b) = demo.read_verify(&changed_b).expect("read b");
    assert!(ok_b, "C1: changed account b byte-identical to ledger");
    assert_eq!(eng_b, AnsweringEngine::Sidecar, "fresh account (other shard) selects sidecar");

    // An untouched account: the sidecar is absent -> falls back to main (proves the main leg
    // was extracted and the selection is content-based, not arrival-order).
    let untouched = demo.accounts[100];
    let (ok_m, eng_m) = demo.read_verify(&untouched).expect("read main");
    assert!(ok_m, "C1: untouched account byte-identical to ledger");
    assert_eq!(eng_m, AnsweringEngine::Main, "untouched account falls back to main");

    // After a fold the sidecar resets: the once-changed account is now served by main.
    demo.fold().expect("fold");
    let (ok_post, eng_post) = demo.read_verify(&changed_a).expect("read post-fold");
    assert!(ok_post, "C1: post-fold changed account still byte-identical to ledger");
    assert_eq!(eng_post, AnsweringEngine::Main, "post-fold the folded account is served by main");
}
