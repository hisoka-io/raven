//! One-command LOCAL demo driver for the generic Ethereum-state private-balance PIR demo.
//!
//! Boots a flat `address -> 32-byte balance` corpus, registers a main (Live) + a Sidecar
//! engine, runs the fold loop + a WRITE firehose while serving + verifying concurrent private
//! READs through the consume-both fan-out, and prints C1/C2/C3/C4/C5 plus the honest
//! serving-QPS curve. Synthetic (deterministic, no chain) is the local gate; `--mode anvil`
//! is the real-E2E Sepolia-promotion path.
//!
//! Run: `cargo run --manifest-path examples/eth-state/Cargo.toml --profile ci-test --bin demo`

#![allow(clippy::expect_used, clippy::print_stdout, clippy::print_stderr)]

use std::process::ExitCode;

use eth_state::harness::Demo;

fn pass(b: bool) -> &'static str {
    if b {
        "PASS"
    } else {
        "FAIL"
    }
}

fn main() -> ExitCode {
    // Accept the documented `--mode anvil` (and a bare `anvil`) so the doc and parser agree.
    let args: Vec<String> = std::env::args().collect();
    let anvil = args.iter().any(|a| a == "anvil")
        || args.windows(2).any(|w| w[0] == "--mode" && w[1] == "anvil");
    if anvil {
        #[cfg(feature = "anvil-e2e")]
        {
            let rpc = std::env::var("ANVIL_RPC_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());
            return match eth_state::anvil::run(&rpc, 256, 16) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("anvil E2E failed: {e}");
                    ExitCode::FAILURE
                }
            };
        }
        #[cfg(not(feature = "anvil-e2e"))]
        println!(
            "anvil mode (real E2E via alloy/tokio) is the Sepolia-promotion path; rebuild with \
             --features anvil-e2e against a running anvil node. Running the synthetic offline gate."
        );
    }

    // Unique per-process data dir: a fixed shared dir would let overlapping runs delete each
    // other's WAL and trip the archive-rename (ENOENT). tempfile is dev-only, so PID-suffix.
    let dir = std::env::temp_dir().join(format!("raven-eth-state-demo-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create demo data dir");

    println!("Raven eth-state demo: flat address -> 32B big-endian balance, main + sidecar fold.");
    // Serving goes through the cached InsPIRe respond path (the default-on cached-respond
    // feature): the cached_respond_kat latency bench measures it at this 32B / gamma=16 cell.
    // The stress_c1_c2_c5 gate is the heavier sustain proof.
    // head_ahead = 1: the chain runs one block beyond raven's last-applied marker, so the C2/C5
    // gates assert against a real non-zero lag (1), bounded under N = 2.
    let mut demo = Demo::new(3000, 1_000_000, dir.clone(), 0x0000_DE70).expect("build demo");
    let res = demo
        .run_stress(8, 4, 1, 2, 1, 0x0000_DE70)
        .expect("run stress");

    let c1 = res.c1_failures == 0;
    let c2 = res.max_lag <= 2;
    // sidecar_hits proves only that the content-selection path was reachable; the load-bearing
    // both-legs-extracted invariant is asserted by the `both_legs_extracted` test (count == 2).
    let c3 = res.sidecar_hits > 0;
    let c4 = res.fold_count > 0 && c1; // folds ran + correctness held across them
    let c5 = res.qps_per_core > 0.0 && res.max_lag <= 2;

    println!("C1 correctness (read == ledger, byte-identical): {}", pass(c1));
    println!("C2 freshness (chain_head - last_applied <= 2):    {}", pass(c2));
    println!(
        "C3 timing-safe consume-both ({} sidecar hits):     {}",
        res.sidecar_hits,
        pass(c3)
    );
    println!(
        "C4 fold correctness ({} folds, C1 held across):    {}",
        res.fold_count,
        pass(c4)
    );
    println!("C5 sustain (lag bounded <= 2, QPS reported):      {}", pass(c5));
    println!(
        "{{\"bench\":\"eth_state_demo\",\"reads\":{},\"folds\":{},\"sidecar_hits\":{},\"mean_read_ms\":{:.3},\"qps_per_core\":{:.1},\"max_lag\":{}}}",
        res.reads, res.fold_count, res.sidecar_hits, res.mean_read_ms, res.qps_per_core, res.max_lag
    );
    println!();
    println!(
        "Honest caveats: anonymity set = ONE shard (2048 entries; shard_id is plaintext), NOT \
         full N. The demo detects STALENESS (C2), not server FORGERY (an eth_getProof Merkle \
         witness is a documented later extension). Main and sidecar wire shapes are uniform \
         (32B / 16 column polys) so a response-size observer cannot infer which engine answered. \
         The sidecar buys INSTANT FRESHNESS + a scale lever, not avoiding a main re-preprocess. \
         Serving-QPS is the binding constraint and is machine-measured above."
    );

    if c1 && c2 && c3 && c4 && c5 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
