//! Real anvil JSON-RPC E2E driver (feature `anvil-e2e`). Seeds balances via the anvil cheat
//! codes (no signing, no gas), reads them back, and serves them through the SAME consume-both
//! fan-out + C1 verifier as the synthetic gate. The synthetic deterministic mode remains the
//! offline exit gate; this path needs a running anvil node and is the Sepolia-promotion route.

// Operator-facing E2E driver output, like the synthetic bin entry point.
#![allow(clippy::print_stdout)]

use std::error::Error;

use alloy::primitives::{Address as EvmAddress, U256};
use alloy::providers::ext::AnvilApi;
use alloy::providers::{Provider, ProviderBuilder};
use futures::executor::block_on;

use crate::fold::MainSidecar;
use crate::ingest::normalize_balance_be;
use crate::{build_session, read_balance_consume_both, EngineHandle, ENTRY_SIZE};
use raven_inspire::params::InspireParams;

/// Run the anvil-backed E2E: seed `num_accounts` balances on the node, serve `reads` private
/// reads through the consume-both fan-out, and verify each against the on-chain balance.
pub fn run(rpc_url: &str, num_accounts: usize, reads: usize) -> Result<(), Box<dyn Error>> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(run_async(rpc_url, num_accounts, reads))
}

fn leaf_address(i: usize) -> EvmAddress {
    let mut a = [0u8; 20];
    a[12..].copy_from_slice(&(i as u64).to_be_bytes());
    EvmAddress::from(a)
}

async fn run_async(
    rpc_url: &str,
    num_accounts: usize,
    reads: usize,
) -> Result<(), Box<dyn Error>> {
    let provider = ProviderBuilder::new().connect(rpc_url).await?;
    // baseFee=0 so the cheat-coded balances are the whole ledger (no fee term).
    provider.anvil_set_next_block_base_fee_per_gas(0u128).await?;

    // Seed balances via the cheat code, then read each back as the ground truth.
    let mut ledger: Vec<u128> = Vec::with_capacity(num_accounts);
    for i in 0..num_accounts {
        let addr = leaf_address(i);
        provider
            .anvil_set_balance(addr, U256::from((i as u128 + 1) * 1000))
            .await?;
    }
    provider.anvil_mine(Some(1), None).await?;
    for i in 0..num_accounts {
        let bal: U256 = provider.get_balance(leaf_address(i)).await?;
        let be = bal.to_be_bytes::<32>();
        // Guarded narrowing to u128 (the demo's ground-truth ledger is u128): error rather than
        // truncate if a balance exceeds 2^128. The tagged record itself holds up to 2^248.
        if be[..16].iter().any(|&b| b != 0) {
            return Err(format!("on-chain balance for account {i} exceeds u128").into());
        }
        let mut low = [0u8; 16];
        low.copy_from_slice(&be[16..]);
        ledger.push(u128::from_be_bytes(low));
    }

    // Build the PIR corpus from the on-chain balances and serve it.
    let params = InspireParams::secure_128_d2048();
    let mut db = vec![0u8; num_accounts * ENTRY_SIZE];
    for (i, &bal) in ledger.iter().enumerate() {
        let rec = normalize_balance_be(&bal.to_be_bytes())?;
        db[i * ENTRY_SIZE..(i + 1) * ENTRY_SIZE].copy_from_slice(&rec);
    }
    let dir = std::env::temp_dir().join(format!("raven-eth-state-anvil-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let (ms, main_sk, side_sk) =
        MainSidecar::seed(&params, &db, ENTRY_SIZE, &dir, 0x0000_A471)?;

    let main_crs = ms.main.current_snapshot().state.crs.clone();
    let side_crs = ms.sidecar.current_snapshot().state.crs.clone();
    let shard_cfg = ms.main.current_snapshot().state.encoded_db.config.clone();
    let main_session = build_session(&main_crs, main_sk, params.sigma, 1)?;
    let side_session = build_session(&side_crs, side_sk, params.sigma, 2)?;

    let main_h = EngineHandle {
        instance: &ms.main,
        session: &main_session,
        crs: &main_crs,
        params: &params,
        shard_config: &shard_cfg,
    };
    let side_h = EngineHandle {
        instance: &ms.sidecar,
        session: &side_session,
        crs: &side_crs,
        params: &params,
        shard_config: &shard_cfg,
    };

    let mut c1_failures = 0usize;
    let mut served = 0usize;
    for (i, &bal) in ledger.iter().enumerate().take(reads) {
        let (bytes, _eng) = block_on(read_balance_consume_both(&main_h, &side_h, i as u64))?;
        let expected = normalize_balance_be(&bal.to_be_bytes())?;
        if bytes.as_ref() != expected.as_slice() {
            c1_failures += 1;
        }
        served += 1;
    }

    let c1 = c1_failures == 0;
    println!("anvil E2E (rpc {rpc_url}): seeded {num_accounts} accounts, served {served} reads.");
    println!("C1 correctness (PIR == on-chain balance): {}", if c1 { "PASS" } else { "FAIL" });
    println!(
        "{{\"bench\":\"eth_state_anvil\",\"accounts\":{num_accounts},\"reads\":{served},\"c1_failures\":{c1_failures}}}"
    );
    if c1 {
        Ok(())
    } else {
        Err(format!("anvil C1 failed: {c1_failures} mismatches").into())
    }
}
