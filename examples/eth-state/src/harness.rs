//! Deterministic policy issuers + ground-truth ledger + the integrated stress harness that
//! drives a WRITE firehose while serving + verifying concurrent private READs.
//!
//! Proves the closing correctness story: C1 (every read byte-identical to the independent
//! ledger, zero tolerance), C2 (freshness: chain_head - last_applied <= N), C5 (sustain:
//! sidecar served-state lag bounded under load; serving-QPS reported honestly). The read
//! path is the consume-both fan-out, so C3 (timing-leak safety) holds on every read.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::executor::block_on;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use raven_inspire::params::{InspireParams, ShardConfig};
use raven_inspire::{ClientSession, ServerCrs};

use crate::fold::MainSidecar;
use crate::ingest::{normalize_balance_be, Address, FlatIndex};
use crate::{
    build_session, read_balance_consume_both, AnsweringEngine, EngineHandle, EthStateError,
    ENTRY_SIZE,
};

/// A value transfer between two accounts. With gasPrice=0/baseFee=0 the ledger delta equals
/// the pure value transfer (no fee term), so the ground truth and the served state cannot
/// diverge on gas - the silent C1 killer is removed by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BalanceDelta {
    /// Sender.
    pub from: Address,
    /// Recipient.
    pub to: Address,
    /// Transferred value.
    pub value: u128,
}

/// Three deterministic issuers (alice=0, bob=1, charlie=2). Each round each issuer makes one
/// transfer between two pseudo-random accounts; the same seed yields the same stream.
pub fn issue_round(round: u64, accounts: &[Address], seed: u64) -> Vec<BalanceDelta> {
    let mut deltas = Vec::with_capacity(3);
    for issuer in 0u64..3 {
        let mut rng = ChaCha20Rng::seed_from_u64(seed ^ (round << 8) ^ issuer);
        let from = accounts[rng.gen_range(0..accounts.len())];
        let to = accounts[rng.gen_range(0..accounts.len())];
        if from != to {
            let value = u128::from(rng.gen_range(1u64..50));
            deltas.push(BalanceDelta { from, to, value });
        }
    }
    deltas
}

/// Independent ground-truth ledger: the authoritative balance per address.
#[derive(Debug, Default)]
pub struct Ledger {
    bal: HashMap<Address, u128>,
}

impl Ledger {
    /// A fresh, empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set an account's balance (genesis seed).
    pub fn seed(&mut self, addr: Address, balance: u128) {
        self.bal.insert(addr, balance);
    }

    /// An account's balance (0 if unseen).
    pub fn balance(&self, addr: &Address) -> u128 {
        self.bal.get(addr).copied().unwrap_or(0)
    }

    /// Apply a transfer: sender -= value via a guarded subtraction (an insufficient-balance
    /// transfer is a no-op, like a failed revm `checked_sub`); recipient += value via
    /// `saturating_add` (conserved supply bounded far below `u128::MAX`, so it never saturates).
    /// Returns the touched (address, new-balance) pairs.
    pub fn apply(&mut self, d: &BalanceDelta) -> Vec<(Address, u128)> {
        let from_bal = self.balance(&d.from);
        if from_bal < d.value {
            return vec![];
        }
        let new_from = from_bal - d.value;
        let new_to = self.balance(&d.to).saturating_add(d.value);
        self.bal.insert(d.from, new_from);
        self.bal.insert(d.to, new_to);
        vec![(d.from, new_from), (d.to, new_to)]
    }
}

/// The measured outcome of a stress run.
#[derive(Debug, Clone)]
pub struct StressResult {
    /// Total private reads served + verified.
    pub reads: usize,
    /// C1 failures (read bytes != ledger). MUST be 0.
    pub c1_failures: usize,
    /// C2/C5: max observed freshness lag (chain_head - last_applied), in blocks.
    pub max_lag: u64,
    /// Number of folds performed.
    pub fold_count: usize,
    /// C5: measured serving throughput (reads per second, single-threaded).
    pub qps_per_core: f64,
    /// Mean per-read serving latency in milliseconds.
    pub mean_read_ms: f64,
    /// How many reads the sidecar answered (recently-changed accounts).
    pub sidecar_hits: usize,
}

/// The integrated demo: the main+sidecar pair, the dense index, the ground-truth ledger, and
/// the two client sessions. Shared by the stress gate and the driver.
pub struct Demo {
    /// The main+sidecar fold engine.
    pub ms: MainSidecar,
    /// Dense address -> leaf index.
    pub flat: FlatIndex,
    /// Independent ground-truth ledger.
    pub ledger: Ledger,
    /// The account set, in dense-index order.
    pub accounts: Vec<Address>,
    main_session: ClientSession,
    side_session: ClientSession,
    main_crs: ServerCrs,
    side_crs: ServerCrs,
    params: InspireParams,
    shard_cfg: ShardConfig,
    /// Simulated chain tip (block height).
    pub chain_head: u64,
}

impl Demo {
    /// Build a demo with `num_accounts` accounts each seeded to `seed_balance`, backed by a V6
    /// store under `data_dir`. Addresses are deterministic (the dense index in the low bytes).
    pub fn new(
        num_accounts: usize,
        seed_balance: u128,
        data_dir: impl Into<PathBuf>,
        seed: u64,
    ) -> Result<Self, EthStateError> {
        let params = InspireParams::secure_128_d2048();
        let mut flat = FlatIndex::new();
        let mut ledger = Ledger::new();
        let mut accounts = Vec::with_capacity(num_accounts);
        for i in 0..num_accounts {
            let mut a = [0u8; 20];
            a[12..20].copy_from_slice(&(i as u64).to_be_bytes());
            accounts.push(a);
            flat.assign(a);
            ledger.seed(a, seed_balance);
        }
        let mut db = vec![0u8; num_accounts * ENTRY_SIZE];
        for (i, a) in accounts.iter().enumerate() {
            let rec = normalize_balance_be(&ledger.balance(a).to_be_bytes())?;
            db[i * ENTRY_SIZE..(i + 1) * ENTRY_SIZE].copy_from_slice(&rec);
        }
        let (ms, main_sk, side_sk) = MainSidecar::seed(&params, &db, ENTRY_SIZE, data_dir, seed)?;
        let main_crs = ms.main.current_snapshot().state.crs.clone();
        let side_crs = ms.sidecar.current_snapshot().state.crs.clone();
        let shard_cfg = ms.main.current_snapshot().state.encoded_db.config.clone();
        let main_session = build_session(&main_crs, main_sk, params.sigma, seed.wrapping_add(1))?;
        let side_session = build_session(&side_crs, side_sk, params.sigma, seed.wrapping_add(2))?;
        Ok(Self {
            ms,
            flat,
            ledger,
            accounts,
            main_session,
            side_session,
            main_crs,
            side_crs,
            params,
            shard_cfg,
            chain_head: 0,
        })
    }

    /// Privately read `addr` via the consume-both fan-out and check the decoded balance is
    /// byte-identical to the ground-truth ledger (C1). Returns (c1_ok, answering_engine).
    pub fn read_verify(&self, addr: &Address) -> Result<(bool, AnsweringEngine), EthStateError> {
        let leaf = self
            .flat
            .get(addr)
            .ok_or_else(|| EthStateError::Query("address has no assigned leaf".to_string()))?;
        let main_h = EngineHandle {
            instance: &self.ms.main,
            session: &self.main_session,
            crs: &self.main_crs,
            params: &self.params,
            shard_config: &self.shard_cfg,
        };
        let side_h = EngineHandle {
            instance: &self.ms.sidecar,
            session: &self.side_session,
            crs: &self.side_crs,
            params: &self.params,
            shard_config: &self.shard_cfg,
        };
        let (bytes, eng) = block_on(read_balance_consume_both(&main_h, &side_h, leaf))?;
        let expected = normalize_balance_be(&self.ledger.balance(addr).to_be_bytes())?;
        Ok((bytes.as_ref() == expected, eng))
    }

    /// Current C2 freshness lag: chain_head - last-applied block.
    pub fn freshness_lag(&self) -> u64 {
        self.chain_head.saturating_sub(self.ms.marker())
    }

    /// Apply a block of explicit `(address, new-balance)` updates at `marker`: update the
    /// ground-truth ledger + the engines, advancing the chain head.
    pub fn apply_block(
        &mut self,
        marker: u64,
        updates: &[(Address, u128)],
    ) -> Result<(), EthStateError> {
        let mut rows: Vec<(u64, Bytes)> = Vec::with_capacity(updates.len());
        for (addr, bal) in updates {
            let leaf = self.flat.assign(*addr);
            self.ledger.seed(*addr, *bal);
            let rec = normalize_balance_be(&bal.to_be_bytes())?;
            rows.push((leaf, Bytes::copy_from_slice(&rec)));
        }
        self.ms.apply_updates(marker, &rows)?;
        self.chain_head = marker;
        Ok(())
    }

    /// Trigger a fold (absorb the sidecar into main, reset the sidecar).
    pub fn fold(&mut self) -> Result<(), EthStateError> {
        self.ms.fold()
    }

    /// Run the WRITE firehose with concurrent verified READs and periodic folds (Tier-A,
    /// synthetic, deterministic). `freshness_n` is the C2 bound asserted on each trusted read.
    pub fn run_stress(
        &mut self,
        rounds: u64,
        fold_every: u64,
        reads_per_round: usize,
        freshness_n: u64,
        head_ahead: u64,
        seed: u64,
    ) -> Result<StressResult, EthStateError> {
        let mut c1_failures = 0usize;
        let mut reads = 0usize;
        let mut sidecar_hits = 0usize;
        let mut max_lag = 0u64;
        let mut fold_count = 0usize;
        let mut read_time = Duration::ZERO;
        let mut rng = ChaCha20Rng::seed_from_u64(seed ^ 0x0000_DEAD);

        for round in 1..=rounds {
            // WRITE firehose: issue deltas, fold into the ledger, push the touched rows.
            let deltas = issue_round(round, &self.accounts, seed);
            let mut touched: Vec<(u64, Bytes)> = Vec::new();
            let mut touched_addrs: Vec<Address> = Vec::new();
            for d in &deltas {
                for (addr, bal) in self.ledger.apply(d) {
                    let leaf = self.flat.assign(addr);
                    let rec = normalize_balance_be(&bal.to_be_bytes())?;
                    touched.push((leaf, Bytes::copy_from_slice(&rec)));
                    touched_addrs.push(addr);
                }
            }
            self.ms.apply_updates(round, &touched)?;
            // Simulate the chain running `head_ahead` blocks beyond raven's last-applied marker.
            // Touches only chain_head: the engine and ledger both already advanced to `round`, so
            // freshness_lag becomes `head_ahead` while C1 (served-vs-ledger) is unaffected.
            self.chain_head = round + head_ahead;
            max_lag = max_lag.max(self.freshness_lag());

            // Concurrent verified READs: the just-touched accounts (fresh -> exercise the
            // sidecar) plus some random accounts (exercise the main).
            let mut round_reads = touched_addrs;
            for _ in 0..reads_per_round {
                round_reads.push(self.accounts[rng.gen_range(0..self.accounts.len())]);
            }
            for addr in &round_reads {
                // C2: refuse to trust an answer beyond the freshness bound.
                if self.freshness_lag() > freshness_n {
                    return Err(EthStateError::Query(format!(
                        "freshness violated: lag {} > N {}",
                        self.freshness_lag(),
                        freshness_n
                    )));
                }
                let t = Instant::now();
                let (ok, eng) = self.read_verify(addr)?;
                read_time += t.elapsed();
                reads += 1;
                if !ok {
                    c1_failures += 1;
                }
                if eng == AnsweringEngine::Sidecar {
                    sidecar_hits += 1;
                }
            }

            if round % fold_every == 0 {
                self.ms.fold()?;
                fold_count += 1;
            }
        }

        let secs = read_time.as_secs_f64();
        let qps_per_core = if secs > 0.0 { reads as f64 / secs } else { 0.0 };
        let mean_read_ms = if reads > 0 {
            read_time.as_secs_f64() * 1000.0 / reads as f64
        } else {
            0.0
        };
        Ok(StressResult {
            reads,
            c1_failures,
            max_lag,
            fold_count,
            qps_per_core,
            mean_read_ms,
            sidecar_hits,
        })
    }
}
