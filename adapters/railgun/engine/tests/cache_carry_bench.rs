//! `inspire::swap_state` cache-carry bench (`#[ignore]`-gated).
//! Carry path asserts median ≤ 50 ms; rebuild path asserts median > 1 s as a
//! regression guard against an always-carry bug.

#![allow(clippy::expect_used, clippy::print_stderr)]

use std::time::{Duration, Instant};

use raven_inspire::params::{InspireParams, InspireVariant};
use raven_railgun_core::{Epoch, InstanceId};
use raven_railgun_engine::{inspire, InstanceRole, PirInstance};

const ENTRIES_LOG2: usize = 16;
const ENTRY_BYTES: usize = 512;
const MEASURED_ITERS: usize = 3;

fn build_synthetic_db(n_entries: usize, entry_bytes: usize) -> Vec<u8> {
    #[allow(clippy::cast_possible_truncation)]
    (0..n_entries)
        .flat_map(|i| (0..entry_bytes).map(move |j| ((i * 31 + j * 17) % 251) as u8))
        .collect()
}

fn median_of(timings: &[Duration]) -> Duration {
    let mut sorted = timings.to_vec();
    sorted.sort();
    *sorted.get(sorted.len() / 2).expect("non-empty timings")
}

fn build_donor_state(params: &InspireParams) -> PirInstance<inspire::RavenInspireScheme> {
    let entries = 1usize << ENTRIES_LOG2;
    let db = build_synthetic_db(entries, ENTRY_BYTES);
    let (state, _sk) = inspire::setup_state(params, &db, ENTRY_BYTES, InspireVariant::TwoPacking)
        .expect("donor setup_state");
    PirInstance::new(
        InstanceId::new("cache-carry-bench"),
        InstanceRole::Live,
        state,
    )
}

#[test]
#[ignore = "production-cell setup is heavy (~12s); cache-carry latency measurement"]
fn swap_state_with_matching_seed_carries_cache_under_50ms() {
    let setup_start = Instant::now();
    let params = InspireParams::secure_128_d2048();
    let instance = build_donor_state(&params);
    let setup_elapsed = setup_start.elapsed();
    eprintln!("cache_carry_bench: donor setup elapsed = {setup_elapsed:?}");

    let mut timings: Vec<Duration> = Vec::with_capacity(MEASURED_ITERS);
    for iter in 0..MEASURED_ITERS {
        let donor = instance.current_state();
        let crs_clone = (*donor.crs).clone();
        let db_clone = donor.encoded_db.clone();
        let variant = donor.variant;
        let entry_size = donor.entry_size;
        let next_epoch = instance.current_epoch().next();
        drop(donor);

        let swap_start = Instant::now();
        inspire::swap_state(
            &instance, crs_clone, db_clone, variant, entry_size, next_epoch,
        )
        .expect("carry swap_state");
        let swap_elapsed = swap_start.elapsed();
        eprintln!("cache_carry_bench: carry iter={iter} swap elapsed = {swap_elapsed:?}");
        timings.push(swap_elapsed);
    }

    let median = median_of(&timings);
    let min = timings.iter().min().copied().unwrap_or_default();
    let max = timings.iter().max().copied().unwrap_or_default();
    eprintln!("cache_carry_bench: carry summary min={min:?} median={median:?} max={max:?}");

    assert!(
        median <= Duration::from_millis(50),
        "carry-path swap regressed: median={median:?} > 50 ms (target lift from \
         ~3.7 s rebuild baseline; min={min:?} max={max:?})"
    );
    assert!(
        instance.current_epoch() > Epoch::ZERO,
        "swap_state must bump the epoch on every iteration"
    );
}

#[test]
#[ignore = "production-cell setup is heavy (~12s); rebuild-path regression guard"]
fn swap_state_with_mismatched_seed_rebuilds_cache_above_baseline() {
    let setup_start = Instant::now();
    let params = InspireParams::secure_128_d2048();
    let instance = build_donor_state(&params);
    let setup_elapsed = setup_start.elapsed();
    eprintln!("cache_carry_bench: rebuild-guard donor setup elapsed = {setup_elapsed:?}");

    let mut timings: Vec<Duration> = Vec::with_capacity(MEASURED_ITERS);
    for iter in 0..MEASURED_ITERS {
        let donor = instance.current_state();
        let mut crs_clone = (*donor.crs).clone();
        let mut new_seed = crs_clone.inspiring_w_seed;
        #[allow(clippy::cast_possible_truncation)]
        {
            new_seed[0] = new_seed[0].wrapping_add((iter as u8).wrapping_add(1));
            new_seed[1] = new_seed[1].wrapping_add((iter as u8).wrapping_add(7));
        }
        assert_ne!(
            new_seed, crs_clone.inspiring_w_seed,
            "rebuild test seed mutation must differ from donor seed (iter={iter})"
        );
        crs_clone.inspiring_w_seed = new_seed;
        let db_clone = donor.encoded_db.clone();
        let variant = donor.variant;
        let entry_size = donor.entry_size;
        let next_epoch = instance.current_epoch().next();
        drop(donor);

        let swap_start = Instant::now();
        inspire::swap_state(
            &instance, crs_clone, db_clone, variant, entry_size, next_epoch,
        )
        .expect("rebuild swap_state");
        let swap_elapsed = swap_start.elapsed();
        eprintln!("cache_carry_bench: rebuild iter={iter} swap elapsed = {swap_elapsed:?}");
        timings.push(swap_elapsed);
    }

    let median = median_of(&timings);
    let min = timings.iter().min().copied().unwrap_or_default();
    let max = timings.iter().max().copied().unwrap_or_default();
    eprintln!("cache_carry_bench: rebuild summary min={min:?} median={median:?} max={max:?}");

    assert!(
        median > Duration::from_secs(1),
        "rebuild-path swap collapsed below the baseline floor: median={median:?} \
         <= 1 s (regression guard against an always-carry bug; min={min:?} \
         max={max:?})"
    );
}
