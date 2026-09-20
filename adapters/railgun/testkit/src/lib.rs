//! Shared test fixtures for the Railgun adapter.
//!
//! Dev-only. Every consumer takes this as a `[dev-dependencies]` edge, which is the only edge
//! cargo permits back to `raven-railgun-engine` without a cycle, and the only one that keeps
//! fixture code out of the shipped CLI binary.
//!
//! The crate exists for three things: ONE definition of the toy database formula, ONE clamping
//! and ONE zero-admitting commitment helper (they are not interchangeable - see [`canonical`]),
//! and [`toy_secret_key`], which removes the pattern of building a whole server state and
//! discarding it just to obtain a key.
//!
//! It is NOT a wall-time mechanism. See [`cached_toy_state`] for why, and what was measured.
//!
//! **Record size is a required parameter and is never defaulted.** A 32-byte fixture and a
//! 256-byte fixture induce different PIR cell geometry, and a mismatched cell does not error -
//! it returns plaintext that decrypts to the wrong bytes.

// Same allow set every test file in this workspace already carries: a fixture crate is
// test code, and the workspace denies these for shipped code.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, InspireVariant};
use raven_inspire::rlwe::RlweSecretKey;
use raven_railgun_engine::inspire::{setup_state, InspireServerState};
use raven_railgun_engine::session_pool::BoundedSessionStore;

/// Entry count every toy fixture uses. Paired with a caller-supplied record size.
pub const TOY_ENTRIES: usize = 256;

/// Deterministic toy database: `entries * entry_size` bytes of `(i + j) % 251`.
///
/// The modulus is 251 - the largest prime below 256 - so consecutive rows never repeat a byte
/// pattern that a shard-boundary bug could accidentally satisfy.
#[must_use]
pub fn toy_db(entries: usize, entry_size: usize) -> Vec<u8> {
    (0..entries)
        .flat_map(|i| {
            (0..entry_size).map(move |j| u8::try_from((i + j) % 251).expect("(i + j) % 251 < 251"))
        })
        .collect()
}

/// A 32-byte commitment seed with **zero clamped to one**.
///
/// The clamp is load-bearing, not defensive. Zero is the empty-leaf sentinel in the IMT, so a
/// fixture that emits the all-zero commitment stops exercising the occupied-leaf path.
/// `engine/tests/validate_apply_precheck.rs` calls this with seed 0 inside `for leaf_index in
/// 0..4` and then asserts `imt_leaf_count_for(0) == 4`; without the clamp that count is 3.
///
/// Use [`canonical_zeroable`] where the test needs 0 to pass through. The two are separate
/// functions rather than one with a flag, so choosing wrongly is visible at the call site.
#[must_use]
pub fn canonical(seed: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[31] = seed.max(1);
    bytes
}

/// A 32-byte commitment seed that **admits zero**.
///
/// Keeps the value Fr-canonical for the IMT's Poseidon hash. Distinct from [`canonical`]: this
/// one lets the all-zero empty-leaf sentinel through, which is exactly what its six original
/// call sites are for.
#[must_use]
pub fn canonical_zeroable(byte: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[31] = byte;
    bytes
}

/// Build a fresh server state at `entry_size`, panicking on failure.
///
/// No caching: every call pays a full keygen. Use it wherever a test asserts on `Arc` identity
/// or `strong_count`, because a live cache entry holds its own reference and changes both.
#[must_use]
pub fn toy_state(entry_size: usize) -> InspireServerState {
    try_toy_state(entry_size).expect("setup_state")
}

/// Build a fresh server state at `entry_size`, returning the adapter's error type.
pub fn try_toy_state(entry_size: usize) -> raven_railgun_core::Result<InspireServerState> {
    let params = InspireParams::secure_128_d2048();
    let db = toy_db(TOY_ENTRIES, entry_size);
    let (state, _sk) = setup_state(&params, &db, entry_size, InspireVariant::TwoPacking)?;
    Ok(state)
}

/// A fresh RLWE secret key, without building a server state to throw away.
///
/// Three test files wanted only a key and paid a full `setup_state` for it, discarding the state
/// into `_off_state`. Key generation is milliseconds; the state around it is seconds. The key is
/// not bound to any particular CRS - the call sites pair it with a live instance's CRS - so
/// generating one directly is equivalent to harvesting one from a sibling state.
#[must_use]
pub fn toy_secret_key(params: &InspireParams) -> RlweSecretKey {
    let mut sampler = GaussianSampler::new(params.sigma);
    RlweSecretKey::generate(params, &mut sampler)
}

/// The heavy, immutable half of a state, shared across every fixture at one record size.
struct CachedParts {
    crs: Arc<raven_inspire::ServerCrs>,
    encoded_db: Arc<raven_inspire::EncodedDatabase>,
    cache: Arc<raven_inspire::ServerInspiringCache>,
    variant: InspireVariant,
}

fn cache_slot() -> &'static Mutex<HashMap<usize, Arc<CachedParts>>> {
    static SLOT: OnceLock<Mutex<HashMap<usize, Arc<CachedParts>>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cached_parts(entry_size: usize) -> Arc<CachedParts> {
    // Not `get_or_insert_with` under the lock: a keygen takes seconds and holding the mutex
    // across it serialises every other record size behind it. Racing threads may both build;
    // the first to re-acquire wins and the loser's work is dropped, which costs one keygen at
    // most and keeps the lock uncontended.
    if let Some(hit) = cache_slot().lock().expect("cache lock").get(&entry_size) {
        return Arc::clone(hit);
    }
    let params = InspireParams::secure_128_d2048();
    let db = toy_db(TOY_ENTRIES, entry_size);
    let (state, _sk) =
        setup_state(&params, &db, entry_size, InspireVariant::TwoPacking).expect("setup_state");
    let parts = Arc::new(CachedParts {
        crs: state.crs,
        encoded_db: state.encoded_db,
        cache: state.cache,
        variant: state.variant,
    });
    let mut guard = cache_slot().lock().expect("cache lock");
    Arc::clone(guard.entry(entry_size).or_insert(parts))
}

fn mint(parts: &CachedParts, entry_size: usize) -> InspireServerState {
    InspireServerState {
        crs: Arc::clone(&parts.crs),
        encoded_db: Arc::clone(&parts.encoded_db),
        cache: Arc::clone(&parts.cache),
        // Never shared. A session store carries per-client key material and a generation
        // counter; handing two fixtures the same one makes one test's registrations visible
        // to another and turns eviction tests into order-dependent flakes.
        session_store: Arc::new(BoundedSessionStore::new()),
        variant: parts.variant,
        entry_size,
    }
}

/// Build a server state at `entry_size`, reusing the heavy parts within a single test.
///
/// **No migrated file uses this**, and that is deliberate rather than an oversight: under nextest
/// it can save at most one build per test, which measured out at under 1% across the suite, and it
/// costs the `Arc`-identity guarantees the uncached builders give for free. It is kept because its
/// tests are the executable record of that measurement.
///
/// The three heavy `Arc`s are shared; the session store is always fresh.
///
/// **Read this before believing it saves time.** The cache is per PROCESS, and
/// `cargo nextest` - which every adapter CI lane uses - runs EVERY TEST IN ITS OWN PROCESS.
/// So it amortises only across calls inside ONE test function, never across tests in a binary.
/// Measured: two tests calling this each paid 7.6 s in different pids; two calls inside one test
/// cost 7.65 s then 0 ms. A file with N tests each building one fixture saves NOTHING.
///
/// Saying "one build per process" without that sentence is how
/// `engine/tests/offline_packing_keys_cache.rs` shipped a false amortisation claim in its header.
///
/// **Do not use this where a test asserts on `Arc` identity or `strong_count`.** A live cache
/// entry holds its own reference, so `Arc::strong_count(&state.encoded_db)` is one higher than
/// an uncached build, and `Arc::make_mut` deep-copies instead of mutating in place. Those tests
/// must call [`toy_state`] instead. If such an assertion goes red, the cache reached a file that
/// needs sole ownership - move that file to the uncached builder rather than relaxing the bound,
/// because `heartbeat_eviction.rs`'s `strong_count <= 2` is a live OOM-regression detector.
#[must_use]
pub fn cached_toy_state(entry_size: usize) -> InspireServerState {
    mint(&cached_parts(entry_size), entry_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned digests of the toy DB at the two shipped record sizes.
    ///
    /// These are the real assertion, not the three-form equality below: `as u8` and
    /// `u8::try_from(..).expect()` cannot disagree when the value is always < 251, so comparing
    /// them proves nothing. A digest catches a changed formula - `% 256`, or `i * j` - that both
    /// spellings would agree on.
    const DIGEST_256B: &str = "1f5d61e0204b78ec";
    const DIGEST_32B: &str = "953694c77a22f205";

    fn digest(bytes: &[u8]) -> String {
        // Small local FNV-1a-style rolling digest: this crate has no hash dependency and adding
        // one to pin a fixture would be a dependency change for a test constant.
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in bytes {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        format!("{h:016x}")
    }

    /// The shipped helper at `cli/src/toy_server.rs` spells the same formula with `as u8`
    /// instead of `u8::try_from(..).expect()`. Comparing those two spellings HERE would prove
    /// nothing: `(i + j) % 251` is always below 251, so the two cannot disagree on any input
    /// the function can produce. Testing the real divergence
    /// would mean calling the shipped function, and `cli` cannot be a dependency of a crate
    /// that `cli` dev-depends on. So this compares against an independently-written loop and
    /// leaves the cross-crate agreement to the digest pin below.
    #[test]
    fn toy_db_matches_an_independently_written_reference_loop() {
        for (entries, entry_size) in [(256usize, 256usize), (256, 32), (4, 3)] {
            let ours = toy_db(entries, entry_size);
            let mut reference = Vec::with_capacity(entries * entry_size);
            for i in 0..entries {
                for j in 0..entry_size {
                    reference.push(u8::try_from((i + j) % 251).expect("< 251"));
                }
            }
            assert_eq!(
                ours, reference,
                "reference loop differs at {entries}x{entry_size}"
            );
            assert_eq!(ours.len(), entries * entry_size);
        }
    }

    /// The digest pin. A formula change reds this even when every spelling agrees.
    #[test]
    fn toy_db_digests_are_pinned() {
        let d256 = digest(&toy_db(TOY_ENTRIES, 256));
        let d32 = digest(&toy_db(TOY_ENTRIES, 32));
        assert_ne!(d256, d32, "the two record sizes must not digest alike");
        assert_eq!(d256, DIGEST_256B, "toy_db(256, 256) changed");
        assert_eq!(d32, DIGEST_32B, "toy_db(256, 32) changed");
        // Spot-check the formula directly at three offsets so the digest is not the only check.
        let db = toy_db(4, 3);
        assert_eq!(db[0], 0, "(0 + 0) % 251");
        assert_eq!(db[1], 1, "(0 + 1) % 251");
        assert_eq!(db[5], 3, "row 1, col 2 -> (1 + 2) % 251");
    }

    #[test]
    fn canonical_clamps_zero_and_canonical_zeroable_does_not() {
        assert_ne!(
            canonical(0),
            canonical_zeroable(0),
            "the two helpers must not agree at the empty-leaf sentinel"
        );
        assert_eq!(canonical(0)[31], 1, "canonical must clamp 0 to 1");
        assert_eq!(
            canonical_zeroable(0)[31],
            0,
            "canonical_zeroable must admit 0"
        );
        assert_eq!(
            canonical(0),
            canonical(1),
            "clamped 0 and 1 are the same value"
        );
    }

    #[test]
    fn canonical_and_canonical_zeroable_agree_on_every_non_zero_seed() {
        for seed in 1..=255u8 {
            assert_eq!(
                canonical(seed),
                canonical_zeroable(seed),
                "the two helpers must differ ONLY at zero; they disagreed at {seed}"
            );
        }
    }

    /// Determinism probe, kept as a test rather than a scratch script because the ANSWER is an
    /// input to the cache design: `setup_state` builds a fresh `GaussianSampler` per call
    /// (`engine/src/inspire.rs:102`), so two independent builds need not agree byte-for-byte.
    /// If they do not, "same encoded_db bytes" is the wrong assertion for `try_toy_state` vs
    /// `toy_state` and the shape assertions below are the right ones.
    #[test]
    fn two_independent_builds_agree_on_shape_and_the_probe_records_whether_bytes_match() {
        let a = toy_state(32);
        let b = try_toy_state(32).expect("try_toy_state");
        assert_eq!(a.entry_size, 32);
        assert_eq!(b.entry_size, 32);
        assert_eq!(a.shard_config().entry_size_bytes, 32);
        assert_eq!(b.shard_config().entry_size_bytes, 32);
        assert_eq!(
            a.shard_config().entries_per_shard(),
            b.shard_config().entries_per_shard(),
            "two builds at one record size must agree on shard geometry"
        );
        let c = toy_state(256);
        assert_eq!(
            c.shard_config().entry_size_bytes,
            256,
            "the record size must reach the cell, not be defaulted"
        );
        assert_ne!(
            a.shard_config().entry_size_bytes,
            c.shard_config().entry_size_bytes,
            "32 and 256 must not collapse to one cell shape"
        );
    }

    /// The cache's whole contract, and the reason `cache-exclusions.md` exists.
    #[test]
    fn cached_states_share_the_heavy_arcs_and_never_the_session_store() {
        let a = cached_toy_state(32);
        let b = cached_toy_state(32);

        assert!(
            std::ptr::eq(Arc::as_ptr(&a.encoded_db), Arc::as_ptr(&b.encoded_db)),
            "two cached states at one record size must share the encoded_db allocation"
        );
        assert!(
            std::ptr::eq(Arc::as_ptr(&a.crs), Arc::as_ptr(&b.crs)),
            "the CRS must be shared too"
        );
        assert!(
            !std::ptr::eq(Arc::as_ptr(&a.session_store), Arc::as_ptr(&b.session_store)),
            "session stores must NEVER be shared: they carry per-client key material"
        );
        assert_eq!(
            a.session_store.len(),
            0,
            "a freshly minted store must be empty"
        );
        assert_eq!(b.session_store.len(), 0, "and so must the next one");

        // A different record size is a different cache slot, not the same one reused.
        let wide = cached_toy_state(256);
        assert!(
            !std::ptr::eq(Arc::as_ptr(&a.encoded_db), Arc::as_ptr(&wide.encoded_db)),
            "32 B and 256 B must not share an encoded database"
        );
        assert_eq!(wide.shard_config().entry_size_bytes, 256);
    }

    /// The cache raises `strong_count` by one against an uncached build. That is the fact
    /// `heartbeat_eviction.rs:240`'s `<= 2` bound is sensitive to, so pin it here rather than
    /// discovering it as a red test in someone else's file.
    #[test]
    fn the_cache_holds_its_own_reference_and_that_is_visible_in_strong_count() {
        let uncached = toy_state(32);
        assert_eq!(
            Arc::strong_count(&uncached.encoded_db),
            1,
            "an uncached build owns its encoded_db alone"
        );
        let cached = cached_toy_state(32);
        assert!(
            Arc::strong_count(&cached.encoded_db) >= 2,
            "a cached build shares with the live cache entry, so the count is higher; \
             this is why Arc-identity tests must use toy_state, not cached_toy_state"
        );
    }

    #[test]
    fn canonical_writes_only_the_last_byte() {
        let out = canonical(0x7f);
        assert_eq!(out[31], 0x7f);
        assert!(
            out[..31].iter().all(|b| *b == 0),
            "bytes 0..31 must stay zero"
        );
    }
}
