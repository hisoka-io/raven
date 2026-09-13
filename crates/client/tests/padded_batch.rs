#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::expect_used, clippy::panic)]

use proptest::prelude::*;
use rand::RngCore;
use raven_client::{
    build_padded_batch_rust, build_padded_batch_rust_with_test_rng, extract_response_rust,
    padded_batch_ladder, PaddedBatchError,
};
use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, SecurityLevel, ShardConfig};
use raven_inspire::{
    respond_seeded_inspiring_cached_with_session, setup, ClientSession, EncodedDatabase,
    ServerInspiringCache, ServerSessionStore,
};

const ENTRY_BYTES: usize = 32;

fn params() -> InspireParams {
    InspireParams {
        ring_dim: 256,
        q: 1_152_921_504_606_830_593,
        crt_moduli: vec![1_152_921_504_606_830_593],
        p: 65_537,
        sigma: 6.4,
        gadget_base: 1 << 20,
        gadget_len: 3,
        security_level: SecurityLevel::Bits128,
    }
}

struct Fixture {
    params: InspireParams,
    session: ClientSession,
    encoded: EncodedDatabase,
    database: Vec<u8>,
    store: ServerSessionStore,
}

impl Fixture {
    fn shard_config(&self) -> &ShardConfig {
        &self.encoded.config
    }
}

fn fixture() -> Fixture {
    let params = params();
    let database = (0..params.ring_dim * ENTRY_BYTES)
        .map(|offset| {
            let row = offset / ENTRY_BYTES;
            let byte = offset % ENTRY_BYTES;
            u8::try_from((row * 7 + byte) % 251).expect("below 251")
        })
        .collect::<Vec<_>>();
    let mut setup_sampler = GaussianSampler::with_seed(params.sigma, 17);
    let (crs, encoded, secret_key) =
        setup(&params, &database, ENTRY_BYTES, &mut setup_sampler).expect("setup");
    let mut session_sampler = GaussianSampler::with_seed(params.sigma, 19);
    let mut session = ClientSession::new(crs, secret_key, &mut session_sampler).expect("session");
    let store = ServerSessionStore::new();
    session
        .register_with_server_derivation(&store)
        .expect("register session")
        .expect("packing handle");
    Fixture {
        params,
        session,
        encoded,
        database,
        store,
    }
}

struct ScriptedRng {
    draws: std::collections::VecDeque<u64>,
}

impl ScriptedRng {
    fn new(draws: impl IntoIterator<Item = u64>) -> Self {
        Self {
            draws: draws.into_iter().collect(),
        }
    }
}

impl RngCore for ScriptedRng {
    fn next_u32(&mut self) -> u32 {
        u32::try_from(self.next_u64() & u64::from(u32::MAX)).expect("masked to u32")
    }

    fn next_u64(&mut self) -> u64 {
        self.draws.pop_front().unwrap_or(0)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(
                bytes
                    .get(..chunk.len())
                    .expect("chunk is at most eight bytes"),
            );
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[test]
fn generated_ladder_uses_the_measured_query_size_and_exact_body_cap() {
    assert_eq!(
        padded_batch_ladder(100, 410).expect("four slots fit exactly"),
        [1, 2, 4]
    );
    assert_eq!(
        padded_batch_ladder(100, 409).expect("three raw slots leave two padded slots"),
        [1, 2]
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn ladder_matches_real_counts_query_sizes_and_body_caps(
        serialized_query_bytes in 1usize..=100_000,
        raw_slot_capacity in 1usize..=4_096,
        real_count in 1usize..=4_096,
        trailing_bytes in 0usize..100_000,
    ) {
        let trailing_bytes = trailing_bytes % serialized_query_bytes;
        let body_cap_bytes = 10 + raw_slot_capacity * serialized_query_bytes + trailing_bytes;
        let ladder = padded_batch_ladder(serialized_query_bytes, body_cap_bytes)
            .expect("positive raw capacity always admits slot one");

        prop_assert_eq!(ladder.first(), Some(&1));
        let is_dyadic = ladder.windows(2).all(|pair| {
            let (Some(low), Some(high)) = (pair.first(), pair.get(1)) else {
                return false;
            };
            *high == *low * 2
        });
        prop_assert!(is_dyadic);
        prop_assert!(ladder
            .iter()
            .all(|slots| 10 + slots * serialized_query_bytes <= body_cap_bytes));

        let padded = ladder.iter().copied().find(|slots| *slots >= real_count);
        let expected = real_count.checked_next_power_of_two()
            .filter(|slots| *slots <= raw_slot_capacity);
        prop_assert_eq!(padded, expected);
    }
}

#[test]
fn ladder_rejects_size_overflow_and_a_cap_below_one_query() {
    let overflow =
        padded_batch_ladder(usize::MAX, usize::MAX).expect_err("framed query size overflows");
    assert!(matches!(
        overflow,
        raven_client::PaddedBatchError::ArithmeticOverflow { .. }
    ));

    let cap = padded_batch_ladder(100, 109).expect_err("one framed query needs 110 bytes");
    assert!(matches!(
        cap,
        raven_client::PaddedBatchError::BodyCapTooSmall {
            body_cap_bytes: 109,
            minimum_body_bytes: 110
        }
    ));
}

#[test]
fn ladder_rejects_zero_query_size_with_its_own_actionable_error() {
    let error = padded_batch_ladder(0, 100).expect_err("a measured query cannot be empty");
    assert_eq!(error, PaddedBatchError::ZeroQuerySize);
    assert!(
        error.to_string().contains("measure a serialized query"),
        "zero-size error must name the required measurement: {error}"
    );
}

#[test]
fn rust_batch_api_returns_caller_order_mapping_for_shuffled_wire_slots() {
    let fixture = fixture();
    let batch = build_padded_batch_rust(
        &fixture.session,
        &fixture.params,
        fixture.shard_config(),
        &[3, 11, 42],
        1_000_000,
    )
    .expect("padded batch");

    assert_eq!(batch.queries.len(), 4);
    assert_eq!(batch.client_states.len(), 3);
    assert_eq!(batch.response_slots.len(), 3);
    assert!(batch.response_slots.iter().all(|slot| *slot < 4));
}

#[test]
fn seeded_layout_is_reproducible_and_permuted() {
    let fixture = fixture();
    let targets = [3, 11, 42];
    let build = |rng: &mut ScriptedRng| {
        build_padded_batch_rust_with_test_rng(
            &fixture.session,
            &fixture.params,
            fixture.shard_config(),
            &targets,
            1_000_000,
            rng,
            [0x5a; 32],
        )
        .expect("seeded batch")
    };

    let first = build(&mut ScriptedRng::new([1, 0, 0, 0]));
    let second = build(&mut ScriptedRng::new([1, 0, 0, 0]));
    assert_eq!(first.response_slots, [3, 0, 1]);
    assert_eq!(
        first
            .client_states
            .iter()
            .map(|state| state.index)
            .collect::<Vec<_>>(),
        targets
    );
    assert_eq!(first.response_slots, second.response_slots);
    assert_eq!(
        first.wire_targets_for_test(),
        second.wire_targets_for_test()
    );
}

#[test]
fn cover_selection_consumes_the_csprng_instead_of_cycling_targets() {
    let fixture = fixture();
    let build = |cover_draw| {
        build_padded_batch_rust_with_test_rng(
            &fixture.session,
            &fixture.params,
            fixture.shard_config(),
            &[3, 11, 42],
            1_000_000,
            &mut ScriptedRng::new([cover_draw, 0, 0, 0]),
            [0x7c; 32],
        )
        .expect("seeded batch")
    };

    let first_cover = build(0);
    let second_cover = build(1);
    assert_eq!(first_cover.response_slots, second_cover.response_slots);
    assert_ne!(
        first_cover.wire_targets_for_test(),
        second_cover.wire_targets_for_test(),
        "changing only the random cover draw must change the emitted cover query"
    );
}

#[test]
fn builder_returns_typed_empty_cap_and_impossible_padding_errors() {
    let fixture = fixture();
    let build = |targets: &[u64], cap, rng: &mut ScriptedRng| {
        build_padded_batch_rust_with_test_rng(
            &fixture.session,
            &fixture.params,
            fixture.shard_config(),
            targets,
            cap,
            rng,
            [0x33; 32],
        )
    };

    let empty = build(&[], 1_000_000, &mut ScriptedRng::new([]))
        .expect_err("empty batch must fail before padding");
    assert_eq!(empty, PaddedBatchError::EmptyBatch);

    let baseline = build(&[3], 1_000_000, &mut ScriptedRng::new([])).expect("one query");
    let one_query_bytes = 10 + baseline.serialized_query_bytes;
    let cap = build(&[3], one_query_bytes - 1, &mut ScriptedRng::new([]))
        .expect_err("one byte below the minimum must fail");
    assert!(matches!(
        cap,
        PaddedBatchError::BodyCapTooSmall {
            body_cap_bytes,
            minimum_body_bytes
        } if body_cap_bytes + 1 == minimum_body_bytes
    ));

    let three_raw_slots = 10 + 3 * baseline.serialized_query_bytes;
    let impossible = build(&[3, 11, 42], three_raw_slots, &mut ScriptedRng::new([]))
        .expect_err("three raw slots cannot represent the next dyadic step");
    assert_eq!(
        impossible,
        PaddedBatchError::ImpossiblePadding {
            real_count: 3,
            max_slots: 3,
        }
    );
}

#[test]
fn generated_ladder_has_no_fixed_32_slot_ceiling() {
    let fixture = fixture();
    let baseline = build_padded_batch_rust_with_test_rng(
        &fixture.session,
        &fixture.params,
        fixture.shard_config(),
        &[0],
        1_000_000,
        &mut ScriptedRng::new([]),
        [0x44; 32],
    )
    .expect("one query");
    let cap = 10 + 64 * baseline.serialized_query_bytes;
    let targets = (0..33).collect::<Vec<_>>();

    let batch = build_padded_batch_rust_with_test_rng(
        &fixture.session,
        &fixture.params,
        fixture.shard_config(),
        &targets,
        cap,
        &mut ScriptedRng::new([]),
        [0x55; 32],
    )
    .expect("generated 64-slot ladder step");
    assert_eq!(batch.queries.len(), 64);
    assert_eq!(batch.request_bytes, cap);
}

#[test]
fn request_length_is_identical_for_real_counts_in_one_bucket() {
    let fixture = fixture();
    let build = |targets: &[u64]| {
        build_padded_batch_rust_with_test_rng(
            &fixture.session,
            &fixture.params,
            fixture.shard_config(),
            targets,
            1_000_000,
            &mut ScriptedRng::new([]),
            [0x66; 32],
        )
        .expect("batch")
    };

    let three = build(&[3, 11, 42]);
    let four = build(&[3, 11, 42, 51]);
    assert_eq!(three.queries.len(), 4);
    assert_eq!(four.queries.len(), 4);
    assert_eq!(three.serialized_query_bytes, four.serialized_query_bytes);
    assert_eq!(three.request_bytes, four.request_bytes);
    assert_eq!(
        2 + bincode::serialize(&three.queries)
            .expect("serialize three-real batch")
            .len(),
        three.request_bytes
    );
    assert_eq!(
        2 + bincode::serialize(&four.queries)
            .expect("serialize four-real batch")
            .len(),
        four.request_bytes
    );
}

#[test]
fn response_slots_restore_plaintexts_to_caller_order() {
    let fixture = fixture();
    let targets = [42u64, 3, 11];
    let batch = build_padded_batch_rust_with_test_rng(
        &fixture.session,
        &fixture.params,
        fixture.shard_config(),
        &targets,
        1_000_000,
        &mut ScriptedRng::new([1, 0, 0, 0]),
        [0x77; 32],
    )
    .expect("batch");
    let cache =
        ServerInspiringCache::new(fixture.session.crs(), &fixture.encoded).expect("server cache");
    let responses = batch
        .queries
        .iter()
        .map(|query| {
            respond_seeded_inspiring_cached_with_session(
                fixture.session.crs(),
                &fixture.encoded,
                query,
                &cache,
                Some(&fixture.store),
            )
            .expect("respond")
        })
        .collect::<Vec<_>>();

    for (caller_index, target_idx) in targets.iter().copied().enumerate() {
        let wire_slot = *batch
            .response_slots
            .get(caller_index)
            .expect("response slot for caller query");
        let plaintext = extract_response_rust(
            fixture.session.crs(),
            batch
                .client_states
                .get(caller_index)
                .expect("state for caller query"),
            responses.get(wire_slot).expect("response at mapped slot"),
            ENTRY_BYTES,
        )
        .expect("extract");
        let start = usize::try_from(target_idx).expect("target fits") * ENTRY_BYTES;
        assert_eq!(
            plaintext,
            fixture
                .database
                .get(start..start + ENTRY_BYTES)
                .expect("expected record")
        );
    }
}
