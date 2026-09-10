//! `register_client_session`'s drift guard, driven on the shipped `#[wasm_bindgen]`
//! export rather than a mirror.
//!
//! The comparison authority is the session's retained CRS, not the params field
//! populated from the current bundle. This makes the same guard live on cold build
//! and warm residue restore without changing the residue format.
//!
//! WHY THE ERR CASES ARE wasm32-ONLY. The arm's sole effect is `JsValue::from_str`,
//! and on a non-wasm target that call panics inside an `extern` shim that cannot
//! unwind (`wasm-bindgen-0.2.123/src/lib.rs:1311`, "function not implemented on
//! non-wasm32 targets"), aborting the process with SIGABRT. `catch_unwind` cannot
//! observe it. So a native test cannot assert `Err` here - it can only assert that
//! the guard does NOT fire, which is the accept case below. `tests/panic_safety.rs:1-3`
//! records the same constraint for the other wrappers.
//!
//! The four comparisons are a disjunction over `ring_dim`, `q`, `p` and `sigma`, so
//! each gets its own case: a fixture drifting one field leaves the other three
//! comparisons unexecuted, and a mutation deleting any one of them would survive.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

/// d=256 everywhere, matching every other test in this crate: the guard compares
/// decoded fields and never touches the ring, so a larger ring buys no coverage and
/// costs an O(d^3) packing-key generation per case.
#[cfg(target_arch = "wasm32")]
mod wasm_only {
    use raven_client::{
        build_client_session, build_instance_params_blob, deserialize_client_session,
        register_client_session, serialize_client_session, ClientSessionHandle,
    };
    use raven_inspire::math::GaussianSampler;
    use raven_inspire::params::{InspireParams, SecurityLevel, ShardConfig};
    use raven_inspire::setup as inspire_setup;
    use wasm_bindgen_test::wasm_bindgen_test;

    const ENTRY_BYTES: usize = 32;

    fn base_params() -> InspireParams {
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

    fn build_db(params: &InspireParams) -> Vec<u8> {
        (0..(params.ring_dim * ENTRY_BYTES))
            .map(|i| u8::try_from(i % 251).expect("i % 251 < 256"))
            .collect()
    }

    /// A bundle for arbitrary params, through the shipped blob builder.
    ///
    /// `expect` on the blob is the guard the task's risk note asks for: a bundle that
    /// fails to construct would make the drift assertion below pass for the wrong
    /// reason, so construction failure must surface as a distinct panic.
    fn bundle_for(params: &InspireParams) -> Vec<u8> {
        let shard = ShardConfig::for_ring_dim(
            params.ring_dim,
            ENTRY_BYTES,
            u64::try_from(params.ring_dim).expect("ring_dim fits u64"),
        )
        .expect("drift fixture: shard config must be constructible for these params");
        let params_bincode = bincode::serialize(params).expect("serialize params");
        let shard_bincode = bincode::serialize(&shard).expect("serialize shard config");
        build_instance_params_blob(&params_bincode, &shard_bincode)
            .expect("drift fixture: params blob must build before the guard is exercised")
    }

    fn session_at_base_params() -> ClientSessionHandle {
        let params = base_params();
        let database = build_db(&params);
        let mut sampler = GaussianSampler::new(params.sigma);
        let (crs, _encoded_db, _sk) =
            inspire_setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("inspire_setup");
        let bundle = bundle_for(&params);
        let crs_bincode = crs.to_versioned_bytes().expect("versioned crs");
        build_client_session(&bundle, &crs_bincode).expect("session")
    }

    /// Drives the guard with a bundle differing from the session's in exactly the one
    /// field `mutate` touches, and asserts the drift arm fired.
    fn assert_drift_rejected(field: &str, mutate: impl FnOnce(&mut InspireParams)) {
        let mut session = session_at_base_params();
        let mut drifted = base_params();
        mutate(&mut drifted);
        assert_ne!(
            bincode::serialize(&drifted).expect("serialize drifted"),
            bincode::serialize(&base_params()).expect("serialize base"),
            "fixture invariant: the {field} mutation must actually change the params"
        );

        // `let ... else`, not `expect_err`: expect_err takes a plain &str and would print
        // the `{field}` placeholder literally on the failure that matters most here.
        let Err(err) = register_client_session(&mut session, &bundle_for(&drifted)) else {
            panic!("a bundle drifting {field} was accepted; the drift guard did not fire");
        };
        let message = err.as_string().unwrap_or_default();
        assert!(
            message.contains("parameters drifted"),
            "drifting {field} produced the wrong error; the guard must be what rejected \
             it, not an incidental decode failure. got: {message}"
        );
    }

    #[wasm_bindgen_test]
    fn drift_in_ring_dim_is_rejected() {
        assert_drift_rejected("ring_dim", |p| p.ring_dim = 512);
    }

    /// `q - 2*ring_dim` keeps `q % (2*ring_dim) == 1` and stays under
    /// `gadget_base^gadget_len`, so the drifted params still pass `validate()` and the
    /// guard is what rejects them.
    #[wasm_bindgen_test]
    fn drift_in_q_is_rejected() {
        assert_drift_rejected("q", |p| {
            p.q = 1_152_921_504_606_830_081;
            p.crt_moduli = vec![1_152_921_504_606_830_081];
        });
    }

    #[wasm_bindgen_test]
    fn drift_in_p_is_rejected() {
        assert_drift_rejected("p", |p| p.p = 65_539);
    }

    /// `sigma` drives secret-key and query-noise sampling (`src/lib.rs:291`, `:357`),
    /// so a silently different width is a security-parameter change, not a rounding
    /// difference.
    #[wasm_bindgen_test]
    fn drift_in_sigma_is_rejected() {
        assert_drift_rejected("sigma", |p| p.sigma = 6.5);
    }

    #[wasm_bindgen_test]
    fn registration_compares_the_bundle_to_the_session_crs() {
        let params = base_params();
        let bundle = bundle_for(&params);
        let mut crs_params = params;
        crs_params.p = 65_539;
        let database = build_db(&crs_params);
        let mut sampler = GaussianSampler::new(crs_params.sigma);
        let (crs, _, _) =
            inspire_setup(&crs_params, &database, ENTRY_BYTES, &mut sampler).expect("drifted CRS");
        let crs_bincode = crs.to_versioned_bytes().expect("versioned CRS");
        let mut session = build_client_session(&bundle, &crs_bincode).expect("session");

        let Err(error) = register_client_session(&mut session, &bundle) else {
            panic!("bundle/session-CRS drift was accepted");
        };
        assert!(error
            .as_string()
            .unwrap_or_default()
            .contains("parameters drifted"));
    }

    #[wasm_bindgen_test]
    fn warm_restore_compares_the_residue_to_live_params() {
        let params = base_params();
        let database = build_db(&params);
        let mut sampler = GaussianSampler::new(params.sigma);
        let (crs, _, _) =
            inspire_setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("base CRS");
        let base_bundle = bundle_for(&params);
        let base_crs_bytes = crs.to_versioned_bytes().expect("base CRS bytes");
        let session = build_client_session(&base_bundle, &base_crs_bytes).expect("session");
        let residue = serialize_client_session(&session).expect("residue");

        let mut live_params = params;
        live_params.p = 65_539;
        let live_bundle = bundle_for(&live_params);
        let mut live_crs = crs;
        live_crs.params = live_params;
        let live_crs_bytes = live_crs.to_versioned_bytes().expect("live CRS bytes");

        let Err(error) = deserialize_client_session(&live_bundle, &live_crs_bytes, &residue) else {
            panic!("drifted warm residue was accepted");
        };
        assert!(error
            .as_string()
            .unwrap_or_default()
            .contains("parameters drifted"));
    }

    #[wasm_bindgen_test]
    fn warm_restore_compares_the_residue_to_the_live_crs() {
        let params = base_params();
        let database = build_db(&params);
        let mut sampler = GaussianSampler::new(params.sigma);
        let (crs, _, _) =
            inspire_setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("base CRS");
        let bundle = bundle_for(&params);
        let crs_bytes = crs.to_versioned_bytes().expect("base CRS bytes");
        let session = build_client_session(&bundle, &crs_bytes).expect("session");
        let residue = serialize_client_session(&session).expect("residue");

        let mut live_crs = crs;
        live_crs.params.p = 65_539;
        let live_crs_bytes = live_crs.to_versioned_bytes().expect("live CRS bytes");

        let Err(error) = deserialize_client_session(&bundle, &live_crs_bytes, &residue) else {
            panic!("live-CRS drifted warm residue was accepted");
        };
        assert!(error.as_string().unwrap_or_default().contains("live CRS"));
    }

    /// The no-false-positive half: the bundle the session was built from must be
    /// accepted, or the shipped SDK cold path would fail on every load.
    #[wasm_bindgen_test]
    fn the_sessions_own_bundle_is_accepted() {
        let params = base_params();
        let database = build_db(&params);
        let mut sampler = GaussianSampler::new(params.sigma);
        let (crs, _encoded_db, _sk) =
            inspire_setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("inspire_setup");
        let bundle = bundle_for(&params);
        let crs_bincode = crs.to_versioned_bytes().expect("versioned crs");
        let mut session = build_client_session(&bundle, &crs_bincode).expect("session");

        assert!(
            register_client_session(&mut session, &bundle).is_ok(),
            "the session's own bundle must register; this is the argument both SDK call \
             sites pass"
        );
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use raven_client::{build_client_session, build_instance_params_blob, register_client_session};
    use raven_inspire::math::GaussianSampler;
    use raven_inspire::params::{InspireParams, SecurityLevel, ShardConfig};
    use raven_inspire::setup as inspire_setup;

    const ENTRY_BYTES: usize = 32;

    fn base_params() -> InspireParams {
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

    /// The only half of the guard a native target can observe. An `Err` here would not
    /// fail this assertion - it would abort the process inside `JsValue::from_str` (see
    /// the module header) - so this case kills condition-inversion mutations by SIGABRT
    /// rather than by assertion, and the accept-path assertion below covers the rest.
    #[test]
    fn the_sessions_own_bundle_is_accepted() {
        let params = base_params();
        let database: Vec<u8> = (0..(params.ring_dim * ENTRY_BYTES))
            .map(|i| u8::try_from(i % 251).expect("i % 251 < 256"))
            .collect();
        let mut sampler = GaussianSampler::new(params.sigma);
        let (crs, encoded_db, _sk) =
            inspire_setup(&params, &database, ENTRY_BYTES, &mut sampler).expect("inspire_setup");
        let params_bincode = bincode::serialize(&params).expect("serialize params");
        let shard_bincode = bincode::serialize(&encoded_db.config).expect("serialize shard");
        let bundle =
            build_instance_params_blob(&params_bincode, &shard_bincode).expect("params blob");
        let crs_bincode = crs.to_versioned_bytes().expect("versioned crs");
        let mut session = build_client_session(&bundle, &crs_bincode).expect("session");

        assert!(
            register_client_session(&mut session, &bundle).is_ok(),
            "the session's own bundle must register; this is the argument both SDK call \
             sites pass"
        );
    }

    /// Pins why the drift fixtures above are hand-built rather than the two shipped
    /// presets: `secure_128_d2048` and `secure_128_d4096` differ in `ring_dim` ALONE,
    /// so a d2048-vs-d4096 drift test exercises one of the guard's four comparisons and
    /// stays green while the other three are deleted. If a future edit makes the presets
    /// differ in `q`, `p` or `sigma`, this reddens and the preset pair becomes usable.
    #[test]
    fn the_shipped_preset_pair_differs_only_in_ring_dim() {
        let d2048 = InspireParams::secure_128_d2048();
        let d4096 = InspireParams::secure_128_d4096();
        assert!(d2048.validate().is_ok(), "d2048 preset must validate");
        assert!(d4096.validate().is_ok(), "d4096 preset must validate");

        assert_ne!(
            d2048.ring_dim, d4096.ring_dim,
            "the presets must differ somewhere"
        );
        assert_eq!(
            d2048.q, d4096.q,
            "preset q drifted; the q case can now use presets"
        );
        assert_eq!(
            d2048.p, d4096.p,
            "preset p drifted; the p case can now use presets"
        );
        assert_eq!(
            d2048.sigma.to_bits(),
            d4096.sigma.to_bits(),
            "preset sigma drifted; the sigma case can now use presets"
        );
    }

    /// The drifted fixtures must be rejected by the GUARD, not by `validate()` inside
    /// `decode_validated_params` one line earlier. Asserted here because the wasm cases
    /// that consume them do not run in the native lane.
    #[test]
    fn every_drift_fixture_is_itself_valid() {
        let mut q_drift = base_params();
        q_drift.q = 1_152_921_504_606_830_081;
        q_drift.crt_moduli = vec![1_152_921_504_606_830_081];
        let mut p_drift = base_params();
        p_drift.p = 65_539;
        let mut sigma_drift = base_params();
        sigma_drift.sigma = 6.5;
        let mut ring_drift = base_params();
        ring_drift.ring_dim = 512;

        for (label, params) in [
            ("ring_dim", ring_drift),
            ("q", q_drift),
            ("p", p_drift),
            ("sigma", sigma_drift),
        ] {
            assert!(
                params.validate().is_ok(),
                "the {label} drift fixture must pass validate(), or the guard is not what \
                 rejects it: {:?}",
                params.validate()
            );
            assert!(
                ShardConfig::for_ring_dim(
                    params.ring_dim,
                    ENTRY_BYTES,
                    u64::try_from(params.ring_dim).expect("ring_dim fits u64"),
                )
                .is_ok(),
                "the {label} drift fixture must have a constructible shard config"
            );
        }
    }
}
