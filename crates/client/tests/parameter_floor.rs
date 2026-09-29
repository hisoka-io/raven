//! Each parameter floor refuses the one field it bounds and admits both shipped presets.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use raven_client::{
    build_seeded_query_rust, check_parameter_floor, ParameterFloorError, MAX_GADGET_LEN, MAX_Q,
    SHIPPED_SIGMA,
};
use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, DEFAULT_CRT_MODULI};
use raven_inspire::{setup, ClientSession};

fn shipped() -> InspireParams {
    InspireParams::secure_128_d2048()
}

#[test]
fn both_shipped_presets_pass() {
    check_parameter_floor(&InspireParams::secure_128_d2048()).expect("d2048");
    check_parameter_floor(&InspireParams::secure_128_d4096()).expect("d4096");
}

#[test]
fn a_narrower_two_prime_modulus_passes() {
    let params = InspireParams {
        q: DEFAULT_CRT_MODULI.iter().product(),
        crt_moduli: DEFAULT_CRT_MODULI.to_vec(),
        ..shipped()
    };
    check_parameter_floor(&params).expect("q below the shipped modulus");
}

#[test]
fn a_ring_outside_the_shipped_range_is_refused() {
    for ring_dim in [256, 512, 1024, 2047, 4097, 8192, usize::MAX] {
        let params = InspireParams {
            ring_dim,
            ..shipped()
        };
        assert_eq!(
            check_parameter_floor(&params),
            Err(ParameterFloorError::RingDim { ring_dim }),
            "ring_dim {ring_dim}"
        );
    }
}

#[test]
fn a_wider_modulus_is_refused() {
    let q = MAX_Q + 1;
    let params = InspireParams { q, ..shipped() };
    assert_eq!(
        check_parameter_floor(&params),
        Err(ParameterFloorError::Modulus { q })
    );
}

#[test]
fn any_width_but_the_shipped_sigma_is_refused() {
    for sigma in [3.19, 3.2, 6.39, 6.41, 12.8, 1.0e9, f64::INFINITY, f64::NAN] {
        let params = InspireParams { sigma, ..shipped() };
        assert!(
            matches!(
                check_parameter_floor(&params),
                Err(ParameterFloorError::Sigma { .. })
            ),
            "sigma {sigma}"
        );
    }
    assert_eq!(SHIPPED_SIGMA.to_bits(), shipped().sigma.to_bits());
}

#[test]
fn a_gadget_wider_than_its_base_needs_is_refused() {
    let wide_packing = InspireParams {
        packing_gadget_len: 4,
        ..shipped()
    };
    assert_eq!(
        check_parameter_floor(&wide_packing),
        Err(ParameterFloorError::GadgetWidth {
            role: "packing",
            len: 4,
            base: 1 << 20,
            covering: 3,
        })
    );
    let wide_query = InspireParams {
        query_gadget_len: usize::MAX,
        ..shipped()
    };
    assert!(matches!(
        check_parameter_floor(&wide_query),
        Err(ParameterFloorError::GadgetWidth { role: "query", .. })
    ));
    let degenerate_base = InspireParams {
        gadget_base: 1,
        ..shipped()
    };
    assert!(matches!(
        check_parameter_floor(&degenerate_base),
        Err(ParameterFloorError::GadgetWidth { covering: 0, .. })
    ));
}

/// Keys and queries grow with the digit count, so a smaller base buys no more digits than the
/// shipped preset has, even where every digit is needed to cover `q`.
#[test]
fn a_gadget_with_more_digits_than_the_shipped_preset_is_refused() {
    let preset = shipped();
    assert_eq!(
        (
            preset.gadget_base,
            preset.query_gadget_len,
            preset.packing_gadget_len
        ),
        (1 << 20, MAX_GADGET_LEN, MAX_GADGET_LEN)
    );
    for (gadget_base, len) in [(2, 60), ((1 << 20) - 1, 4)] {
        let params = InspireParams {
            gadget_base,
            query_gadget_len: len,
            packing_gadget_len: len,
            ..shipped()
        };
        params
            .validate()
            .expect("base covers q in exactly len digits");
        assert_eq!(
            check_parameter_floor(&params),
            Err(ParameterFloorError::GadgetDigits { role: "query", len }),
            "base {gadget_base}"
        );
    }
}

/// Only the unit-test harness lifts the floors; this crate's own integration tests link the same
/// floored library a dependent does.
#[test]
fn an_integration_build_enforces_the_floors() {
    let params = InspireParams {
        ring_dim: 256,
        ..shipped()
    };
    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded, secret_key) =
        setup(&params, &vec![0u8; params.ring_dim * 32], 32, &mut sampler).expect("setup");
    let session = ClientSession::new(crs, secret_key, &mut sampler).expect("session");
    let refusal =
        build_seeded_query_rust(&session, &params, &encoded.config, 0).expect_err("refused");
    assert!(
        refusal.contains("ring_dim 256 is outside [2048, 4096]"),
        "{refusal}"
    );
}
