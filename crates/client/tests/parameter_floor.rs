//! Each parameter floor refuses the one field it bounds and admits both shipped presets.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use raven_client::{
    build_seeded_query_rust, check_parameter_floor, ParameterFloorError, MAX_GADGET_LEN, MAX_Q,
    SHIPPED_CRT_MODULI, SHIPPED_SIGMA,
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
fn both_shipped_presets_carry_the_one_accepted_limb_set() {
    for preset in [
        InspireParams::secure_128_d2048(),
        InspireParams::secure_128_d4096(),
    ] {
        assert_eq!(preset.crt_moduli, SHIPPED_CRT_MODULI);
        assert_eq!(preset.q, MAX_Q);
    }
}

/// A valid set under a narrower modulus is still not the set the client was shipped with.
#[test]
fn a_narrower_two_prime_modulus_is_refused() {
    let q: u64 = DEFAULT_CRT_MODULI.iter().product();
    let params = InspireParams {
        q,
        crt_moduli: DEFAULT_CRT_MODULI.to_vec(),
        ..shipped()
    };
    assert!(q < MAX_Q);
    params
        .validate()
        .expect("the reference pair is a valid set");
    assert_eq!(
        check_parameter_floor(&params),
        Err(ParameterFloorError::ModulusLimbs {
            q,
            crt_moduli: DEFAULT_CRT_MODULI.to_vec(),
        })
    );
}

/// Two 61-bit NTT primes for ring dimension 2,048. Their product is near 2^122 and wraps a
/// `u64` to `WRAPPED_PRODUCT`, a 63-bit number.
const CRAFTED_LIMBS: [u64; 2] = [2_305_843_009_213_616_129, 2_305_843_009_213_554_689];
const WRAPPED_PRODUCT: u64 = 4_611_686_029_265_252_353;

/// The `q` field can state the shipped modulus over limbs that multiply to another one, and
/// the limbs are what a key is built under.
#[test]
fn crafted_limbs_behind_the_shipped_q_are_refused() {
    assert_eq!(
        CRAFTED_LIMBS[0].wrapping_mul(CRAFTED_LIMBS[1]),
        WRAPPED_PRODUCT
    );
    assert!(u128::from(CRAFTED_LIMBS[0]) * u128::from(CRAFTED_LIMBS[1]) > 1 << 121);
    for limbs in [
        CRAFTED_LIMBS.to_vec(),
        DEFAULT_CRT_MODULI.to_vec(),
        vec![MAX_Q, MAX_Q],
        vec![MAX_Q, 1],
        vec![1, MAX_Q],
        vec![MAX_Q - 1],
        Vec::new(),
    ] {
        let params = InspireParams {
            crt_moduli: limbs.clone(),
            ..shipped()
        };
        assert_eq!(params.q, MAX_Q, "precondition: q alone passes its bound");
        assert_eq!(
            check_parameter_floor(&params),
            Err(ParameterFloorError::ModulusLimbs {
                q: MAX_Q,
                crt_moduli: limbs.clone(),
            }),
            "limbs {limbs:?}"
        );
    }
}

/// The same pair with `q` set to what its product wraps to: `validate` refuses the overflow
/// and the floor refuses the modulus, each on its own.
#[test]
fn crafted_limbs_with_their_wrapped_product_are_refused_twice() {
    let params = InspireParams {
        q: WRAPPED_PRODUCT,
        crt_moduli: CRAFTED_LIMBS.to_vec(),
        ..shipped()
    };
    let invalid = params.validate().expect_err("the product overflows");
    assert!(invalid.contains("overflows u64"), "{invalid}");
    assert_eq!(
        check_parameter_floor(&params),
        Err(ParameterFloorError::Modulus { q: WRAPPED_PRODUCT })
    );
}

#[test]
fn a_narrower_single_prime_is_refused() {
    let q = DEFAULT_CRT_MODULI[0];
    let params = InspireParams {
        q,
        crt_moduli: vec![q],
        ..shipped()
    };
    assert_eq!(
        check_parameter_floor(&params),
        Err(ParameterFloorError::ModulusLimbs {
            q,
            crt_moduli: vec![q],
        })
    );
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
        approximate_packing_gadget: false,
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
            approximate_packing_gadget: false,
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

#[test]
fn the_approximate_packing_gadget_is_refused() {
    let approximate = InspireParams {
        approximate_packing_gadget: true,
        ..shipped()
    };
    assert!(
        approximate.validate().is_ok(),
        "fixture: the set must be usable, so the floor is what refuses it"
    );
    assert_eq!(
        check_parameter_floor(&approximate),
        Err(ParameterFloorError::ApproximatePackingGadget)
    );
    let wider_ring = InspireParams {
        approximate_packing_gadget: true,
        ..InspireParams::secure_128_d4096()
    };
    assert_eq!(
        check_parameter_floor(&wider_ring),
        Err(ParameterFloorError::ApproximatePackingGadget)
    );
}

/// A served set with the option on reaches no key build: the session entry point refuses the
/// CRS before it derives anything.
#[test]
fn a_session_is_not_built_under_the_approximate_packing_gadget() {
    let params = InspireParams {
        approximate_packing_gadget: true,
        ..shipped()
    };
    let mut sampler = GaussianSampler::new(params.sigma);
    let (crs, encoded, secret_key) =
        setup(&params, &vec![0u8; params.ring_dim * 32], 32, &mut sampler).expect("setup");
    let session = ClientSession::new(crs, secret_key, &mut sampler).expect("session");
    let refusal =
        build_seeded_query_rust(&session, &params, &encoded.config, 0).expect_err("refused");
    assert!(
        refusal.contains("the approximate packing gadget is on"),
        "{refusal}"
    );
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
