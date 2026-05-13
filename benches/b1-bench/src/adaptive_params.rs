//! Port of Google's `params_for_scenario_medium_payload` (see
//! `private-membership/research/InsPIRe/src/params.rs:109-167`).

use raven_inspire::params::{InspireParams, SecurityLevel};

#[derive(Debug, Clone, Copy)]
pub struct AdaptiveInputs {
    pub input_num_items: usize,
    pub input_item_size_bits: usize,
    /// Gamma triple. `[64, 1024, 64]` for 256 B records (paper §7.1).
    pub gammas: [usize; 3],
    /// Power of two; trailing zeros skew `(nu_1, nu_2)` toward
    /// `nu_1`. `1` matches Google.
    pub performance_factor: usize,
}

#[derive(Debug, Clone)]
pub struct AdaptiveDerivation {
    pub poly_len: usize,
    pub p: u64,
    pub nu_1: usize,
    pub nu_2: usize,
    pub q2_bits: usize,
    pub t_exp_left: usize,
    pub sigma_x: f64,
    pub z: u64,
    pub db_rows: usize,
    pub db_cols: usize,
    pub working_num_large_items: f64,
    pub num_tiles: f64,
    pub num_tiles_log2: usize,
    pub term_0_variance: f64,
    pub term_1_variance: f64,
    pub term_2_variance: f64,
    pub max_variance: f64,
    pub required_q_log2: f64,
    pub custom_moduli: Vec<u64>,
    pub custom_q_log2: f64,
}

fn get_variance(
    dim: f64,
    p: f64,
    sigma_x: f64,
    ell_ks: f64,
    z: f64,
    poly_len: f64,
    gamma: f64,
) -> f64 {
    (dim * p.powi(2) * sigma_x.powi(2)
        + ell_ks * gamma * poly_len * z.powi(2) * sigma_x.powi(2) / 4.0)
        .log2()
        / 2.0
}

pub fn derive_medium_payload(inputs: &AdaptiveInputs) -> AdaptiveDerivation {
    let gamma_0 = inputs.gammas[0];
    let gamma_1 = inputs.gammas[1];
    let gamma_2 = inputs.gammas[2];

    let poly_len_log2: usize = 11;
    let poly_len: usize = 1 << poly_len_log2;

    let log_p: usize = 16;
    assert!(log_p <= 16);
    let p: u64 = 1u64 << log_p;

    let q2_bits: usize = 28;
    let t_exp_left: usize = 3;

    let working_num_large_items = (inputs.input_num_items as f64
        * inputs.input_item_size_bits as f64
        / (log_p * gamma_0) as f64)
        .ceil();

    let num_tiles = working_num_large_items / (poly_len * poly_len) as f64;
    let num_tiles_log2 = num_tiles.ceil().log2().ceil() as usize;

    let log_factor = inputs.performance_factor.trailing_zeros() as usize;
    let (nu_1, nu_2) = if num_tiles_log2 % 2 == 0 {
        (
            (num_tiles_log2 / 2).saturating_add(log_factor),
            (num_tiles_log2 / 2).saturating_sub(log_factor),
        )
    } else {
        (
            num_tiles_log2.div_ceil(2).saturating_add(log_factor),
            ((num_tiles_log2.saturating_sub(1)) / 2).saturating_sub(log_factor),
        )
    };

    let db_rows = nu_1;
    let db_cols = 1usize << (nu_2 + gamma_0.trailing_zeros() as usize);

    let size_over_t = 1usize << (nu_1 + poly_len_log2);
    let t_val = 1usize << (nu_2 + poly_len_log2);
    let sigma_x: f64 = 6.4;
    let z: u64 = 1 << 19;

    let term_0_variance = get_variance(
        size_over_t as f64,
        p as f64,
        sigma_x,
        t_exp_left as f64,
        z as f64,
        poly_len as f64,
        gamma_0 as f64,
    );
    let term_1_variance = get_variance(
        t_val as f64,
        p as f64,
        sigma_x,
        t_exp_left as f64,
        z as f64,
        poly_len as f64,
        gamma_1 as f64,
    );
    let term_2_variance = get_variance(
        t_val as f64,
        p as f64,
        sigma_x,
        t_exp_left as f64,
        z as f64,
        poly_len as f64,
        gamma_2 as f64,
    );

    let max_variance = term_0_variance.max(term_1_variance).max(term_2_variance);

    let required_q_log2 =
        (2.0 * 2.0 * p as f64).log2() + (2.0 * 41.0 * 2.0f64.ln()).sqrt().log2() + max_variance;

    let custom_moduli: Vec<u64> = vec![67_043_329, 132_120_577];
    let custom_q: f64 = custom_moduli.iter().map(|&m| m as f64).product();
    let custom_q_log2 = custom_q.log2();

    AdaptiveDerivation {
        poly_len,
        p,
        nu_1,
        nu_2,
        q2_bits,
        t_exp_left,
        sigma_x,
        z,
        db_rows,
        db_cols,
        working_num_large_items,
        num_tiles,
        num_tiles_log2,
        term_0_variance,
        term_1_variance,
        term_2_variance,
        max_variance,
        required_q_log2,
        custom_moduli,
        custom_q_log2,
    }
}

pub fn to_inspire_params(d: &AdaptiveDerivation) -> InspireParams {
    let q: u64 = d.custom_moduli.iter().product();
    InspireParams {
        ring_dim: d.poly_len,
        q,
        crt_moduli: d.custom_moduli.clone(),
        p: d.p,
        sigma: d.sigma_x,
        gadget_base: d.z,
        gadget_len: d.t_exp_left,
        security_level: SecurityLevel::Bits128,
    }
}

pub fn fmt_derivation(inputs: &AdaptiveInputs, d: &AdaptiveDerivation) -> String {
    let inspire = to_inspire_params(d);
    format!(
        concat!(
            "=== adaptive-params derivation ===\n",
            "input_num_items: {num_items} (log2 = {num_items_log2})\n",
            "input_item_size_bits: {item_bits} (log2 = {item_bits_log2})\n",
            "gammas: [{g0}, {g1}, {g2}]\n",
            "performance_factor: {pf}\n",
            "poly_len: {poly_len} (log2 = {poly_len_log2})\n",
            "p: {p}\n",
            "q2_bits: {q2_bits}\n",
            "t_exp_left: {t_exp_left}\n",
            "z: {z}\n",
            "sigma_x: {sigma_x}\n",
            "working_num_large_items: {working_large}\n",
            "num_tiles: {num_tiles} (log2 = {num_tiles_log2})\n",
            "(nu_1, nu_2): ({nu_1}, {nu_2})\n",
            "db_rows: {db_rows}\n",
            "db_cols: {db_cols}\n",
            "term_0_variance: {t0:.4}\n",
            "term_1_variance: {t1:.4}\n",
            "term_2_variance: {t2:.4}\n",
            "max_variance: {max_var:.4}\n",
            "required_q_log2: {req_q:.4}\n",
            "custom_moduli: {moduli:?}\n",
            "custom_q_log2: {custom_q:.4}\n",
            "InspireParams: ring_dim={ring_dim}, q={q} (log2={q_log2:.4}), ",
            "crt_moduli={crt_moduli:?}, p={bridge_p}, sigma={bridge_sigma}, ",
            "gadget_base={gadget_base}, gadget_len={gadget_len}, security={sec_level:?}\n",
        ),
        num_items = inputs.input_num_items,
        num_items_log2 = (inputs.input_num_items as f64).log2() as u32,
        item_bits = inputs.input_item_size_bits,
        item_bits_log2 = (inputs.input_item_size_bits as f64).log2() as u32,
        g0 = inputs.gammas[0],
        g1 = inputs.gammas[1],
        g2 = inputs.gammas[2],
        pf = inputs.performance_factor,
        poly_len = d.poly_len,
        poly_len_log2 = (d.poly_len as f64).log2() as u32,
        p = d.p,
        q2_bits = d.q2_bits,
        t_exp_left = d.t_exp_left,
        z = d.z,
        sigma_x = d.sigma_x,
        working_large = d.working_num_large_items,
        num_tiles = d.num_tiles,
        num_tiles_log2 = d.num_tiles_log2,
        nu_1 = d.nu_1,
        nu_2 = d.nu_2,
        db_rows = d.db_rows,
        db_cols = d.db_cols,
        t0 = d.term_0_variance,
        t1 = d.term_1_variance,
        t2 = d.term_2_variance,
        max_var = d.max_variance,
        req_q = d.required_q_log2,
        moduli = d.custom_moduli,
        custom_q = d.custom_q_log2,
        ring_dim = inspire.ring_dim,
        q = inspire.q,
        q_log2 = (inspire.q as f64).log2(),
        crt_moduli = inspire.crt_moduli,
        bridge_p = inspire.p,
        bridge_sigma = inspire.sigma,
        gadget_base = inspire.gadget_base,
        gadget_len = inspire.gadget_len,
        sec_level = inspire.security_level,
    )
}
