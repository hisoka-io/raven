#[cfg(feature = "inspire")]
pub mod adaptive_params;

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert_eq!(1 + 1, 2);
    }

    #[cfg(feature = "inspire")]
    #[test]
    fn adaptive_params_medium_payload_2_20_x_256b() {
        let d = crate::adaptive_params::derive_medium_payload(
            &crate::adaptive_params::AdaptiveInputs {
                input_num_items: 1 << 20,
                input_item_size_bits: 256 * 8,
                gammas: [64, 1024, 64],
                performance_factor: 1,
            },
        );
        assert_eq!(d.poly_len, 2048);
        assert_eq!(d.p, 65536);
        assert_eq!(d.t_exp_left, 3);
        assert_eq!(d.z, 1 << 19);
        assert_eq!(d.custom_moduli, vec![67_043_329, 132_120_577]);
        assert!(d.custom_q_log2 >= d.required_q_log2);
    }
}
