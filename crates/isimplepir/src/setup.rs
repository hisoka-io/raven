//! `Setup`: produces `hint = D . A` plus an HKDF-SHA256 + ChaCha20
//! `A`-matrix seed (pure-Rust to keep wasm32 builds AES-NI-free).

use hkdf::Hkdf;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::Sha256;

use crate::error::{IsimplePirError, Result};
use crate::hint::ClientHint;
use crate::params::LweParams;
use crate::version::HintVersion;

/// HKDF info label, versioned.
pub const A_SEED_LABEL: &[u8] = b"raven-isimplepir/A/v1";

pub const SEED_BYTES: usize = 32;

/// Invariant: every element of `db` is in `[0, p)`.
#[derive(Clone, Debug)]
pub struct ServerState {
    pub db: Vec<u32>,
    pub params: LweParams,
    pub a_seed: [u8; SEED_BYTES],
    pub version: HintVersion,
}

#[derive(Clone, Debug)]
pub struct SetupOutput {
    pub hint: ClientHint,
    pub server: ServerState,
}

/// `A` matrix `M x n` u32, row-major. Byte-identical between scalar
/// and parallel paths.
pub fn derive_a_matrix(a_seed: &[u8; SEED_BYTES], params: &LweParams) -> Result<Vec<u32>> {
    #[cfg(feature = "server")]
    {
        derive_a_matrix_parallel(a_seed, params)
    }
    #[cfg(not(feature = "server"))]
    {
        derive_a_matrix_scalar(a_seed, params)
    }
}

fn hkdf_chacha20_key(a_seed: &[u8; SEED_BYTES]) -> Result<[u8; SEED_BYTES]> {
    let hkdf = Hkdf::<Sha256>::new(None, a_seed);
    let mut chacha_key = [0u8; SEED_BYTES];
    hkdf.expand(A_SEED_LABEL, &mut chacha_key)
        .map_err(|e| IsimplePirError::Randomness(format!("HKDF expand failed: {e}")))?;
    Ok(chacha_key)
}

#[allow(dead_code)]
pub(crate) fn derive_a_matrix_scalar(
    a_seed: &[u8; SEED_BYTES],
    params: &LweParams,
) -> Result<Vec<u32>> {
    let chacha_key = hkdf_chacha20_key(a_seed)?;

    let total_u32 = params.m.saturating_mul(params.n);
    let total_bytes = total_u32.saturating_mul(4);
    let mut bytes = vec![0u8; total_bytes];

    let mut rng = ChaCha20Rng::from_seed(chacha_key);
    rng.fill_bytes(&mut bytes);

    let mut a = Vec::with_capacity(total_u32);
    for chunk in bytes.chunks_exact(4) {
        #[allow(clippy::indexing_slicing)]
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        a.push(word);
    }
    Ok(a)
}

/// Each worker seeks to its absolute ChaCha20 word offset via
/// `set_word_pos`. Falls back to scalar below `MIN_CHUNK_WORDS`.
#[cfg(feature = "server")]
pub(crate) fn derive_a_matrix_parallel(
    a_seed: &[u8; SEED_BYTES],
    params: &LweParams,
) -> Result<Vec<u32>> {
    use rayon::prelude::*;

    let chacha_key = hkdf_chacha20_key(a_seed)?;
    let total_u32 = params.m.saturating_mul(params.n);

    const MIN_CHUNK_WORDS: usize = 1 << 13;
    if total_u32 < MIN_CHUNK_WORDS {
        return derive_a_matrix_scalar(a_seed, params);
    }

    let threads = rayon::current_num_threads().max(1);
    // Round up to a ChaCha20 block boundary (16 u32 words).
    let chunk_words = total_u32.div_ceil(threads).next_multiple_of(16);

    let mut a = vec![0u32; total_u32];
    a.par_chunks_mut(chunk_words)
        .enumerate()
        .for_each(|(idx, chunk)| {
            let start_word = (idx * chunk_words) as u128;
            let mut rng = ChaCha20Rng::from_seed(chacha_key);
            rng.set_word_pos(start_word);
            let byte_len = chunk.len().saturating_mul(4);
            let mut bytes = vec![0u8; byte_len];
            rng.fill_bytes(&mut bytes);
            for (slot, src) in chunk.iter_mut().zip(bytes.chunks_exact(4)) {
                #[allow(clippy::indexing_slicing)]
                {
                    *slot = u32::from_le_bytes([src[0], src[1], src[2], src[3]]);
                }
            }
        });
    Ok(a)
}

fn validate_database_shape(database: &[u32], params: &LweParams) -> Result<()> {
    let expected = params.l.saturating_mul(params.m);
    if database.len() != expected {
        return Err(IsimplePirError::DatabaseShape {
            reason: format!(
                "database length {} does not match L * M = {} * {} = {}",
                database.len(),
                params.l,
                params.m,
                expected,
            ),
        });
    }
    for (i, &v) in database.iter().enumerate() {
        if v >= params.p {
            return Err(IsimplePirError::DatabaseShape {
                reason: format!(
                    "database element {i} = {v} exceeds plaintext modulus p = {}",
                    params.p,
                ),
            });
        }
    }
    Ok(())
}

/// Validate + clone into a fresh `Vec<u32>`. Use `setup_owned` to
/// avoid the clone at large cells.
pub fn encode_database(database: &[u32], params: &LweParams) -> Result<Vec<u32>> {
    validate_database_shape(database, params)?;
    Ok(database.to_vec())
}

/// `H = D . A` mod 2^32. Byte-identical scalar / parallel.
pub(crate) fn compute_hint(db: &[u32], a_matrix: &[u32], params: &LweParams) -> Vec<u32> {
    #[cfg(feature = "server")]
    {
        compute_hint_parallel(db, a_matrix, params)
    }
    #[cfg(not(feature = "server"))]
    {
        compute_hint_scalar(db, a_matrix, params)
    }
}

#[allow(dead_code)]
pub(crate) fn compute_hint_scalar(db: &[u32], a_matrix: &[u32], params: &LweParams) -> Vec<u32> {
    let mut h = vec![0u32; params.l.saturating_mul(params.n)];

    for i in 0..params.l {
        let db_row_start = i.saturating_mul(params.m);
        let h_row_start = i.saturating_mul(params.n);
        for k in 0..params.m {
            let db_row_idx = db_row_start.saturating_add(k);
            let Some(&d_ik) = db.get(db_row_idx) else {
                continue;
            };
            if d_ik == 0 {
                continue;
            }
            let a_row_start = k.saturating_mul(params.n);
            for j in 0..params.n {
                let a_idx = a_row_start.saturating_add(j);
                let h_idx = h_row_start.saturating_add(j);
                let Some(&a_kj) = a_matrix.get(a_idx) else {
                    continue;
                };
                let Some(h_slot) = h.get_mut(h_idx) else {
                    continue;
                };
                *h_slot = h_slot.wrapping_add(d_ik.wrapping_mul(a_kj));
            }
        }
    }

    h
}

#[cfg(feature = "server")]
pub(crate) fn compute_hint_parallel(db: &[u32], a_matrix: &[u32], params: &LweParams) -> Vec<u32> {
    use rayon::prelude::*;

    let mut h = vec![0u32; params.l.saturating_mul(params.n)];
    let m = params.m;
    let n = params.n;

    h.par_chunks_mut(n).enumerate().for_each(|(i, h_row)| {
        let db_row_start = i.saturating_mul(m);
        for k in 0..m {
            let db_row_idx = db_row_start.saturating_add(k);
            let Some(&d_ik) = db.get(db_row_idx) else {
                continue;
            };
            if d_ik == 0 {
                continue;
            }
            let a_row_start = k.saturating_mul(n);
            for j in 0..n {
                let a_idx = a_row_start.saturating_add(j);
                let Some(&a_kj) = a_matrix.get(a_idx) else {
                    continue;
                };
                let Some(h_slot) = h_row.get_mut(j) else {
                    continue;
                };
                *h_slot = h_slot.wrapping_add(d_ik.wrapping_mul(a_kj));
            }
        }
    });

    h
}

/// `a_seed = None` draws from `getrandom`; `Some(seed)` is for KATs.
pub fn setup(
    database: &[u32],
    params: LweParams,
    a_seed: Option<[u8; SEED_BYTES]>,
) -> Result<SetupOutput> {
    params.validate()?;
    let db = encode_database(database, &params)?;

    let seed = match a_seed {
        Some(s) => s,
        None => {
            let mut s = [0u8; SEED_BYTES];
            getrandom::fill(&mut s)
                .map_err(|e| IsimplePirError::Randomness(format!("getrandom failed: {e}")))?;
            s
        }
    };

    let a_matrix = derive_a_matrix(&seed, &params)?;
    let hint_data = compute_hint(&db, &a_matrix, &params);

    let hint = ClientHint {
        l: params.l,
        n: params.n,
        data: hint_data,
        version: HintVersion::INITIAL,
    };
    let server = ServerState {
        db,
        params,
        a_seed: seed,
        version: HintVersion::INITIAL,
    };
    Ok(SetupOutput { hint, server })
}

/// Like `setup` but moves `database` into `ServerState.db`. Use
/// when the clone in `encode_database` would double peak memory.
pub fn setup_owned(
    database: Vec<u32>,
    params: LweParams,
    a_seed: Option<[u8; SEED_BYTES]>,
) -> Result<SetupOutput> {
    params.validate()?;
    validate_database_shape(&database, &params)?;

    let seed = match a_seed {
        Some(s) => s,
        None => {
            let mut s = [0u8; SEED_BYTES];
            getrandom::fill(&mut s)
                .map_err(|e| IsimplePirError::Randomness(format!("getrandom failed: {e}")))?;
            s
        }
    };

    let a_matrix = derive_a_matrix(&seed, &params)?;
    let hint_data = compute_hint(&database, &a_matrix, &params);

    let hint = ClientHint {
        l: params.l,
        n: params.n,
        data: hint_data,
        version: HintVersion::INITIAL,
    };
    let server = ServerState {
        db: database,
        params,
        a_seed: seed,
        version: HintVersion::INITIAL,
    };
    Ok(SetupOutput { hint, server })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toy_params() -> LweParams {
        LweParams {
            n: crate::params::LWE_DIM,
            log2_q: crate::params::CIPHERTEXT_MODULUS_LOG2,
            p: 991,
            l: 4,
            m: 4,
            bits_per_element: 9,
        }
    }

    #[test]
    fn hkdf_chacha20_deterministic() {
        let params = toy_params();
        let seed = [7u8; SEED_BYTES];
        let a1 = derive_a_matrix(&seed, &params).expect("derive 1");
        let a2 = derive_a_matrix(&seed, &params).expect("derive 2");
        assert_eq!(a1, a2, "same seed must yield byte-identical A");
        assert_eq!(a1.len(), params.m * params.n);
    }

    #[test]
    fn different_seeds_produce_different_a() {
        let params = toy_params();
        let a1 = derive_a_matrix(&[0u8; 32], &params).expect("derive 1");
        let a2 = derive_a_matrix(&[1u8; 32], &params).expect("derive 2");
        assert_ne!(a1, a2);
    }

    #[test]
    fn setup_produces_consistent_hint() {
        let params = toy_params();
        let db: Vec<u32> = (0..16u32).collect();
        let out = setup(&db, params, Some([42u8; 32])).expect("setup");
        assert_eq!(out.hint.l, 4);
        assert_eq!(out.hint.n, crate::params::LWE_DIM);
        assert_eq!(out.hint.data.len(), 4 * crate::params::LWE_DIM);
        assert_eq!(out.hint.version, HintVersion::INITIAL);
        assert_eq!(out.server.a_seed, [42u8; 32]);
    }

    #[test]
    fn setup_owned_matches_setup_byte_identity() {
        let shapes: &[(usize, usize, u32)] = &[(4, 4, 991), (5, 7, 31), (3, 2, 13)];
        for &(l, m, p) in shapes {
            let params = LweParams {
                n: crate::params::LWE_DIM,
                log2_q: crate::params::CIPHERTEXT_MODULUS_LOG2,
                p,
                l,
                m,
                bits_per_element: 4,
            };
            let db: Vec<u32> = (0..(l * m)).map(|i| (i as u32 * 17 + 3) % p).collect();
            let a_seed = [91u8; 32];

            let reference = setup(&db, params, Some(a_seed)).expect("setup");
            let owned = setup_owned(db.clone(), params, Some(a_seed)).expect("setup_owned");

            assert_eq!(
                reference.hint.data, owned.hint.data,
                "hint.data diverged at shape (l={l}, m={m}, p={p})"
            );
            assert_eq!(reference.hint.l, owned.hint.l);
            assert_eq!(reference.hint.n, owned.hint.n);
            assert_eq!(reference.hint.version, owned.hint.version);
            assert_eq!(
                reference.server.db, owned.server.db,
                "server.db diverged at shape (l={l}, m={m}, p={p})"
            );
            assert_eq!(reference.server.a_seed, owned.server.a_seed);
            assert_eq!(reference.server.params, owned.server.params);
            assert_eq!(reference.server.version, owned.server.version);
        }
    }

    #[test]
    fn setup_owned_rejects_out_of_bound_element() {
        let params = toy_params();
        let mut db: Vec<u32> = (0..16u32).collect();
        db[0] = 10_000;
        let result = setup_owned(db, params, Some([0u8; 32]));
        assert!(matches!(result, Err(IsimplePirError::DatabaseShape { .. })));
    }

    #[test]
    fn setup_rejects_db_with_out_of_bounds_element() {
        let params = toy_params();
        let mut db: Vec<u32> = (0..16u32).collect();
        db[0] = 10_000;
        let result = setup(&db, params, Some([0u8; 32]));
        assert!(matches!(result, Err(IsimplePirError::DatabaseShape { .. })));
    }

    #[test]
    fn compute_hint_matches_naive_matmul() {
        let params = LweParams {
            n: 4,
            log2_q: 32,
            p: 13,
            l: 2,
            m: 3,
            bits_per_element: 4,
        };
        let db = vec![1u32, 2, 3, 4, 5, 6];
        let a = vec![7u32, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18];
        let h = compute_hint(&db, &a, &params);
        // h[0, 0] = 1*7 + 2*11 + 3*15 = 74
        assert_eq!(h[0], 74);
        // h[0, 1] = 1*8 + 2*12 + 3*16 = 80
        assert_eq!(h[1], 80);
        // h[1, 3] = 4*10 + 5*14 + 6*18 = 218
        assert_eq!(h[4 + 3], 218);
    }

    #[cfg(feature = "server")]
    #[test]
    fn derive_a_scalar_vs_parallel_byte_identity() {
        let seeds: &[[u8; 32]] = &[[0u8; 32], [7u8; 32], [0xABu8; 32]];
        let shapes: &[(usize, usize)] =
            &[(4, 4), (4, 1024), (64, 1024), (1024, 1024), (2731, 1024)];
        for seed in seeds {
            for &(m, n) in shapes {
                let params = LweParams {
                    n,
                    log2_q: 32,
                    p: 991,
                    l: 1,
                    m,
                    bits_per_element: 9,
                };
                let scalar = derive_a_matrix_scalar(seed, &params).expect("scalar");
                let parallel = derive_a_matrix_parallel(seed, &params).expect("parallel");
                assert_eq!(
                    scalar, parallel,
                    "derive_a_matrix scalar vs parallel diverge at (m={m}, n={n}) seed={seed:?}"
                );
                assert_eq!(scalar.len(), m * n);
            }
        }
    }

    #[cfg(feature = "server")]
    #[test]
    fn scalar_matches_parallel_byte_identity() {
        use rand_chacha::ChaCha20Rng;
        use rand_core::{RngCore, SeedableRng};

        let shapes: &[(usize, usize, usize, u32)] = &[
            (1, 1, 1, 5),
            (2, 3, 4, 13),
            (3, 2, 4, 13),
            (4, 4, 8, 17),
            (5, 7, 4, 31),
            (4, 4, 1024, 991),
        ];

        for &(l, m, n, p) in shapes {
            let params = LweParams {
                n,
                log2_q: 32,
                p,
                l,
                m,
                bits_per_element: 4,
            };
            let seed: [u8; 32] = {
                let mut s = [0u8; 32];
                s[..8].copy_from_slice(
                    &((l as u64)
                        .wrapping_mul(1_000_003)
                        .wrapping_add((m as u64).wrapping_mul(1_000_033))
                        .wrapping_add((n as u64).wrapping_mul(1_000_037))
                        .wrapping_add(u64::from(p)))
                    .to_le_bytes(),
                );
                s
            };
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut db = vec![0u32; l * m];
            for slot in db.iter_mut() {
                let mut buf = [0u8; 4];
                rng.fill_bytes(&mut buf);
                *slot = u32::from_le_bytes(buf) % p;
            }
            let mut a = vec![0u32; m * n];
            for slot in a.iter_mut() {
                let mut buf = [0u8; 4];
                rng.fill_bytes(&mut buf);
                *slot = u32::from_le_bytes(buf);
            }

            let scalar = compute_hint_scalar(&db, &a, &params);
            let parallel = compute_hint_parallel(&db, &a, &params);
            assert_eq!(
                scalar, parallel,
                "compute_hint scalar vs parallel diverge at (l={l}, m={m}, n={n}, p={p})"
            );
            assert_eq!(scalar.len(), l * n);
        }
    }
}
