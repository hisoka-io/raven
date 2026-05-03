//! Three-oracle aggregator helper for the G5'.D byte-identity tests.
//!
//! Used by `tests/g5_d_subsquid_root_oracle.rs`.

#![allow(dead_code, unreachable_pub)]

/// Source labels for each oracle the aggregator can compare. Returned
/// inside [`OracleDisagreement`] so test-failure messages name the
/// specific source that drifted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OracleSource {
    /// G5'.A on-chain `merkleRoot()` view.
    Chain,
    /// G5'.C upstream PPOI / Railway aggregator root.
    Upstream,
    /// G5'.D subsquid GraphQL root.
    Subsquid,
}

/// Failure variant returned when at least one oracle disagrees with
/// the local IMT-derived root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleDisagreement {
    /// Local IMT root from `Imt::root()` / `LogicalLeafStore::imt_root`.
    pub our_root: [u8; 32],
    /// First oracle that disagreed.
    pub source: OracleSource,
    /// The disagreeing source's reported root.
    pub other_root: [u8; 32],
    /// Optional context label (e.g. "tree=0 milestone=4") for forensics.
    pub context: String,
}

/// Aggregate four candidate roots (our local + chain + upstream +
/// subsquid) and assert byte-identity. Each oracle is optional via
/// [`Option`]; absent oracles short-circuit (e.g. the per-list path
/// has no chain root, so callers pass `None` for chain and only
/// compare upstream + subsquid).
///
/// # Errors
///
/// Returns [`Err(OracleDisagreement)`] on the first mismatch found.
/// Comparison order is deterministic: Chain -> Upstream -> Subsquid,
/// matching reading-order in the test logs so a fail at depth N gives
/// the operator a clear "everything passed up to here, then X drifted"
/// signal.
pub fn assert_three_oracle_byte_identity(
    our_root: [u8; 32],
    chain_root: Option<[u8; 32]>,
    upstream_root: Option<[u8; 32]>,
    subsquid_root: Option<[u8; 32]>,
    context: &str,
) -> Result<(), OracleDisagreement> {
    if let Some(c) = chain_root {
        if c != our_root {
            return Err(OracleDisagreement {
                our_root,
                source: OracleSource::Chain,
                other_root: c,
                context: context.to_owned(),
            });
        }
    }
    if let Some(u) = upstream_root {
        if u != our_root {
            return Err(OracleDisagreement {
                our_root,
                source: OracleSource::Upstream,
                other_root: u,
                context: context.to_owned(),
            });
        }
    }
    if let Some(s) = subsquid_root {
        if s != our_root {
            return Err(OracleDisagreement {
                our_root,
                source: OracleSource::Subsquid,
                other_root: s,
                context: context.to_owned(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_when_all_present_oracles_agree() {
        let r = [0x42u8; 32];
        assert!(
            assert_three_oracle_byte_identity(r, Some(r), Some(r), Some(r), "ctx").is_ok(),
            "all-equal must pass"
        );
    }

    #[test]
    fn passes_when_only_some_oracles_present() {
        let r = [0x42u8; 32];
        assert!(
            assert_three_oracle_byte_identity(r, None, Some(r), None, "ctx").is_ok(),
            "absent oracles short-circuit"
        );
    }

    #[test]
    fn flags_chain_when_chain_disagrees() {
        let r = [0x42u8; 32];
        let bad = [0x43u8; 32];
        let err = assert_three_oracle_byte_identity(r, Some(bad), Some(r), Some(r), "ctx-1")
            .expect_err("chain mismatch");
        assert_eq!(err.source, OracleSource::Chain);
        assert_eq!(err.other_root, bad);
        assert_eq!(err.context, "ctx-1");
    }

    #[test]
    fn flags_upstream_when_upstream_disagrees() {
        let r = [0x42u8; 32];
        let bad = [0x44u8; 32];
        let err = assert_three_oracle_byte_identity(r, Some(r), Some(bad), Some(r), "ctx-2")
            .expect_err("upstream mismatch");
        assert_eq!(err.source, OracleSource::Upstream);
        assert_eq!(err.other_root, bad);
    }

    #[test]
    fn flags_subsquid_when_subsquid_disagrees() {
        let r = [0x42u8; 32];
        let bad = [0x45u8; 32];
        let err = assert_three_oracle_byte_identity(r, Some(r), Some(r), Some(bad), "ctx-3")
            .expect_err("subsquid mismatch");
        assert_eq!(err.source, OracleSource::Subsquid);
        assert_eq!(err.other_root, bad);
    }

    #[test]
    fn deterministic_order_returns_chain_first_when_multiple_disagree() {
        let r = [0x42u8; 32];
        let chain_bad = [0x10u8; 32];
        let upstream_bad = [0x20u8; 32];
        let subsquid_bad = [0x30u8; 32];
        let err = assert_three_oracle_byte_identity(
            r,
            Some(chain_bad),
            Some(upstream_bad),
            Some(subsquid_bad),
            "ctx",
        )
        .expect_err("any mismatch");
        assert_eq!(err.source, OracleSource::Chain);
    }
}
