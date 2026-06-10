//! Server-runtime identity types shared by the server and storage crates.

use serde::{Deserialize, Serialize};

/// Identifier for a PIR engine instance. Operator-defined; immutable after registration.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InstanceId(
    /// Operator-defined string. The engine uses string identity for lookup;
    /// callers must keep the value stable across restarts.
    pub String,
);

impl InstanceId {
    /// Construct from any string.
    pub fn new<S: Into<String>>(s: S) -> Self {
        Self(s.into())
    }

    /// Underlying string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for InstanceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Monotonic snapshot version. Bumped every time an instance's server state is
/// swapped (post re-preprocess, post update batch).
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct Epoch(
    /// Monotonic counter; saturates at `u64::MAX`.
    pub u64,
);

impl Epoch {
    /// Sentinel value for a fresh instance before any state swap.
    pub const ZERO: Self = Self(0);

    /// Next epoch (saturating at `u64::MAX`).
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl std::fmt::Display for Epoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn epoch_next_is_monotonic() {
        assert_eq!(Epoch::ZERO.next(), Epoch(1));
        assert_eq!(Epoch::ZERO.next().next(), Epoch(2));
    }

    #[test]
    fn epoch_next_saturates() {
        assert_eq!(Epoch(u64::MAX).next(), Epoch(u64::MAX));
    }

    #[test]
    fn instance_id_round_trip_serde() -> core::result::Result<(), bincode::Error> {
        let id = InstanceId::new("commit-tree-0");
        let bytes = bincode::serialize(&id)?;
        let back: InstanceId = bincode::deserialize(&bytes)?;
        assert_eq!(id, back);
        Ok(())
    }

    proptest! {
        #[test]
        fn epoch_next_saturating_and_monotonic(n in any::<u64>()) {
            prop_assert_eq!(Epoch(n).next(), Epoch(n.saturating_add(1)));
            prop_assert!(Epoch(n).next() >= Epoch(n));
        }
    }
}
