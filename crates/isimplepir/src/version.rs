use serde::{Deserialize, Serialize};

/// Monotonic hint version. `Setup` returns [`HintVersion::INITIAL`];
/// every successful `DBUpdate` / `StateUpdate` pair increments by
/// one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HintVersion(pub u64);

impl HintVersion {
    pub const INITIAL: HintVersion = HintVersion(0);

    #[inline]
    pub fn next(self) -> Self {
        HintVersion(self.0.saturating_add(1))
    }

    #[inline]
    pub fn get(self) -> u64 {
        self.0
    }
}

impl Default for HintVersion {
    fn default() -> Self {
        Self::INITIAL
    }
}
