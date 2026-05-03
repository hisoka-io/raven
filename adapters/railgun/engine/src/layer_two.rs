//! Layer 2 reorg detection: protocol-layer guarantee that the local IMT root
//! matches the contract's `rootHistory(tree, root)`. Catches the case Layer 1
//! misses — events applied locally in the wrong order, or the indexer dropping
//! a Shield event between `eth_getLogs` chunks. See [`VerifyOutcome`] for the
//! soundness model.

use std::cmp::Ordering;

use raven_railgun_core::{AdapterError, Result};
use raven_railgun_indexer::ChainSource;

use crate::imt::Imt;

/// Outcome of one Layer 2 verification round.
///
/// `rootHistory` is monotonic-set (never cleared) so a hit alone proves
/// "canonical at some past height", not currently canonical. Branches:
/// - **Active tree** (`tree == active`): InSync requires rootHistory hit AND
///   `merkleRoot() == local_root`.
/// - **Frozen tree** (`tree < active`): rootHistory hit is sufficient — frozen
///   trees can never gain a newer canonical root.
/// - **Future tree** (`tree > active`): always OutOfSync.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Local root passes the soundness check for the given tree.
    InSync,
    /// Local root failed verification; orchestrator should emit
    /// `IndexerMessage::Reorg` and walk back.
    OutOfSync {
        /// Locally-computed root that failed.
        local_root: [u8; 32],
        /// Tree whose root failed.
        tree_number: u32,
    },
}

/// Verify the IMT's current root against chain state. See [`VerifyOutcome`].
///
/// # Errors
/// Returns [`AdapterError::Scheme`] on chain source failure. Treat as transient.
pub async fn verify_root_against_chain<S: ChainSource + ?Sized>(
    source: &S,
    tree_number: u32,
    imt: &Imt,
) -> Result<VerifyOutcome> {
    let local_root = imt.root();

    // Capture the chain anchor ONCE so all three eth_calls observe the same
    // state. Without this, chain advancement between calls produces false
    // InSync/OutOfSync. Pin to finalized to avoid tip-reorg races.
    let anchor_block = source
        .latest_block()
        .await
        .map_err(|e| AdapterError::Scheme(format!("layer2 latest_block: {e}")))?;
    let at = Some(raven_railgun_indexer::BlockId::Number(
        raven_railgun_indexer::BlockNumberOrTag::Number(anchor_block),
    ));

    let active = source
        .active_tree_number(at)
        .await
        .map_err(|e| AdapterError::Scheme(format!("layer2 active_tree_number: {e}")))?;

    match tree_number.cmp(&active) {
        Ordering::Equal => active_branch(source, tree_number, local_root, at).await,
        Ordering::Less => frozen_branch(source, tree_number, local_root, at).await,
        Ordering::Greater => Ok(VerifyOutcome::OutOfSync {
            local_root,
            tree_number,
        }),
    }
}

async fn active_branch<S: ChainSource + ?Sized>(
    source: &S,
    tree_number: u32,
    local_root: [u8; 32],
    at: Option<raven_railgun_indexer::BlockId>,
) -> Result<VerifyOutcome> {
    let in_history = source
        .root_history(tree_number, local_root, at)
        .await
        .map_err(|e| {
            AdapterError::Scheme(format!("layer2 root_history(tree={tree_number}): {e}"))
        })?;
    let current = source
        .merkle_root(at)
        .await
        .map_err(|e| AdapterError::Scheme(format!("layer2 merkle_root: {e}")))?;
    if in_history && current == local_root {
        Ok(VerifyOutcome::InSync)
    } else {
        Ok(VerifyOutcome::OutOfSync {
            local_root,
            tree_number,
        })
    }
}

async fn frozen_branch<S: ChainSource + ?Sized>(
    source: &S,
    tree_number: u32,
    local_root: [u8; 32],
    at: Option<raven_railgun_indexer::BlockId>,
) -> Result<VerifyOutcome> {
    let in_history = source
        .root_history(tree_number, local_root, at)
        .await
        .map_err(|e| {
            AdapterError::Scheme(format!("layer2 root_history(tree={tree_number}): {e}"))
        })?;
    if in_history {
        Ok(VerifyOutcome::InSync)
    } else {
        Ok(VerifyOutcome::OutOfSync {
            local_root,
            tree_number,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use raven_railgun_core::RailgunEvent;
    use raven_railgun_indexer::{IndexerError, Result as IndexerResult};

    struct ChainStub {
        active_tree: u32,
        merkle_root_value: [u8; 32],
        history: Vec<(u32, [u8; 32])>,
    }

    #[async_trait]
    impl ChainSource for ChainStub {
        async fn latest_block(&self) -> IndexerResult<u64> {
            Ok(18_514_200)
        }
        async fn events_in_range(
            &self,
            _from_block: u64,
            _to_block: u64,
        ) -> IndexerResult<Vec<RailgunEvent>> {
            Err(IndexerError::Rpc(
                "ChainStub: events_in_range not used".into(),
            ))
        }
        async fn root_history(
            &self,
            tree_number: u32,
            merkle_root: [u8; 32],
            _at: Option<raven_railgun_indexer::BlockId>,
        ) -> IndexerResult<bool> {
            Ok(self
                .history
                .iter()
                .any(|(t, r)| *t == tree_number && *r == merkle_root))
        }
        async fn block_hash(&self, _block_number: u64) -> IndexerResult<[u8; 32]> {
            Err(IndexerError::Rpc("ChainStub: block_hash not used".into()))
        }
        async fn merkle_root(
            &self,
            _at: Option<raven_railgun_indexer::BlockId>,
        ) -> IndexerResult<[u8; 32]> {
            Ok(self.merkle_root_value)
        }
        async fn active_tree_number(
            &self,
            _at: Option<raven_railgun_indexer::BlockId>,
        ) -> IndexerResult<u32> {
            Ok(self.active_tree)
        }
    }

    #[tokio::test]
    async fn active_tree_in_sync_requires_history_and_current_match() {
        let mut imt = Imt::new().expect("imt");
        imt.insert_leaves(0, &[[1u8; 32], [2u8; 32]]).expect("seed");
        let local_root = imt.root();
        let source = ChainStub {
            active_tree: 0,
            merkle_root_value: local_root,
            history: vec![(0, local_root)],
        };
        let outcome = verify_root_against_chain(&source, 0, &imt)
            .await
            .expect("verify");
        assert_eq!(outcome, VerifyOutcome::InSync);
    }

    #[tokio::test]
    async fn active_tree_history_hit_but_stale_current_is_out_of_sync() {
        // W2 soundness regression: stale-but-historic root passes rootHistory
        // but merkleRoot() has moved past it.
        let mut imt = Imt::new().expect("imt");
        imt.insert_leaves(0, &[[1u8; 32]]).expect("seed");
        let stale_local = imt.root();
        let source = ChainStub {
            active_tree: 0,
            merkle_root_value: [0xee; 32],   // chain has advanced
            history: vec![(0, stale_local)], // but our root WAS canonical at some past height
        };
        let outcome = verify_root_against_chain(&source, 0, &imt)
            .await
            .expect("verify");
        assert_eq!(
            outcome,
            VerifyOutcome::OutOfSync {
                local_root: stale_local,
                tree_number: 0,
            }
        );
    }

    #[tokio::test]
    async fn active_tree_no_history_hit_is_out_of_sync() {
        let mut imt = Imt::new().expect("imt");
        imt.insert_leaves(0, &[[7u8; 32]]).expect("seed");
        let local_root = imt.root();
        let source = ChainStub {
            active_tree: 0,
            merkle_root_value: local_root, // even if current matches
            history: vec![],               // but never appeared in history
        };
        let outcome = verify_root_against_chain(&source, 0, &imt)
            .await
            .expect("verify");
        assert_eq!(
            outcome,
            VerifyOutcome::OutOfSync {
                local_root,
                tree_number: 0,
            }
        );
    }

    #[tokio::test]
    async fn frozen_tree_in_sync_on_history_hit_alone() {
        let mut imt = Imt::new().expect("imt");
        imt.insert_leaves(0, &[[1u8; 32]]).expect("seed");
        let local_root = imt.root();
        let source = ChainStub {
            active_tree: 1,
            merkle_root_value: [0xff; 32], // tree 1's current root, not tree 0's
            history: vec![(0, local_root)],
        };
        let outcome = verify_root_against_chain(&source, 0, &imt)
            .await
            .expect("verify");
        assert_eq!(outcome, VerifyOutcome::InSync);
    }

    #[tokio::test]
    async fn frozen_tree_no_history_hit_is_out_of_sync() {
        let mut imt = Imt::new().expect("imt");
        imt.insert_leaves(0, &[[7u8; 32]]).expect("seed");
        let local_root = imt.root();
        let source = ChainStub {
            active_tree: 1,
            merkle_root_value: [0xff; 32],
            history: vec![], // tree 0 frozen but our root never appeared
        };
        let outcome = verify_root_against_chain(&source, 0, &imt)
            .await
            .expect("verify");
        assert_eq!(
            outcome,
            VerifyOutcome::OutOfSync {
                local_root,
                tree_number: 0,
            }
        );
    }

    // W2 race-fix regression: all three eth_calls must thread the same anchor.
    #[tokio::test]
    async fn verifier_threads_block_anchor_to_all_three_calls() {
        use std::sync::Mutex;

        struct AnchorRecorder {
            seen: Mutex<Vec<Option<raven_railgun_indexer::BlockId>>>,
        }
        #[async_trait]
        impl ChainSource for AnchorRecorder {
            async fn latest_block(&self) -> IndexerResult<u64> {
                Ok(18_000_000)
            }
            async fn events_in_range(
                &self,
                _from_block: u64,
                _to_block: u64,
            ) -> IndexerResult<Vec<RailgunEvent>> {
                Err(IndexerError::Rpc("AnchorRecorder: events_in_range".into()))
            }
            async fn root_history(
                &self,
                _t: u32,
                _r: [u8; 32],
                at: Option<raven_railgun_indexer::BlockId>,
            ) -> IndexerResult<bool> {
                self.seen.lock().expect("lock").push(at);
                Ok(true)
            }
            async fn block_hash(&self, _n: u64) -> IndexerResult<[u8; 32]> {
                Err(IndexerError::Rpc("AnchorRecorder: block_hash".into()))
            }
            async fn merkle_root(
                &self,
                at: Option<raven_railgun_indexer::BlockId>,
            ) -> IndexerResult<[u8; 32]> {
                self.seen.lock().expect("lock").push(at);
                Ok([0u8; 32])
            }
            async fn active_tree_number(
                &self,
                at: Option<raven_railgun_indexer::BlockId>,
            ) -> IndexerResult<u32> {
                self.seen.lock().expect("lock").push(at);
                Ok(0)
            }
        }

        let imt = Imt::new().expect("imt");
        let source = AnchorRecorder {
            seen: Mutex::new(vec![]),
        };
        let _ = verify_root_against_chain(&source, 0, &imt).await;

        let seen = source.seen.lock().expect("lock");
        assert_eq!(
            seen.len(),
            3,
            "verifier must invoke active_tree_number + root_history + merkle_root \
             exactly once per round; got {} calls",
            seen.len()
        );
        let expected = Some(raven_railgun_indexer::BlockId::Number(
            raven_railgun_indexer::BlockNumberOrTag::Number(18_000_000),
        ));
        for (i, anchor) in seen.iter().enumerate() {
            assert_eq!(
                *anchor, expected,
                "call #{i} did not receive the captured anchor: got {anchor:?}, expected {expected:?}"
            );
        }
    }

    #[tokio::test]
    async fn future_tree_is_always_out_of_sync() {
        let mut imt = Imt::new().expect("imt");
        imt.insert_leaves(0, &[[1u8; 32]]).expect("seed");
        let local_root = imt.root();
        let source = ChainStub {
            active_tree: 0, // chain only on tree 0
            merkle_root_value: [0xff; 32],
            history: vec![(0, local_root)], // hit on tree 0 (irrelevant)
        };
        // We claim local IMT belongs to tree 5 (future).
        let outcome = verify_root_against_chain(&source, 5, &imt)
            .await
            .expect("verify");
        assert_eq!(
            outcome,
            VerifyOutcome::OutOfSync {
                local_root,
                tree_number: 5,
            }
        );
    }

    #[tokio::test]
    async fn rpc_failure_surfaces_as_scheme_error() {
        struct AlwaysFail;
        #[async_trait]
        impl ChainSource for AlwaysFail {
            async fn latest_block(&self) -> IndexerResult<u64> {
                Err(IndexerError::Rpc("nope".into()))
            }
            async fn events_in_range(
                &self,
                _from_block: u64,
                _to_block: u64,
            ) -> IndexerResult<Vec<RailgunEvent>> {
                Err(IndexerError::Rpc("nope".into()))
            }
            async fn root_history(
                &self,
                _tree_number: u32,
                _merkle_root: [u8; 32],
                _at: Option<raven_railgun_indexer::BlockId>,
            ) -> IndexerResult<bool> {
                Err(IndexerError::Rpc("synthetic outage".into()))
            }
            async fn block_hash(&self, _block_number: u64) -> IndexerResult<[u8; 32]> {
                Err(IndexerError::Rpc("nope".into()))
            }
            async fn merkle_root(
                &self,
                _at: Option<raven_railgun_indexer::BlockId>,
            ) -> IndexerResult<[u8; 32]> {
                Err(IndexerError::Rpc("synthetic outage".into()))
            }
            async fn active_tree_number(
                &self,
                _at: Option<raven_railgun_indexer::BlockId>,
            ) -> IndexerResult<u32> {
                Err(IndexerError::Rpc("synthetic outage".into()))
            }
        }
        let imt = Imt::new().expect("imt");
        let err = verify_root_against_chain(&AlwaysFail, 0, &imt)
            .await
            .expect_err("must surface RPC failure");
        match err {
            AdapterError::Scheme(msg) => {
                assert!(msg.contains("layer2"), "msg should reference layer2: {msg}");
            }
            other => panic!("expected AdapterError::Scheme, got {other:?}"),
        }
    }
}
