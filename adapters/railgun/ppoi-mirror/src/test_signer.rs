//! A list provider whose signing key is public, so a test can serve synthetic rows the feed
//! accepts. Rows it signs verify only under its own list key.

use ed25519_dalek::{Signer, SigningKey};

/// Signs rows for the list whose key is [`TestListSigner::list_key`].
#[derive(Clone, Debug)]
pub struct TestListSigner(SigningKey);

impl TestListSigner {
    /// The provider whose secret key is 32 copies of `seed`.
    #[must_use]
    pub fn new(seed: u8) -> Self {
        Self(SigningKey::from_bytes(&[seed; 32]))
    }

    /// The list key its rows verify under.
    #[must_use]
    pub fn list_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// [`Self::list_key`] as the hex a config and a request carry.
    #[must_use]
    pub fn list_key_hex(&self) -> String {
        crate::hex_lower(&self.list_key())
    }

    /// `signedPOIEvent.signature` for a row served with exactly these strings.
    ///
    /// ```
    /// use raven_railgun_ppoi_mirror::test_signer::TestListSigner;
    /// let signature = TestListSigner::new(7).sign(0, "0x01", "Shield")?;
    /// assert_eq!(signature.len(), 128);
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    pub fn sign(
        &self,
        index: u64,
        blinded_commitment: &str,
        event_type: &str,
    ) -> serde_json::Result<String> {
        let message = crate::signed_message(index, blinded_commitment, event_type)?;
        Ok(crate::hex_lower(&self.0.sign(&message).to_bytes()))
    }

    /// One `ppoi_poi_events` result row carrying exactly these strings, signed.
    pub fn row(
        &self,
        index: u64,
        blinded_commitment: &str,
        event_type: &str,
        validated_merkleroot: &str,
    ) -> serde_json::Result<serde_json::Value> {
        Ok(serde_json::json!({
            "signedPOIEvent": {
                "index": index,
                "blindedCommitment": blinded_commitment,
                "signature": self.sign(index, blinded_commitment, event_type)?,
                "type": event_type,
            },
            "validatedMerkleroot": validated_merkleroot,
        }))
    }
}
