// VEIL — Prekey Bundle Storage
// Ticket: VEIL-301
// Spec reference: Section 3.2, 9.3
//
// Stores prekey bundles for each registered user. On fetch, one classical
// OTP and one PQ OTP are consumed and returned to the requester.
// The server never inspects key contents — they are opaque bytes.

use crate::error::VeilRelayError;
use prost::Message;
use sled::Db;

/// Persistent prekey store backed by sled.
#[derive(Clone)]
pub struct PrekeyStore {
    tree: sled::Tree,
}

impl PrekeyStore {
    pub fn new(db: &Db) -> anyhow::Result<Self> {
        Ok(PrekeyStore {
            tree: db.open_tree("prekeys")?,
        })
    }

    /// Store or replace a prekey bundle for a registration ID.
    pub fn upload_bundle(
        &self,
        registration_id: u32,
        bundle: &crate::proto::PrekeyBundle,
    ) -> Result<(), VeilRelayError> {
        let key = registration_id.to_be_bytes();
        let value = bundle.encode_to_vec();
        self.tree.insert(key.as_ref(), value)?;
        self.tree.flush()?;

        tracing::info!(registration_id, "prekey bundle uploaded");
        Ok(())
    }

    /// Fetch a prekey bundle, consuming one classical OTP and one PQ OTP.
    ///
    /// The returned bundle contains only the signed prekeys and the consumed
    /// one-time prekeys. The remaining pool sizes are NOT disclosed to prevent
    /// enumeration attacks.
    pub fn fetch_bundle(
        &self,
        registration_id: u32,
    ) -> Result<crate::proto::PrekeyBundle, VeilRelayError> {
        let key = registration_id.to_be_bytes();

        // Transactional read-modify-write to atomically consume OTPs
        let result = self.tree.transaction(|tx_tree| {
            let raw = tx_tree
                .get(key.as_ref())?
                .ok_or(sled::transaction::ConflictableTransactionError::Abort(()))?;

            let mut stored_bundle = crate::proto::PrekeyBundle::decode(raw.as_ref())
                .map_err(|_| sled::transaction::ConflictableTransactionError::Abort(()))?;

            // Build the response bundle with at most one OTP of each type
            let mut response_bundle = crate::proto::PrekeyBundle {
                identity_key_ed25519: stored_bundle.identity_key_ed25519.clone(),
                identity_key_mldsa65: stored_bundle.identity_key_mldsa65.clone(),
                signed_prekey_id: stored_bundle.signed_prekey_id,
                signed_prekey: stored_bundle.signed_prekey.clone(),
                signed_prekey_sig: stored_bundle.signed_prekey_sig.clone(),
                pq_signed_prekey: stored_bundle.pq_signed_prekey.clone(),
                pq_signed_prekey_sig: stored_bundle.pq_signed_prekey_sig.clone(),
                opks: Vec::new(),
                pq_opks: Vec::new(),
            };

            // Consume one classical OTP (if available)
            if !stored_bundle.opks.is_empty() {
                let consumed = stored_bundle.opks.remove(0);
                response_bundle.opks.push(consumed);
            }

            // Consume one PQ OTP (if available)
            if !stored_bundle.pq_opks.is_empty() {
                let consumed = stored_bundle.pq_opks.remove(0);
                response_bundle.pq_opks.push(consumed);
            }

            // Write back the bundle with consumed OTPs removed
            let updated = stored_bundle.encode_to_vec();
            tx_tree.insert(key.as_ref(), updated)?;

            Ok(response_bundle)
        });

        match result {
            Ok(bundle) => {
                tracing::info!(registration_id, "prekey bundle fetched");
                Ok(bundle)
            }
            Err(sled::transaction::TransactionError::Abort(())) => {
                Err(VeilRelayError::PrekeyBundleNotFound)
            }
            Err(sled::transaction::TransactionError::Storage(e)) => {
                Err(VeilRelayError::StorageError(e))
            }
        }
    }

    /// Get the remaining OTP counts for a registration (used for replenishment checks).
    pub fn otp_counts(
        &self,
        registration_id: u32,
    ) -> Result<(usize, usize), VeilRelayError> {
        let key = registration_id.to_be_bytes();
        let raw = self
            .tree
            .get(key.as_ref())?
            .ok_or(VeilRelayError::PrekeyBundleNotFound)?;

        let bundle = crate::proto::PrekeyBundle::decode(raw.as_ref())
            .map_err(|e| VeilRelayError::SerializationError(e.to_string()))?;

        Ok((bundle.opks.len(), bundle.pq_opks.len()))
    }
}
