// VEIL — Message Queue
// Ticket: VEIL-301
// Spec reference: Section 2.2
//
// Per-device FIFO queue of opaque VeilEnvelope blobs.
// Messages are deleted after the client acknowledges receipt.
// The server never inspects message content.

use crate::error::VeilRelayError;
use prost::Message;
use sled::Db;
use uuid::Uuid;

/// Per-device message queue backed by sled.
#[derive(Clone)]
pub struct MessageQueue {
    /// Messages indexed by server_guid for deletion.
    messages_tree: sled::Tree,
    /// Index: (registration_id, device_id) → list of server_guids.
    index_tree: sled::Tree,
    /// Maximum messages per device.
    max_queue_size: usize,
}

impl MessageQueue {
    pub fn new(db: &Db) -> anyhow::Result<Self> {
        Ok(MessageQueue {
            messages_tree: db.open_tree("messages")?,
            index_tree: db.open_tree("message_index")?,
            max_queue_size: 10_000,
        })
    }

    pub fn with_max_size(mut self, max: usize) -> Self {
        self.max_queue_size = max;
        self
    }

    /// Enqueue a message for delivery to a specific device.
    ///
    /// Assigns a server_guid and server_timestamp, then stores the
    /// envelope in the queue.
    pub fn enqueue(
        &self,
        registration_id: u32,
        device_id: u32,
        mut envelope: crate::proto::VeilEnvelope,
    ) -> Result<Vec<u8>, VeilRelayError> {
        // Check queue size limit
        let index_key = Self::index_key(registration_id, device_id);
        let current_guids = self.get_guid_list(&index_key)?;
        if current_guids.len() >= self.max_queue_size {
            return Err(VeilRelayError::MessageQueueFull);
        }

        // Assign server metadata
        let server_guid = Uuid::new_v4().as_bytes().to_vec();
        let server_timestamp = chrono::Utc::now().timestamp_millis() as u64;

        envelope.server_guid = server_guid.clone();
        envelope.server_timestamp = server_timestamp;

        // Store the envelope
        let envelope_bytes = envelope.encode_to_vec();
        self.messages_tree
            .insert(server_guid.as_slice(), envelope_bytes)?;

        // Update the device's message index
        let mut guids = current_guids;
        guids.push(server_guid.clone());
        let index_value = serde_json::to_vec(&guids)
            .map_err(|e| VeilRelayError::SerializationError(e.to_string()))?;
        self.index_tree.insert(index_key, index_value)?;

        tracing::info!(
            registration_id,
            device_id,
            queue_size = guids.len(),
            "message enqueued"
        );

        Ok(server_guid)
    }

    /// Retrieve all pending messages for a device.
    ///
    /// Messages are NOT deleted — the client must explicitly acknowledge
    /// each one via `acknowledge()`.
    pub fn retrieve(
        &self,
        registration_id: u32,
        device_id: u32,
    ) -> Result<Vec<crate::proto::VeilEnvelope>, VeilRelayError> {
        let index_key = Self::index_key(registration_id, device_id);
        let guids = self.get_guid_list(&index_key)?;

        let mut envelopes = Vec::with_capacity(guids.len());
        for guid in &guids {
            if let Some(raw) = self.messages_tree.get(guid)? {
                if let Ok(envelope) = crate::proto::VeilEnvelope::decode(raw.as_ref()) {
                    envelopes.push(envelope);
                }
            }
        }

        tracing::info!(
            registration_id,
            device_id,
            count = envelopes.len(),
            "messages retrieved"
        );

        Ok(envelopes)
    }

    /// Acknowledge receipt of a message, triggering its deletion.
    ///
    /// The message is permanently removed from storage. This is the
    /// only way messages leave the queue.
    pub fn acknowledge(
        &self,
        registration_id: u32,
        device_id: u32,
        server_guid: &[u8],
    ) -> Result<(), VeilRelayError> {
        // Remove from message store
        self.messages_tree
            .remove(server_guid)?
            .ok_or(VeilRelayError::MessageNotFound)?;

        // Remove from device index
        let index_key = Self::index_key(registration_id, device_id);
        let mut guids = self.get_guid_list(&index_key)?;
        guids.retain(|g| g != server_guid);

        let index_value = serde_json::to_vec(&guids)
            .map_err(|e| VeilRelayError::SerializationError(e.to_string()))?;
        self.index_tree.insert(index_key, index_value)?;

        tracing::info!(
            registration_id,
            device_id,
            remaining = guids.len(),
            "message acknowledged and deleted"
        );

        Ok(())
    }

    /// Get the queue depth for a device (for push notification decisions).
    pub fn queue_depth(
        &self,
        registration_id: u32,
        device_id: u32,
    ) -> Result<usize, VeilRelayError> {
        let index_key = Self::index_key(registration_id, device_id);
        Ok(self.get_guid_list(&index_key)?.len())
    }

    // ── Helpers ──

    fn index_key(registration_id: u32, device_id: u32) -> Vec<u8> {
        format!("{}:{}", registration_id, device_id).into_bytes()
    }

    fn get_guid_list(&self, index_key: &[u8]) -> Result<Vec<Vec<u8>>, VeilRelayError> {
        match self.index_tree.get(index_key)? {
            Some(raw) => serde_json::from_slice(&raw)
                .map_err(|e| VeilRelayError::SerializationError(e.to_string())),
            None => Ok(Vec::new()),
        }
    }
}
