// VEIL — Account Storage
// Ticket: VEIL-301

use crate::error::VeilRelayError;
use serde::{Deserialize, Serialize};
use sled::Db;
use std::sync::atomic::{AtomicU32, Ordering};

/// Device/account metadata stored on the relay.
///
/// The relay stores the minimum necessary for routing:
/// no names, no phone numbers, no message content.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeviceRecord {
    pub registration_id: u32,
    pub device_id: u32,
    pub identity_key_ed25519: Vec<u8>,
    pub identity_key_mldsa65: Vec<u8>,
    pub apns_token: Option<Vec<u8>>,
    pub created_at: i64,
}

/// Persistent account store backed by sled.
#[derive(Clone)]
pub struct AccountStore {
    tree: sled::Tree,
    next_registration_id: std::sync::Arc<AtomicU32>,
}

impl AccountStore {
    pub fn new(db: &Db) -> anyhow::Result<Self> {
        let tree = db.open_tree("accounts")?;

        // Determine the next registration ID from existing data
        let max_id = tree
            .iter()
            .filter_map(|r| r.ok())
            .filter_map(|(_k, v)| serde_json::from_slice::<DeviceRecord>(&v).ok())
            .map(|d| d.registration_id)
            .max()
            .unwrap_or(0);

        Ok(AccountStore {
            tree,
            next_registration_id: std::sync::Arc::new(AtomicU32::new(max_id + 1)),
        })
    }

    /// Register a new device and return its registration ID and device ID.
    pub fn register_device(
        &self,
        identity_key_ed25519: &[u8],
        identity_key_mldsa65: &[u8],
        apns_token: Option<&[u8]>,
    ) -> Result<(u32, u32), VeilRelayError> {
        let registration_id = self.next_registration_id.fetch_add(1, Ordering::SeqCst);
        let device_id = 1; // First device; multi-device adds more

        let record = DeviceRecord {
            registration_id,
            device_id,
            identity_key_ed25519: identity_key_ed25519.to_vec(),
            identity_key_mldsa65: identity_key_mldsa65.to_vec(),
            apns_token: apns_token.map(|t| t.to_vec()),
            created_at: chrono::Utc::now().timestamp(),
        };

        let key = Self::device_key(registration_id, device_id);
        let value = serde_json::to_vec(&record)
            .map_err(|e| VeilRelayError::SerializationError(e.to_string()))?;

        self.tree.insert(key, value)?;
        self.tree.flush()?;

        tracing::info!(registration_id, device_id, "device registered");
        Ok((registration_id, device_id))
    }

    /// Look up a device record.
    pub fn get_device(
        &self,
        registration_id: u32,
        device_id: u32,
    ) -> Result<DeviceRecord, VeilRelayError> {
        let key = Self::device_key(registration_id, device_id);
        let value = self.tree.get(key)?.ok_or(VeilRelayError::DeviceNotFound)?;
        serde_json::from_slice(&value)
            .map_err(|e| VeilRelayError::SerializationError(e.to_string()))
    }

    /// Get all devices for a registration (for multi-device push).
    pub fn get_all_devices(
        &self,
        registration_id: u32,
    ) -> Result<Vec<DeviceRecord>, VeilRelayError> {
        let prefix = format!("{}:", registration_id);
        let devices: Vec<DeviceRecord> = self
            .tree
            .scan_prefix(prefix.as_bytes())
            .filter_map(|r| r.ok())
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect();
        Ok(devices)
    }

    /// Update APNs token for a device.
    pub fn update_apns_token(
        &self,
        registration_id: u32,
        device_id: u32,
        apns_token: &[u8],
    ) -> Result<(), VeilRelayError> {
        let mut record = self.get_device(registration_id, device_id)?;
        record.apns_token = Some(apns_token.to_vec());

        let key = Self::device_key(registration_id, device_id);
        let value = serde_json::to_vec(&record)
            .map_err(|e| VeilRelayError::SerializationError(e.to_string()))?;

        self.tree.insert(key, value)?;
        Ok(())
    }

    /// Composite key: "registration_id:device_id"
    fn device_key(registration_id: u32, device_id: u32) -> Vec<u8> {
        format!("{}:{}", registration_id, device_id).into_bytes()
    }
}
