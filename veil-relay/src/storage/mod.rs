// VEIL — Storage Layer
// Ticket: VEIL-301 — Relay Service Core Infrastructure
// Spec reference: Section 2.2, 2.3
//
// The storage layer uses sled (embedded key-value store) for zero-config
// deployment. Three logical stores:
//   - accounts: registration_id → device metadata
//   - prekeys: registration_id → serialized PrekeyBundle
//   - messages: (registration_id, device_id) → FIFO queue of VeilEnvelopes

pub mod accounts;
pub mod message_queue;
pub mod prekey_store;

use sled::Db;

/// Shared storage state for the relay service.
///
/// All trees are opened from a single sled database instance.
/// sled provides ACID transactions, crash recovery, and lock-free
/// concurrent reads.
#[derive(Clone)]
pub struct Storage {
    pub accounts: accounts::AccountStore,
    pub prekeys: prekey_store::PrekeyStore,
    pub messages: message_queue::MessageQueue,
}

impl Storage {
    /// Open or create the storage database at the given path.
    pub fn open(path: &str) -> anyhow::Result<Self> {
        let db = sled::open(path)?;

        Ok(Storage {
            accounts: accounts::AccountStore::new(&db)?,
            prekeys: prekey_store::PrekeyStore::new(&db)?,
            messages: message_queue::MessageQueue::new(&db)?,
        })
    }

    /// Open an in-memory database for testing.
    #[cfg(test)]
    pub fn open_temporary() -> anyhow::Result<Self> {
        let config = sled::Config::new().temporary(true);
        let db = config.open()?;

        Ok(Storage {
            accounts: accounts::AccountStore::new(&db)?,
            prekeys: prekey_store::PrekeyStore::new(&db)?,
            messages: message_queue::MessageQueue::new(&db)?,
        })
    }
}
