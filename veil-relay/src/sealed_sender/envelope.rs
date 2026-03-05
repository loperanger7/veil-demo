// VEIL — Sealed Sender Envelope Handler
// Ticket: VEIL-302
// Spec reference: Section 4.2
//
// The server's role with sealed sender envelopes is deliberately minimal:
//   1. Accept the opaque blob from the sender
//   2. Assign server_guid and server_timestamp
//   3. Enqueue for the recipient device(s)
//   4. Deliver on retrieval
//   5. Delete on acknowledgment
//
// The server NEVER:
//   - Decrypts or parses the sealed_sender field
//   - Infers sender identity from any envelope field
//   - Stores sender metadata alongside the message
//   - Logs any field that could identify the sender

use crate::error::VeilRelayError;
use crate::storage::message_queue::MessageQueue;
use crate::storage::accounts::AccountStore;

/// Validates and routes a sealed-sender envelope to the recipient's device queue(s).
///
/// This function enforces the zero-knowledge invariant: the only fields
/// read from the envelope are `registration_id` and `device_id`, which
/// identify the *recipient*, not the sender.
pub fn route_sealed_envelope(
    message_queue: &MessageQueue,
    account_store: &AccountStore,
    recipient_registration_id: u32,
    recipient_device_id: u32,
    envelope: crate::proto::VeilEnvelope,
) -> Result<Vec<u8>, VeilRelayError> {
    // Verify recipient exists
    let _device = account_store
        .get_device(recipient_registration_id, recipient_device_id)?
        .ok_or(VeilRelayError::RecipientNotFound)?;

    // Validate envelope has required opaque fields
    if envelope.sealed_sender.is_empty() {
        return Err(VeilRelayError::InvalidEnvelope(
            "sealed_sender field is empty".into(),
        ));
    }

    if envelope.content.is_empty() {
        return Err(VeilRelayError::InvalidEnvelope(
            "content field is empty".into(),
        ));
    }

    // Enqueue — the message_queue assigns server_guid and server_timestamp
    let server_guid = message_queue.enqueue(
        recipient_registration_id,
        recipient_device_id,
        envelope,
    )?;

    tracing::info!(
        recipient_registration_id,
        recipient_device_id,
        "sealed envelope routed"
    );

    Ok(server_guid)
}

/// Route a sealed envelope to ALL devices registered under an account.
///
/// Multi-device delivery: the same envelope is enqueued for each device
/// so that all of a recipient's devices can decrypt the message.
pub fn route_to_all_devices(
    message_queue: &MessageQueue,
    account_store: &AccountStore,
    recipient_registration_id: u32,
    envelope: &crate::proto::VeilEnvelope,
) -> Result<Vec<(u32, Vec<u8>)>, VeilRelayError> {
    let devices = account_store.get_all_devices(recipient_registration_id)?;

    if devices.is_empty() {
        return Err(VeilRelayError::RecipientNotFound);
    }

    let mut results = Vec::with_capacity(devices.len());

    for device in &devices {
        let guid = message_queue.enqueue(
            recipient_registration_id,
            device.device_id,
            envelope.clone(),
        )?;
        results.push((device.device_id, guid));
    }

    tracing::info!(
        recipient_registration_id,
        device_count = results.len(),
        "sealed envelope routed to all devices"
    );

    Ok(results)
}

/// Audit check: verify that a VeilEnvelope has no sender-identifying metadata.
///
/// This is a debug/testing assertion — in production, the server never looks
/// at these fields, but in tests we want to confirm the client isn't
/// accidentally populating sender fields.
#[cfg(test)]
pub fn assert_no_sender_metadata(envelope: &crate::proto::VeilEnvelope) {
    // The source_registration_id should be 0 (unset) in sealed sender mode
    assert_eq!(
        envelope.source_registration_id, 0,
        "sealed sender envelope must not contain source_registration_id"
    );

    // The source_device_id should be 0 (unset) in sealed sender mode
    assert_eq!(
        envelope.source_device_id, 0,
        "sealed sender envelope must not contain source_device_id"
    );
}
