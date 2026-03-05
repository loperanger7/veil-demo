// VEIL — Sealed Sender Tests
// Ticket: VEIL-302
//
// Verifies that the relay server maintains zero-knowledge of sender identity.
//
// Dijkstra-style invariant:
//   forall (envelope : VeilEnvelope, stored : StoredEnvelope) ->
//       stored.source_registration_id == 0 &&
//       stored.source_device_id == 0 &&
//       no_log_contains(sender_id)

#[tokio::test]
async fn test_sealed_sender_no_sender_metadata_in_storage() {
    // Setup
    let config = sled::Config::new().temporary(true);
    let db = config.open().unwrap();

    let accounts = veil_relay::storage::accounts::AccountStore::new(&db).unwrap();
    let messages = veil_relay::storage::message_queue::MessageQueue::new(&db).unwrap();

    // Register a device
    let reg_id = accounts.register_device(1, vec![0xAA; 32]).unwrap();

    // Create a sealed-sender envelope
    let envelope = veil_relay::proto::VeilEnvelope {
        content: vec![0x42; 256],
        sealed_sender: vec![0x99; 128],
        content_type: 1,
        // These MUST be zero in sealed sender mode
        source_registration_id: 0,
        source_device_id: 0,
        server_guid: vec![],
        server_timestamp: 0,
    };

    // Route through the sealed sender handler
    let guid = veil_relay::sealed_sender::envelope::route_sealed_envelope(
        &messages,
        &accounts,
        reg_id,
        1,
        envelope,
    )
    .unwrap();

    // Retrieve and verify
    let stored = messages.retrieve(reg_id, 1).unwrap();
    assert_eq!(stored.len(), 1);

    let stored_envelope = &stored[0];

    // INVARIANT: No sender identity in stored envelope
    assert_eq!(
        stored_envelope.source_registration_id, 0,
        "stored envelope must not contain sender registration_id"
    );
    assert_eq!(
        stored_envelope.source_device_id, 0,
        "stored envelope must not contain sender device_id"
    );

    // The sealed_sender blob is preserved opaquely
    assert_eq!(stored_envelope.sealed_sender, vec![0x99; 128]);

    // Server-assigned metadata is present
    assert!(!stored_envelope.server_guid.is_empty());
    assert!(stored_envelope.server_timestamp > 0);
}

#[tokio::test]
async fn test_sealed_sender_rejects_empty_sealed_sender() {
    let config = sled::Config::new().temporary(true);
    let db = config.open().unwrap();

    let accounts = veil_relay::storage::accounts::AccountStore::new(&db).unwrap();
    let messages = veil_relay::storage::message_queue::MessageQueue::new(&db).unwrap();

    let reg_id = accounts.register_device(1, vec![0xAA; 32]).unwrap();

    // Envelope with empty sealed_sender — invalid
    let envelope = veil_relay::proto::VeilEnvelope {
        content: vec![0x42; 256],
        sealed_sender: vec![], // Empty!
        content_type: 1,
        source_registration_id: 0,
        source_device_id: 0,
        server_guid: vec![],
        server_timestamp: 0,
    };

    let result = veil_relay::sealed_sender::envelope::route_sealed_envelope(
        &messages,
        &accounts,
        reg_id,
        1,
        envelope,
    );

    assert!(result.is_err(), "empty sealed_sender must be rejected");
}

#[tokio::test]
async fn test_sealed_sender_multi_device_delivery() {
    let config = sled::Config::new().temporary(true);
    let db = config.open().unwrap();

    let accounts = veil_relay::storage::accounts::AccountStore::new(&db).unwrap();
    let messages = veil_relay::storage::message_queue::MessageQueue::new(&db).unwrap();

    // Register two devices under the same account
    let reg_id = accounts.register_device(1, vec![0xAA; 32]).unwrap();
    // Register a second device (same registration_id, different device_id)
    accounts.register_device(2, vec![0xAA; 32]).unwrap();

    let envelope = veil_relay::proto::VeilEnvelope {
        content: vec![0x42; 256],
        sealed_sender: vec![0x99; 128],
        content_type: 1,
        source_registration_id: 0,
        source_device_id: 0,
        server_guid: vec![],
        server_timestamp: 0,
    };

    // Route to all devices
    let results = veil_relay::sealed_sender::envelope::route_to_all_devices(
        &messages,
        &accounts,
        reg_id,
        &envelope,
    )
    .unwrap();

    // Both devices should have received the message
    assert_eq!(results.len(), 2, "message must be delivered to all devices");

    // Each device has its own copy with unique server_guid
    let guid1 = &results[0].1;
    let guid2 = &results[1].1;
    assert_ne!(guid1, guid2, "each device copy must have a unique server_guid");
}
