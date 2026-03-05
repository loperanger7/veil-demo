// VEIL — Integration Tests
// Tickets: VEIL-301, VEIL-302
//
// End-to-end tests exercising the full API flow:
//   Register → Upload Prekeys → Fetch Prekeys → Send Message →
//   Retrieve Messages → Acknowledge → Verify Deletion
//
// These tests use sled's temporary (in-memory) mode and axum's
// built-in test utilities — no network sockets needed.

use axum::body::Bytes;
use axum::http::{Request, StatusCode};
use prost::Message;
use tower::ServiceExt;

// Re-export the relay crate modules
// Note: In the actual build, these would come from `use veil_relay::*;`
// For now, we define the test structure assuming the crate is importable.

/// Helper: build a test app with in-memory storage.
async fn test_app() -> axum::Router {
    // Open temporary sled database
    let config = sled::Config::new().temporary(true);
    let db = config.open().expect("failed to open temp sled");

    let storage = veil_relay::storage::Storage {
        accounts: veil_relay::storage::accounts::AccountStore::new(&db).unwrap(),
        prekeys: veil_relay::storage::prekey_store::PrekeyStore::new(&db).unwrap(),
        messages: veil_relay::storage::message_queue::MessageQueue::new(&db).unwrap(),
    };

    let signing_key = veil_relay::auth::anonymous_token::TokenSigningKey::generate().unwrap();
    let token_service = std::sync::Arc::new(
        veil_relay::auth::anonymous_token::AnonymousTokenService::new(signing_key, &db).unwrap(),
    );

    let state = veil_relay::api::AppState {
        storage,
        token_service,
    };

    veil_relay::api::router(state)
}

/// Helper: create a mock anonymous token (hex-encoded Ristretto point).
///
/// In a real flow, this would go through the blind signing protocol.
/// For integration tests, we use a known-valid Ristretto point.
fn mock_token_hex() -> String {
    // The Ristretto basepoint compressed — a valid point
    let basepoint = curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
    hex::encode(basepoint.as_bytes())
}

// ── Test: Full Message Lifecycle ──

#[tokio::test]
async fn test_full_message_lifecycle() {
    let app = test_app().await;

    // Step 1: Register Alice's device
    let reg_request = veil_relay::proto::RegistrationRequest {
        device_id: 1,
        identity_key: vec![0xAA; 32],
        blinded_tokens: vec![], // Skip tokens for this test
    };

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/registration")
                .header("content-type", "application/x-protobuf")
                .body(axum::body::Body::from(reg_request.encode_to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let reg_response = veil_relay::proto::RegistrationResponse::decode(body.as_ref()).unwrap();
    let alice_reg_id = reg_response.registration_id;
    assert!(alice_reg_id > 0);

    // Step 2: Upload Alice's prekey bundle
    let bundle = veil_relay::proto::PrekeyBundle {
        identity_key: vec![0xAA; 32],
        signed_prekey: vec![0xBB; 32],
        signed_prekey_signature: vec![0xCC; 64],
        one_time_prekeys: vec![vec![0xDD; 32], vec![0xEE; 32]],
        pq_kem_public_key: Some(vec![0xFF; 1568]),
        pq_kem_signature: Some(vec![0x11; 64]),
    };

    let upload_request = veil_relay::proto::PrekeyUploadRequest {
        registration_id: alice_reg_id,
        bundle: Some(bundle),
    };

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/keys")
                .header("content-type", "application/x-protobuf")
                .header("x-veil-token", mock_token_hex())
                .body(axum::body::Body::from(upload_request.encode_to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Step 3: Fetch Alice's prekey bundle (as Bob would)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/keys/{}", alice_reg_id))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let fetch_response = veil_relay::proto::PrekeyFetchResponse::decode(body.as_ref()).unwrap();
    assert!(fetch_response.bundle.is_some());

    // Step 4: Send a sealed-sender message to Alice (as Bob)
    let envelope = veil_relay::proto::VeilEnvelope {
        content: vec![0x42; 256],      // Opaque ciphertext
        sealed_sender: vec![0x99; 128], // Sender info encrypted to Alice
        content_type: 1,
        source_registration_id: 0,      // Zero — sealed sender
        source_device_id: 0,            // Zero — sealed sender
        server_guid: vec![],            // Assigned by server
        server_timestamp: 0,            // Assigned by server
    };

    let send_request = veil_relay::proto::SendMessageRequest {
        envelope: Some(envelope),
    };

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/v1/messages/{}", alice_reg_id))
                .header("content-type", "application/x-protobuf")
                .header("x-veil-token", mock_token_hex())
                .body(axum::body::Body::from(send_request.encode_to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let send_response = veil_relay::proto::SendMessageResponse::decode(body.as_ref()).unwrap();
    assert_eq!(send_response.delivery_results.len(), 1);
    let server_guid = &send_response.delivery_results[0].server_guid;

    // Step 5: Alice retrieves her messages
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/v1/messages?registration_id={}&device_id=1",
                    alice_reg_id
                ))
                .header("x-veil-token", mock_token_hex())
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let retrieve_response =
        veil_relay::proto::RetrieveMessagesResponse::decode(body.as_ref()).unwrap();
    assert_eq!(retrieve_response.envelopes.len(), 1);
    assert_eq!(retrieve_response.envelopes[0].content, vec![0x42; 256]);

    // Step 6: Alice acknowledges receipt
    let guid_hex = hex::encode(server_guid);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/v1/messages/{}?registration_id={}&device_id=1",
                    guid_hex, alice_reg_id
                ))
                .header("x-veil-token", mock_token_hex())
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Step 7: Verify message is deleted
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/v1/messages?registration_id={}&device_id=1",
                    alice_reg_id
                ))
                .header("x-veil-token", mock_token_hex())
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let retrieve_response =
        veil_relay::proto::RetrieveMessagesResponse::decode(body.as_ref()).unwrap();
    assert_eq!(
        retrieve_response.envelopes.len(),
        0,
        "message queue must be empty after acknowledgment"
    );
}

// ── Test: Prekey Bundle Not Found ──

#[tokio::test]
async fn test_prekey_bundle_not_found() {
    let app = test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/keys/999999")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ── Test: Send to Nonexistent Recipient ──

#[tokio::test]
async fn test_send_to_nonexistent_recipient() {
    let app = test_app().await;

    let envelope = veil_relay::proto::VeilEnvelope {
        content: vec![0x42; 256],
        sealed_sender: vec![0x99; 128],
        content_type: 1,
        source_registration_id: 0,
        source_device_id: 0,
        server_guid: vec![],
        server_timestamp: 0,
    };

    let send_request = veil_relay::proto::SendMessageRequest {
        envelope: Some(envelope),
    };

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/messages/999999")
                .header("content-type", "application/x-protobuf")
                .header("x-veil-token", mock_token_hex())
                .body(axum::body::Body::from(send_request.encode_to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ── Test: Missing Token Returns 401 ──

#[tokio::test]
async fn test_missing_token_returns_unauthorized() {
    let app = test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/keys")
                .header("content-type", "application/x-protobuf")
                // No X-Veil-Token header
                .body(axum::body::Body::from(vec![0u8; 10]))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
