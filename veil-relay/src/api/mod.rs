// VEIL — API Module
// Ticket: VEIL-301
// Spec reference: Section 2.1
//
// HTTP/2 API routes served over TLS 1.3.
// All routes use protobuf serialization (application/x-protobuf).
//
// Route map:
//   POST   /v1/registration              → register device
//   PUT    /v1/keys                       → upload prekey bundle
//   GET    /v1/keys/:registration_id      → fetch prekey bundle
//   PUT    /v1/messages/:registration_id  → send sealed-sender envelope
//   GET    /v1/messages                   → retrieve queued messages
//   DELETE /v1/messages/:server_guid      → acknowledge message delivery
//   PUT    /v1/push/token                 → register APNs push token
//
// Auth: All state-mutating routes (PUT/POST/DELETE) require an anonymous
// token in the X-Veil-Token header. GET /v1/keys is public (needed for
// first contact). GET /v1/messages uses token + replenishment.

pub mod messages;
pub mod prekeys;
pub mod push;
pub mod registration;

use axum::{
    routing::{delete, get, post, put},
    Router,
};

use crate::storage::Storage;
use crate::auth::anonymous_token::AnonymousTokenService;
use std::sync::Arc;

/// Application state shared across all handlers.
#[derive(Clone)]
pub struct AppState {
    pub storage: Storage,
    pub token_service: Arc<AnonymousTokenService>,
}

/// Build the axum router with all API routes.
pub fn router(state: AppState) -> Router {
    Router::new()
        // VEIL-301: Registration
        .route("/v1/registration", post(registration::register_device))
        // VEIL-301: Prekey management
        .route("/v1/keys", put(prekeys::upload_prekeys))
        .route("/v1/keys/{registration_id}", get(prekeys::fetch_prekeys))
        // VEIL-301: Message delivery
        .route(
            "/v1/messages/{registration_id}",
            put(messages::send_message),
        )
        .route("/v1/messages", get(messages::retrieve_messages))
        .route(
            "/v1/messages/{server_guid}",
            delete(messages::acknowledge_message),
        )
        // VEIL-304: Push token
        .route("/v1/push/token", put(push::register_push_token))
        .with_state(state)
}
