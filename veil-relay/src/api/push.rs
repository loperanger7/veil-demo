// VEIL — Push Token Registration Handler
// Ticket: VEIL-304
// Spec reference: Section 2.4
//
// Clients register their APNs device token so the server can send
// silent push notifications when new messages arrive.
//
// The push payload is always minimal: { "aps": { "content-available": 1 } }
// No message preview, sender identity, or badge count is ever included.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use prost::Message;

use crate::api::AppState;
use crate::auth::anonymous_token;
use crate::error::VeilRelayError;

/// PUT /v1/push/token
///
/// Request body: PushTokenRequest (protobuf)
/// Header: X-Veil-Token (anonymous token)
///
/// Stores the client's APNs token alongside their device record.
/// The token is used only for silent "wake up" pushes.
pub async fn register_push_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, VeilRelayError> {
    // Verify anonymous token
    let token_header = headers
        .get("x-veil-token")
        .and_then(|v| v.to_str().ok());
    anonymous_token::verify_token_header(&state.token_service, token_header).await?;

    let request = crate::proto::PushTokenRequest::decode(body.as_ref())
        .map_err(|e| VeilRelayError::InvalidRequest(e.to_string()))?;

    if request.registration_id == 0 || request.device_id == 0 {
        return Err(VeilRelayError::InvalidRequest(
            "registration_id and device_id must be non-zero".into(),
        ));
    }

    if request.apns_token.is_empty() {
        return Err(VeilRelayError::InvalidRequest(
            "apns_token must not be empty".into(),
        ));
    }

    // Update the device record with the APNs token
    state.storage.accounts.update_apns_token(
        request.registration_id,
        request.device_id,
        &request.apns_token,
    )?;

    tracing::info!(
        registration_id = request.registration_id,
        device_id = request.device_id,
        "push token registered"
    );

    Ok(StatusCode::NO_CONTENT)
}
