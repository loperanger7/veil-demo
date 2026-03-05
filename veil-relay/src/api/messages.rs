// VEIL — Message Delivery Handlers
// Ticket: VEIL-301, VEIL-302
// Spec reference: Section 2.1, 4.2
//
// Three operations:
//   1. Send: Accept sealed-sender envelope, route to recipient device(s)
//   2. Retrieve: Return all pending messages for the authenticated device
//   3. Acknowledge: Delete a specific message after client confirms receipt
//
// Zero-knowledge invariants:
//   - Send handler never inspects sealed_sender payload
//   - No sender IP → message correlation is stored
//   - Retrieve returns opaque blobs; decryption happens client-side

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use prost::Message;
use serde::Deserialize;

use crate::api::AppState;
use crate::auth::anonymous_token::{self, BlindedToken};
use crate::error::VeilRelayError;
use crate::sealed_sender::envelope;

/// PUT /v1/messages/:registration_id
///
/// Request body: SendMessageRequest (protobuf)
/// Header: X-Veil-Token (anonymous token)
///
/// Routes the sealed-sender envelope to all of the recipient's devices.
/// Returns the server_guids assigned to each device's copy.
pub async fn send_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(registration_id): Path<u32>,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, VeilRelayError> {
    // Verify anonymous token (prevents spam without revealing sender)
    let token_header = headers
        .get("x-veil-token")
        .and_then(|v| v.to_str().ok());
    anonymous_token::verify_token_header(&state.token_service, token_header).await?;

    let request = crate::proto::SendMessageRequest::decode(body.as_ref())
        .map_err(|e| VeilRelayError::InvalidRequest(e.to_string()))?;

    let veil_envelope = request
        .envelope
        .ok_or(VeilRelayError::InvalidRequest("missing envelope".into()))?;

    // Route to all recipient devices via sealed sender handler
    let delivery_results = envelope::route_to_all_devices(
        &state.storage.messages,
        &state.storage.accounts,
        registration_id,
        &veil_envelope,
    )?;

    // Build response
    let response = crate::proto::SendMessageResponse {
        delivery_results: delivery_results
            .into_iter()
            .map(|(device_id, server_guid)| crate::proto::DeliveryResult {
                device_id,
                server_guid,
            })
            .collect(),
    };

    let response_bytes = response.encode_to_vec();

    Ok((
        StatusCode::OK,
        [("content-type", "application/x-protobuf")],
        response_bytes,
    ))
}

/// Query parameters for message retrieval.
#[derive(Deserialize)]
pub struct RetrieveQuery {
    pub registration_id: u32,
    pub device_id: u32,
}

/// GET /v1/messages?registration_id=X&device_id=Y
///
/// Response body: RetrieveMessagesResponse (protobuf)
/// Header: X-Veil-Token (anonymous token)
///
/// Returns all pending messages for the specified device.
/// Includes replenishment tokens if the client submitted blinded tokens.
///
/// Messages are NOT deleted — the client must acknowledge each one.
pub async fn retrieve_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<RetrieveQuery>,
) -> Result<impl IntoResponse, VeilRelayError> {
    // Verify anonymous token
    let token_header = headers
        .get("x-veil-token")
        .and_then(|v| v.to_str().ok());
    anonymous_token::verify_token_header(&state.token_service, token_header).await?;

    // Retrieve pending messages
    let envelopes = state
        .storage
        .messages
        .retrieve(params.registration_id, params.device_id)?;

    // Check for replenishment request (blinded tokens in header)
    let replenishment_tokens = if let Some(blinded_header) =
        headers.get("x-veil-blinded-tokens")
    {
        if let Ok(blinded_hex) = blinded_header.to_str() {
            // Parse comma-separated hex-encoded blinded tokens
            let blinded: Vec<BlindedToken> = blinded_hex
                .split(',')
                .filter_map(|hex_str| {
                    hex::decode(hex_str.trim()).ok().map(|point| BlindedToken { point })
                })
                .collect();

            if !blinded.is_empty() {
                state
                    .token_service
                    .issue_replenishment(&blinded, 100)?
                    .into_iter()
                    .map(|st| crate::proto::SignedBlindedToken { point: st.point })
                    .collect()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let response = crate::proto::RetrieveMessagesResponse {
        envelopes,
        replenishment_tokens,
    };

    let response_bytes = response.encode_to_vec();

    Ok((
        StatusCode::OK,
        [("content-type", "application/x-protobuf")],
        response_bytes,
    ))
}

/// DELETE /v1/messages/:server_guid
///
/// Header: X-Veil-Token (anonymous token)
/// Query: registration_id, device_id
///
/// Acknowledges receipt and permanently deletes the message.
/// This is the ONLY way messages leave the queue.
pub async fn acknowledge_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server_guid_hex): Path<String>,
    Query(params): Query<RetrieveQuery>,
) -> Result<impl IntoResponse, VeilRelayError> {
    // Verify anonymous token
    let token_header = headers
        .get("x-veil-token")
        .and_then(|v| v.to_str().ok());
    anonymous_token::verify_token_header(&state.token_service, token_header).await?;

    let server_guid =
        hex::decode(&server_guid_hex).map_err(|_| VeilRelayError::InvalidRequest(
            "invalid server_guid hex".into(),
        ))?;

    state.storage.messages.acknowledge(
        params.registration_id,
        params.device_id,
        &server_guid,
    )?;

    Ok(StatusCode::NO_CONTENT)
}
