// VEIL — Prekey Bundle Handlers
// Ticket: VEIL-301
// Spec reference: Section 2.1, 3.2
//
// Upload and fetch prekey bundles.
//
// Upload: Client sends their full prekey bundle (identity key, signed prekey,
// one-time prekeys, optional post-quantum KEM key). Requires anonymous token.
//
// Fetch: Anyone can fetch a prekey bundle to initiate a PQXDH handshake.
// One one-time prekey is consumed atomically per fetch. No token required
// (needed for first-contact scenarios).

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use prost::Message;

use crate::api::AppState;
use crate::auth::anonymous_token;
use crate::error::VeilRelayError;

/// PUT /v1/keys
///
/// Request body: PrekeyUploadRequest (protobuf)
/// Header: X-Veil-Token (anonymous token)
///
/// Stores the client's prekey bundle. Overwrites any existing bundle
/// for the same registration_id.
pub async fn upload_prekeys(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, VeilRelayError> {
    // Verify anonymous token
    let token_header = headers
        .get("x-veil-token")
        .and_then(|v| v.to_str().ok());
    anonymous_token::verify_token_header(&state.token_service, token_header).await?;

    let request = crate::proto::PrekeyUploadRequest::decode(body.as_ref())
        .map_err(|e| VeilRelayError::InvalidRequest(e.to_string()))?;

    // Validate
    if request.registration_id == 0 {
        return Err(VeilRelayError::InvalidRequest(
            "registration_id must be non-zero".into(),
        ));
    }

    let bundle = request
        .bundle
        .ok_or(VeilRelayError::InvalidRequest("missing prekey bundle".into()))?;

    // Store the bundle
    state
        .storage
        .prekeys
        .store_bundle(request.registration_id, &bundle)?;

    tracing::info!(
        registration_id = request.registration_id,
        otp_count = bundle.one_time_prekeys.len(),
        has_pq_key = bundle.pq_kem_public_key.is_some(),
        "prekey bundle uploaded"
    );

    Ok(StatusCode::NO_CONTENT)
}

/// GET /v1/keys/:registration_id
///
/// Response body: PrekeyFetchResponse (protobuf)
///
/// Returns the recipient's prekey bundle with one OTP consumed atomically.
/// No authentication required — anyone needs to be able to fetch prekeys
/// to initiate a conversation.
pub async fn fetch_prekeys(
    State(state): State<AppState>,
    Path(registration_id): Path<u32>,
) -> Result<impl IntoResponse, VeilRelayError> {
    let bundle = state
        .storage
        .prekeys
        .fetch_bundle(registration_id)?
        .ok_or(VeilRelayError::PrekeyBundleNotFound)?;

    let response = crate::proto::PrekeyFetchResponse {
        registration_id,
        bundle: Some(bundle),
    };

    let response_bytes = response.encode_to_vec();

    tracing::info!(
        registration_id,
        "prekey bundle fetched"
    );

    Ok((
        StatusCode::OK,
        [("content-type", "application/x-protobuf")],
        response_bytes,
    ))
}
