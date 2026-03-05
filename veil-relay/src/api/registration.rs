// VEIL — Device Registration Handler
// Ticket: VEIL-301
// Spec reference: Section 2.1
//
// Registers a new device and issues initial anonymous tokens.
// The server assigns a unique registration_id but stores no
// identifying information about the client.

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
};
use prost::Message;

use crate::api::AppState;
use crate::auth::anonymous_token::BlindedToken;
use crate::error::VeilRelayError;

/// POST /v1/registration
///
/// Request body: RegistrationRequest (protobuf)
/// Response body: RegistrationResponse (protobuf)
///
/// Flow:
///   1. Parse registration request (contains blinded tokens for initial supply)
///   2. Create device record in account store
///   3. Sign the blinded tokens
///   4. Return registration_id + signed tokens
pub async fn register_device(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, VeilRelayError> {
    let request = crate::proto::RegistrationRequest::decode(body.as_ref())
        .map_err(|e| VeilRelayError::InvalidRequest(e.to_string()))?;

    // Validate
    if request.device_id == 0 {
        return Err(VeilRelayError::InvalidRequest(
            "device_id must be non-zero".into(),
        ));
    }

    // Create device record
    let registration_id = state.storage.accounts.register_device(
        request.device_id,
        request.identity_key.clone(),
    )?;

    // Sign blinded tokens for the client's initial supply
    let blinded_tokens: Vec<BlindedToken> = request
        .blinded_tokens
        .iter()
        .map(|bt| BlindedToken {
            point: bt.point.clone(),
        })
        .collect();

    let signed_tokens = state.token_service.sign_blinded_tokens(&blinded_tokens)?;

    // Build response
    let response = crate::proto::RegistrationResponse {
        registration_id,
        server_public_key: state.token_service.public_key_bytes(),
        signed_tokens: signed_tokens
            .into_iter()
            .map(|st| crate::proto::SignedBlindedToken {
                point: st.point,
            })
            .collect(),
    };

    let response_bytes = response.encode_to_vec();

    tracing::info!(
        registration_id,
        device_id = request.device_id,
        token_count = blinded_tokens.len(),
        "device registered"
    );

    Ok((
        StatusCode::CREATED,
        [("content-type", "application/x-protobuf")],
        response_bytes,
    ))
}
