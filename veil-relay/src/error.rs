// VEIL — Error Types
// Unified error handling for the Veil Relay Service.
//
// Design: errors never leak message content, sender identity, or internal
// storage details to the client. All error responses use opaque status codes.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

/// Top-level error type for the Veil Relay Service.
#[derive(Error, Debug)]
pub enum VeilRelayError {
    // ── Registration ──
    #[error("device registration failed")]
    RegistrationFailed,

    #[error("device not found")]
    DeviceNotFound,

    // ── Prekeys ──
    #[error("prekey bundle not found")]
    PrekeyBundleNotFound,

    #[error("no one-time prekeys available")]
    NoOneTimePrekeys,

    #[error("invalid prekey bundle")]
    InvalidPrekeyBundle,

    // ── Messages ──
    #[error("message queue full")]
    MessageQueueFull,

    #[error("message not found")]
    MessageNotFound,

    #[error("invalid envelope")]
    InvalidEnvelope,

    // ── Authentication ──
    #[error("invalid anonymous token")]
    InvalidToken,

    #[error("rate limit exceeded")]
    RateLimitExceeded,

    // ── Storage ──
    #[error("storage error")]
    StorageError(#[from] sled::Error),

    // ── Serialization ──
    #[error("serialization error")]
    SerializationError(String),

    // ── Internal ──
    #[error("internal server error")]
    Internal(#[from] anyhow::Error),
}

/// Convert errors into HTTP responses.
///
/// Security: error responses are deliberately vague to prevent
/// information leakage. The actual error details are logged server-side
/// with `tracing` but never sent to the client.
impl IntoResponse for VeilRelayError {
    fn into_response(self) -> Response {
        let status = match &self {
            VeilRelayError::DeviceNotFound => StatusCode::NOT_FOUND,
            VeilRelayError::PrekeyBundleNotFound => StatusCode::NOT_FOUND,
            VeilRelayError::NoOneTimePrekeys => StatusCode::GONE,
            VeilRelayError::MessageNotFound => StatusCode::NOT_FOUND,
            VeilRelayError::InvalidToken => StatusCode::UNAUTHORIZED,
            VeilRelayError::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            VeilRelayError::InvalidEnvelope
            | VeilRelayError::InvalidPrekeyBundle
            | VeilRelayError::RegistrationFailed => StatusCode::BAD_REQUEST,
            VeilRelayError::MessageQueueFull => StatusCode::SERVICE_UNAVAILABLE,
            VeilRelayError::StorageError(_)
            | VeilRelayError::SerializationError(_)
            | VeilRelayError::Internal(_) => {
                // Log internal errors but don't expose details
                tracing::error!(error = %self, "internal error");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };

        // Never include error details in the response body
        status.into_response()
    }
}
