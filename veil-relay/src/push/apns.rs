// VEIL — Apple Push Notification Service Client
// Ticket: VEIL-304
// Spec reference: Section 2.4
//
// HTTP/2 client for Apple's APNs using token-based (.p8) authentication.
//
// Privacy invariants:
//   - Push payload: ONLY { "aps": { "content-available": 1 } }
//   - NO alert text, NO badge count, NO sound
//   - NO sender information, NO message preview
//   - The push merely wakes the app to fetch messages over the encrypted channel
//
// Apple's APNs requires:
//   - HTTP/2 with TLS
//   - JWT bearer token signed with ES256 (from .p8 key)
//   - Topic = app bundle ID

use crate::error::VeilRelayError;
use crate::storage::accounts::AccountStore;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::Serialize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// APNs environment endpoints.
#[derive(Debug, Clone)]
pub enum ApnsEnvironment {
    /// Production: api.push.apple.com
    Production,
    /// Sandbox: api.sandbox.push.apple.com
    Sandbox,
}

impl ApnsEnvironment {
    pub fn base_url(&self) -> &str {
        match self {
            ApnsEnvironment::Production => "https://api.push.apple.com",
            ApnsEnvironment::Sandbox => "https://api.sandbox.push.apple.com",
        }
    }
}

/// Configuration for APNs authentication.
#[derive(Clone)]
pub struct ApnsConfig {
    /// The .p8 key file contents (PEM-encoded ES256 private key).
    pub key_bytes: Vec<u8>,
    /// Key ID from Apple Developer portal.
    pub key_id: String,
    /// Team ID from Apple Developer portal.
    pub team_id: String,
    /// App bundle identifier (used as APNs topic).
    pub bundle_id: String,
    /// APNs environment.
    pub environment: ApnsEnvironment,
}

/// APNs push notification client.
///
/// Sends silent push notifications to wake up client apps.
pub struct ApnsClient {
    config: ApnsConfig,
    http_client: reqwest::Client,
}

/// The minimal APNs payload — zero-knowledge silent notification.
#[derive(Serialize)]
struct ApnsPayload {
    aps: ApsSilent,
}

#[derive(Serialize)]
struct ApsSilent {
    #[serde(rename = "content-available")]
    content_available: u8,
}

impl ApnsPayload {
    /// The only payload we ever send: silent wake-up.
    fn silent() -> Self {
        ApnsPayload {
            aps: ApsSilent {
                content_available: 1,
            },
        }
    }
}

/// JWT header for APNs token authentication.
#[derive(Serialize)]
struct JwtHeader {
    alg: String,
    kid: String,
}

/// JWT claims for APNs.
#[derive(Serialize)]
struct JwtClaims {
    iss: String,
    iat: u64,
}

impl ApnsClient {
    /// Create a new APNs client.
    ///
    /// The HTTP client is configured for HTTP/2 (Apple's requirement).
    pub fn new(config: ApnsConfig) -> Result<Self, VeilRelayError> {
        let http_client = reqwest::Client::builder()
            .http2_prior_knowledge()
            .build()
            .map_err(|e| VeilRelayError::PushError(e.to_string()))?;

        Ok(ApnsClient {
            config,
            http_client,
        })
    }

    /// Send a silent push notification to a specific device token.
    ///
    /// Returns Ok(()) on success, or an error if the push fails.
    /// APNs errors (e.g., invalid token) are logged but do not
    /// prevent message delivery — push is best-effort.
    pub async fn send_silent_push(
        &self,
        device_token: &str,
    ) -> Result<(), VeilRelayError> {
        let url = format!(
            "{}/3/device/{}",
            self.config.environment.base_url(),
            device_token
        );

        let jwt = self.generate_jwt()?;
        let payload = serde_json::to_vec(&ApnsPayload::silent())
            .map_err(|e| VeilRelayError::PushError(e.to_string()))?;

        let response = self
            .http_client
            .post(&url)
            .header("authorization", format!("bearer {}", jwt))
            .header("apns-topic", &self.config.bundle_id)
            .header("apns-push-type", "background")
            .header("apns-priority", "5") // Low priority (silent)
            .body(payload)
            .send()
            .await
            .map_err(|e| VeilRelayError::PushError(e.to_string()))?;

        if response.status().is_success() {
            tracing::debug!(device_token, "silent push sent");
            Ok(())
        } else {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "unknown".into());
            tracing::warn!(
                device_token,
                status = %status,
                body = %body,
                "APNs push failed"
            );
            Err(VeilRelayError::PushError(format!(
                "APNs returned {}: {}",
                status, body
            )))
        }
    }

    /// Notify all devices for a given registration_id.
    ///
    /// Best-effort: individual push failures are logged but don't
    /// prevent other devices from being notified.
    pub async fn notify_all_devices(
        &self,
        account_store: &AccountStore,
        registration_id: u32,
    ) -> Result<(), VeilRelayError> {
        let devices = account_store.get_all_devices(registration_id)?;

        for device in &devices {
            if let Some(ref apns_token) = device.apns_token {
                if let Err(e) = self.send_silent_push(apns_token).await {
                    tracing::warn!(
                        registration_id,
                        device_id = device.device_id,
                        error = %e,
                        "push notification failed for device"
                    );
                    // Continue to next device — don't fail the whole batch
                }
            }
        }

        Ok(())
    }

    /// Generate a JWT for APNs token authentication.
    ///
    /// Apple requires:
    ///   - Header: { "alg": "ES256", "kid": "<key_id>" }
    ///   - Claims: { "iss": "<team_id>", "iat": <timestamp> }
    ///   - Signed with the .p8 private key
    fn generate_jwt(&self) -> Result<String, VeilRelayError> {
        let header = JwtHeader {
            alg: "ES256".to_string(),
            kid: self.config.key_id.clone(),
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| VeilRelayError::PushError(e.to_string()))?;

        let claims = JwtClaims {
            iss: self.config.team_id.clone(),
            iat: now.as_secs(),
        };

        let header_b64 = base64_url_encode(
            &serde_json::to_vec(&header)
                .map_err(|e| VeilRelayError::PushError(e.to_string()))?,
        );
        let claims_b64 = base64_url_encode(
            &serde_json::to_vec(&claims)
                .map_err(|e| VeilRelayError::PushError(e.to_string()))?,
        );

        let signing_input = format!("{}.{}", header_b64, claims_b64);

        // Sign with ES256
        let key_pair = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &self.config.key_bytes,
            &ring::rand::SystemRandom::new(),
        )
        .map_err(|e| VeilRelayError::PushError(format!("invalid .p8 key: {}", e)))?;

        let signature = key_pair
            .sign(
                &ring::rand::SystemRandom::new(),
                signing_input.as_bytes(),
            )
            .map_err(|e| VeilRelayError::PushError(format!("signing failed: {}", e)))?;

        let signature_b64 = base64_url_encode(signature.as_ref());

        Ok(format!("{}.{}", signing_input, signature_b64))
    }
}

/// Base64url encoding without padding (per JWT spec).
fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}
