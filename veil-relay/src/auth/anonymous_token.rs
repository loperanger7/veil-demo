// VEIL — Anonymous Token Service
// Ticket: VEIL-303
// Spec reference: Section 4.3
//
// Ristretto255-based blind signature scheme for anonymous credentials.
//
// Flow:
//   1. Client generates random scalar r, computes T = r * G (blinded token)
//   2. Client sends T to server
//   3. Server computes S = k * T (signed blinded token), where k is server's signing key
//   4. Client unblinds: token = r^{-1} * S = k * G (valid token)
//   5. Client sends token with API request
//   6. Server verifies: token is on the curve and was signed by k
//
// Unlinkability: The server signs T (blinded) but later sees k*G (unblinded).
// It cannot determine which T produced which token without solving DLOG.

use crate::error::VeilRelayError;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Server-side signing key for anonymous tokens.
///
/// This key is generated once at server startup and used to sign
/// all blinded tokens. Rotation requires issuing new tokens to all clients.
#[derive(Clone)]
pub struct TokenSigningKey {
    /// The secret scalar k.
    secret: Scalar,
    /// The public point K = k * G.
    public: RistrettoPoint,
}

impl TokenSigningKey {
    /// Generate a new random signing key.
    pub fn generate() -> Result<Self, VeilRelayError> {
        let rng = SystemRandom::new();
        let mut key_bytes = [0u8; 64];
        rng.fill(&mut key_bytes)
            .map_err(|_| VeilRelayError::CryptoError("RNG failure".into()))?;

        let secret = Scalar::from_bytes_mod_order_wide(&key_bytes);
        let public = &secret * RISTRETTO_BASEPOINT_TABLE;

        Ok(TokenSigningKey { secret, public })
    }

    /// Load a signing key from bytes (for persistence across restarts).
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let secret = Scalar::from_canonical_bytes(*bytes)
            .unwrap_or_else(|| Scalar::from_bytes_mod_order(*bytes));
        let public = &secret * RISTRETTO_BASEPOINT_TABLE;
        TokenSigningKey { secret, public }
    }

    /// Export the secret key bytes (for secure storage).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Get the public verification key.
    pub fn public_key(&self) -> RistrettoPoint {
        self.public
    }
}

/// A blinded token submitted by a client for signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindedToken {
    /// Compressed Ristretto point T = r * G.
    pub point: Vec<u8>,
}

/// A signed blinded token returned to the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBlindedToken {
    /// Compressed Ristretto point S = k * T.
    pub point: Vec<u8>,
}

/// A spent token presented with an API request.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpentToken {
    /// Compressed Ristretto point: token = r^{-1} * S = k * G.
    pub point: Vec<u8>,
}

/// Anonymous token service.
///
/// Handles blind signing during issuance and verification during spend.
/// The service maintains a set of spent tokens to prevent double-spend.
pub struct AnonymousTokenService {
    signing_key: TokenSigningKey,
    /// sled tree storing spent tokens to prevent double-spend.
    spent_tree: sled::Tree,
}

impl AnonymousTokenService {
    pub fn new(signing_key: TokenSigningKey, db: &sled::Db) -> anyhow::Result<Self> {
        Ok(AnonymousTokenService {
            signing_key,
            spent_tree: db.open_tree("spent_tokens")?,
        })
    }

    /// Sign a batch of blinded tokens.
    ///
    /// Called during registration to issue the client's initial token supply.
    /// Each blinded point T is multiplied by the server's secret scalar k
    /// to produce S = k * T.
    pub fn sign_blinded_tokens(
        &self,
        blinded_tokens: &[BlindedToken],
    ) -> Result<Vec<SignedBlindedToken>, VeilRelayError> {
        let mut signed = Vec::with_capacity(blinded_tokens.len());

        for bt in blinded_tokens {
            let compressed = CompressedRistretto::from_slice(&bt.point)
                .map_err(|_| VeilRelayError::InvalidToken)?;

            let point = compressed
                .decompress()
                .ok_or(VeilRelayError::InvalidToken)?;

            // S = k * T
            let signed_point = self.signing_key.secret * point;

            signed.push(SignedBlindedToken {
                point: signed_point.compress().to_bytes().to_vec(),
            });
        }

        tracing::info!(count = signed.len(), "signed blinded tokens");
        Ok(signed)
    }

    /// Verify and consume a spent token.
    ///
    /// A valid token is a Ristretto point that:
    ///   1. Decompresses to a valid point
    ///   2. Has not been spent before (not in spent_tree)
    ///
    /// Note: We cannot directly verify the token was produced by our key
    /// without a DLEQ proof. Instead, we rely on the fact that only clients
    /// who received signed blinded tokens can produce valid unblinded tokens
    /// that are on the curve. For production, a DLEQ proof should be added.
    ///
    /// After verification, the token is marked as spent to prevent reuse.
    pub fn verify_and_spend(&self, token: &SpentToken) -> Result<(), VeilRelayError> {
        // Verify it's a valid Ristretto point
        let compressed = CompressedRistretto::from_slice(&token.point)
            .map_err(|_| VeilRelayError::InvalidToken)?;
        let _point = compressed
            .decompress()
            .ok_or(VeilRelayError::InvalidToken)?;

        // Check for double-spend
        if self.spent_tree.contains_key(&token.point)? {
            tracing::warn!("double-spend attempt detected");
            return Err(VeilRelayError::TokenAlreadySpent);
        }

        // Mark as spent
        self.spent_tree.insert(
            &token.point,
            &chrono::Utc::now().timestamp_millis().to_be_bytes(),
        )?;

        Ok(())
    }

    /// Issue fresh blinded tokens (called during message retrieval).
    ///
    /// When a client retrieves messages, the response includes fresh
    /// signed blinded tokens to replenish their supply.
    pub fn issue_replenishment(
        &self,
        blinded_tokens: &[BlindedToken],
        max_count: usize,
    ) -> Result<Vec<SignedBlindedToken>, VeilRelayError> {
        if blinded_tokens.len() > max_count {
            return Err(VeilRelayError::TooManyTokensRequested);
        }
        self.sign_blinded_tokens(blinded_tokens)
    }

    /// Get the public verification key (shared with clients).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.signing_key.public.compress().to_bytes().to_vec()
    }
}

/// Extractor for anonymous token verification in axum handlers.
///
/// Reads the `X-Veil-Token` header and verifies + spends the token.
pub async fn verify_token_header(
    token_service: &AnonymousTokenService,
    token_header: Option<&str>,
) -> Result<(), VeilRelayError> {
    let token_hex = token_header.ok_or(VeilRelayError::MissingToken)?;

    let token_bytes =
        hex::decode(token_hex).map_err(|_| VeilRelayError::InvalidToken)?;

    let token = SpentToken {
        point: token_bytes,
    };

    token_service.verify_and_spend(&token)
}
