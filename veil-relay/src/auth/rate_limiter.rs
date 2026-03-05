// VEIL — Token-Based Rate Limiter
// Ticket: VEIL-303
// Spec reference: Section 4.3
//
// Rate limiting without identity linkage. Each state-mutating API call
// consumes one anonymous token. Clients receive tokens during registration
// and replenish them when retrieving messages.
//
// Unlike IP-based rate limiting, this approach:
//   - Does not reveal client IP to the rate limiter
//   - Cannot be circumvented by changing IPs
//   - Self-regulates: spammers exhaust tokens, honest users don't

use crate::auth::anonymous_token::AnonymousTokenService;
use crate::error::VeilRelayError;
use std::sync::Arc;

/// Token-based rate limiter.
///
/// Wraps the anonymous token service with rate-limiting policy decisions.
pub struct TokenRateLimiter {
    token_service: Arc<AnonymousTokenService>,
    /// Maximum tokens issued per registration.
    initial_token_count: usize,
    /// Maximum tokens issued per replenishment.
    replenishment_count: usize,
}

impl TokenRateLimiter {
    pub fn new(
        token_service: Arc<AnonymousTokenService>,
        initial_token_count: usize,
        replenishment_count: usize,
    ) -> Self {
        TokenRateLimiter {
            token_service,
            initial_token_count,
            replenishment_count,
        }
    }

    /// Verify a token for a state-mutating request.
    ///
    /// Consumes the token (marks it spent). Returns error if:
    ///   - Token is missing or malformed
    ///   - Token has already been spent (double-spend)
    pub fn consume_token(&self, token_hex: Option<&str>) -> Result<(), VeilRelayError> {
        let token_hex = token_hex.ok_or(VeilRelayError::MissingToken)?;

        let token_bytes =
            hex::decode(token_hex).map_err(|_| VeilRelayError::InvalidToken)?;

        let token = crate::auth::anonymous_token::SpentToken {
            point: token_bytes,
        };

        self.token_service.verify_and_spend(&token)
    }

    /// Get the number of tokens to issue during registration.
    pub fn initial_token_count(&self) -> usize {
        self.initial_token_count
    }

    /// Get the number of tokens to issue during replenishment.
    pub fn replenishment_count(&self) -> usize {
        self.replenishment_count
    }
}
