// VEIL — Auth Module
// Tickets: VEIL-303 (Anonymous Credentials)
// Spec reference: Section 4.3
//
// Anonymous credential system using Ristretto255 blind signatures.
// The server can verify that a token was issued by it, but cannot
// link a spent token back to the registration that received it.

pub mod anonymous_token;
pub mod rate_limiter;
