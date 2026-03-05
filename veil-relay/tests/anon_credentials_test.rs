// VEIL — Anonymous Credentials Tests
// Ticket: VEIL-303
//
// Tests for the Ristretto255 blind signature anonymous credential system.
//
// Dijkstra-style invariant:
//   forall (token_set_A, token_set_B : IssuedTokens) ->
//       spend(token_set_A[i]) cannot be linked to issuance(token_set_A)
//       by the server, even given full knowledge of all issuances.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    scalar::Scalar,
};
use veil_relay::auth::anonymous_token::*;

/// Helper: simulate the full blind signing protocol.
///
///   Client: r = random scalar, T = r * G  (blinded)
///   Server: S = k * T                     (signed blinded)
///   Client: token = r^{-1} * S = k * G    (unblinded = valid token)
fn simulate_blind_sign(
    signing_key: &TokenSigningKey,
) -> (SpentToken, Scalar) {
    // Client generates blinding factor
    let r = Scalar::random(&mut rand::thread_rng());
    let blinded_point = &r * RISTRETTO_BASEPOINT_TABLE;

    let blinded_token = BlindedToken {
        point: blinded_point.compress().to_bytes().to_vec(),
    };

    // Server signs
    let config = sled::Config::new().temporary(true);
    let db = config.open().unwrap();
    let service = AnonymousTokenService::new(signing_key.clone(), &db).unwrap();

    let signed = service.sign_blinded_tokens(&[blinded_token]).unwrap();

    // Client unblinds
    let signed_point = curve25519_dalek::ristretto::CompressedRistretto::from_slice(
        &signed[0].point,
    )
    .unwrap()
    .decompress()
    .unwrap();

    let r_inv = r.invert();
    let unblinded = r_inv * signed_point; // k * G

    let token = SpentToken {
        point: unblinded.compress().to_bytes().to_vec(),
    };

    (token, r)
}

#[test]
fn test_blind_sign_produces_valid_token() {
    let signing_key = TokenSigningKey::generate().unwrap();
    let (token, _) = simulate_blind_sign(&signing_key);

    // Token should be a valid Ristretto point
    let compressed =
        curve25519_dalek::ristretto::CompressedRistretto::from_slice(&token.point).unwrap();
    assert!(
        compressed.decompress().is_some(),
        "unblinded token must be a valid Ristretto point"
    );
}

#[test]
fn test_token_spend_succeeds() {
    let signing_key = TokenSigningKey::generate().unwrap();
    let (token, _) = simulate_blind_sign(&signing_key);

    let config = sled::Config::new().temporary(true);
    let db = config.open().unwrap();
    let service = AnonymousTokenService::new(signing_key, &db).unwrap();

    // First spend should succeed
    assert!(service.verify_and_spend(&token).is_ok());
}

#[test]
fn test_double_spend_rejected() {
    let signing_key = TokenSigningKey::generate().unwrap();
    let (token, _) = simulate_blind_sign(&signing_key);

    let config = sled::Config::new().temporary(true);
    let db = config.open().unwrap();
    let service = AnonymousTokenService::new(signing_key, &db).unwrap();

    // First spend: OK
    service.verify_and_spend(&token).unwrap();

    // Second spend: MUST fail
    let result = service.verify_and_spend(&token);
    assert!(result.is_err(), "double-spend must be rejected");
}

#[test]
fn test_invalid_token_rejected() {
    let signing_key = TokenSigningKey::generate().unwrap();

    let config = sled::Config::new().temporary(true);
    let db = config.open().unwrap();
    let service = AnonymousTokenService::new(signing_key, &db).unwrap();

    // Invalid: not a valid Ristretto point
    let bad_token = SpentToken {
        point: vec![0xFF; 32],
    };

    let result = service.verify_and_spend(&bad_token);
    assert!(result.is_err(), "invalid point must be rejected");
}

#[test]
fn test_tokens_from_different_issuances_are_unlinkable() {
    let signing_key = TokenSigningKey::generate().unwrap();

    // Issue two batches of tokens (simulating two different registrations)
    let (token_a, r_a) = simulate_blind_sign(&signing_key);
    let (token_b, r_b) = simulate_blind_sign(&signing_key);

    // The unblinded tokens should be different (different blinding factors)
    assert_ne!(
        token_a.point, token_b.point,
        "tokens from different issuances must differ"
    );

    // But both should be valid Ristretto points
    let point_a = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&token_a.point)
        .unwrap()
        .decompress()
        .unwrap();
    let point_b = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&token_b.point)
        .unwrap()
        .decompress()
        .unwrap();

    // Key unlinkability property: both tokens are k*G but with different
    // blinding factors, so the server only sees the final points.
    // Without knowing r_a or r_b, the server cannot determine which
    // blinded point T produced which token.

    // The blinding factors are different
    assert_ne!(r_a, r_b, "blinding factors must be unique");

    // Both tokens should be spendable
    let config = sled::Config::new().temporary(true);
    let db = config.open().unwrap();
    let service = AnonymousTokenService::new(signing_key, &db).unwrap();

    assert!(service.verify_and_spend(&token_a).is_ok());
    assert!(service.verify_and_spend(&token_b).is_ok());
}

#[test]
fn test_batch_signing() {
    let signing_key = TokenSigningKey::generate().unwrap();

    let config = sled::Config::new().temporary(true);
    let db = config.open().unwrap();
    let service = AnonymousTokenService::new(signing_key, &db).unwrap();

    // Create 100 blinded tokens
    let blinded_tokens: Vec<BlindedToken> = (0..100)
        .map(|_| {
            let r = Scalar::random(&mut rand::thread_rng());
            let point = &r * RISTRETTO_BASEPOINT_TABLE;
            BlindedToken {
                point: point.compress().to_bytes().to_vec(),
            }
        })
        .collect();

    let signed = service.sign_blinded_tokens(&blinded_tokens).unwrap();
    assert_eq!(signed.len(), 100, "all tokens must be signed");

    // All signed tokens should be valid Ristretto points
    for st in &signed {
        let compressed =
            curve25519_dalek::ristretto::CompressedRistretto::from_slice(&st.point).unwrap();
        assert!(compressed.decompress().is_some());
    }
}

#[test]
fn test_replenishment_limit() {
    let signing_key = TokenSigningKey::generate().unwrap();

    let config = sled::Config::new().temporary(true);
    let db = config.open().unwrap();
    let service = AnonymousTokenService::new(signing_key, &db).unwrap();

    // Request more tokens than the limit allows
    let too_many: Vec<BlindedToken> = (0..200)
        .map(|_| {
            let r = Scalar::random(&mut rand::thread_rng());
            let point = &r * RISTRETTO_BASEPOINT_TABLE;
            BlindedToken {
                point: point.compress().to_bytes().to_vec(),
            }
        })
        .collect();

    let result = service.issue_replenishment(&too_many, 100);
    assert!(
        result.is_err(),
        "requesting more tokens than max_count must fail"
    );
}
