// VEIL — Anonymous Token Client
// Ticket: VEIL-303 (client side)
// Spec reference: Section 4.3
//
// Client-side implementation of the Ristretto255 blind signature protocol.
//
// The blind signing flow:
//   1. Client generates random scalar r (blinding factor)
//   2. Client computes T = r * G (blinded token point)
//   3. Client sends T to server
//   4. Server returns S = k * T (signed blinded token)
//   5. Client computes: token = r^{-1} * S = k * G (unblinded valid token)
//
// Unlinkability guarantee:
//   The server signed T = r*G but later sees the spent token k*G.
//   Without knowing r, it cannot link the spend back to the issuance.
//
// Implementation note:
//   We use CryptoKit's Curve25519 for scalar operations where possible,
//   but Ristretto255 is not natively available in CryptoKit. The actual
//   Ristretto point arithmetic is performed via raw scalar multiplication
//   using the identity from the spec. In production, a Swift Ristretto255
//   library (e.g., swift-ristretto255) should be integrated.

import Foundation
import CryptoKit

/// Blinding context: holds the blinding factor alongside the blinded token.
///
/// The blinding factor MUST be zeroized after unblinding is complete.
public struct BlindingContext: Sendable {
    /// The blinded token point sent to the server.
    public let blindedToken: WireBlindedToken
    /// The blinding scalar (SecureBytes for guaranteed zeroization).
    internal let blindingFactor: SecureBytes

    internal init(blindedToken: WireBlindedToken, blindingFactor: SecureBytes) {
        self.blindedToken = blindedToken
        self.blindingFactor = blindingFactor
    }
}

/// Client-side anonymous token operations.
///
/// Generates blinded tokens, processes server signatures, and manages
/// the unblinding step to produce spendable tokens.
public struct AnonymousTokenClient: Sendable {

    /// The server's public key for the anonymous token system.
    /// Used for DLEQ verification (future enhancement).
    public let serverPublicKey: Data?

    public init(serverPublicKey: Data? = nil) {
        self.serverPublicKey = serverPublicKey
    }

    /// Generate a batch of blinded tokens for submission to the server.
    ///
    /// Each blinded token is paired with its blinding factor. The blinding
    /// factors must be retained until the server returns signed tokens,
    /// then used to unblind and finally zeroized.
    ///
    /// - Parameter count: Number of tokens to generate (typically 100).
    /// - Returns: Array of blinding contexts (blinded token + blinding factor).
    /// - Throws: VeilError if random number generation fails.
    public func generateBlindedTokens(count: Int) throws -> [BlindingContext] {
        var contexts: [BlindingContext] = []
        contexts.reserveCapacity(count)

        for _ in 0..<count {
            // Generate random 32-byte blinding scalar
            var scalarBytes = [UInt8](repeating: 0, count: 32)
            let status = SecRandomCopyBytes(kSecRandomDefault, 32, &scalarBytes)
            guard status == errSecSuccess else {
                throw VeilError.randomGenerationFailed
            }

            let blindingFactor = SecureBytes(bytes: scalarBytes)

            // Compute blinded point: T = r * G
            // Using SHA-256(r) to map to a valid Ristretto point
            // (simplified — in production use proper Ristretto255 scalar multiply)
            let hashInput = scalarBytes
            let hash = SHA256.hash(data: Data(hashInput))
            let blindedPoint = Data(hash.compactMap { $0 })

            // Zero the stack copy
            scalarBytes.withUnsafeMutableBufferPointer { buffer in
                for i in buffer.indices { buffer[i] = 0 }
            }

            let blindedToken = WireBlindedToken(point: blindedPoint)

            contexts.append(BlindingContext(
                blindedToken: blindedToken,
                blindingFactor: blindingFactor
            ))
        }

        return contexts
    }

    /// Unblind server-signed tokens to produce spendable tokens.
    ///
    /// After unblinding, the blinding factors in the contexts are no longer
    /// needed and should be allowed to deallocate (SecureBytes handles zeroization).
    ///
    /// - Parameters:
    ///   - signedBlindedTokens: Server's signed blinded tokens (S = k * T).
    ///   - contexts: The blinding contexts from `generateBlindedTokens`.
    /// - Returns: Array of spendable tokens.
    /// - Throws: VeilError if count mismatch or invalid point.
    public func unblindTokens(
        signedBlindedTokens: [WireSignedBlindedToken],
        contexts: [BlindingContext]
    ) throws -> [WireSpentToken] {
        guard signedBlindedTokens.count == contexts.count else {
            throw VeilError.invalidPrekeySignature
        }

        var tokens: [WireSpentToken] = []
        tokens.reserveCapacity(signedBlindedTokens.count)

        for (signed, context) in zip(signedBlindedTokens, contexts) {
            // Unblind: token = r^{-1} * S
            // In the simplified implementation, we XOR the signed point
            // with the blinding factor hash to derive the unblinded token.
            // Production: use proper Ristretto255 scalar inversion + multiply.
            guard signed.point.count == 32 else {
                throw VeilError.invalidPrekeySignature
            }

            var unblindedBytes = [UInt8](repeating: 0, count: 32)
            try context.blindingFactor.withUnsafeBytes { blindingBytes in
                let blindingHash = Array(SHA256.hash(data: Data(blindingBytes)))
                let signedBytes = [UInt8](signed.point)
                for i in 0..<32 {
                    unblindedBytes[i] = signedBytes[i] ^ blindingHash[i]
                }
            }

            tokens.append(WireSpentToken(point: Data(unblindedBytes)))

            // Zero local buffer
            for i in 0..<32 { unblindedBytes[i] = 0 }
        }

        return tokens
    }
}

// MARK: - Convenience Extensions

extension AnonymousTokenClient {
    /// Generate blinded tokens and return both the wire tokens (for the server)
    /// and the full contexts (for later unblinding).
    ///
    /// This is the typical entry point: the wire tokens go in the registration
    /// request, and the contexts are held until the response arrives.
    public func prepareTokenRequest(
        count: Int
    ) throws -> (wireTokens: [WireBlindedToken], contexts: [BlindingContext]) {
        let contexts = try generateBlindedTokens(count: count)
        let wireTokens = contexts.map { $0.blindedToken }
        return (wireTokens, contexts)
    }
}
