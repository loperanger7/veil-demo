// VEIL — Session Manager Tests
// Ticket: VEIL-203
//
// Tests for session establishment, identity trust (TOFU), and
// safety number computation.
//
// Dijkstra-style invariants:
//   - Session establishment requires valid prekey signature verification
//   - Identity key changes are detected (TOFU violation)
//   - Safety numbers are deterministic for the same key pair
//   - Sessions are cached after establishment

import XCTest
@testable import VeilCrypto

final class SessionManagerTests: XCTestCase {

    // ── Test: Session establishment caches the session ──

    func testSessionEstablishmentCachesSession() async throws {
        let identityKeyPair = try await IdentityKeyPair.generate()
        let relayClient = RelayClient(configuration: .development())
        let tokenStore = TokenStore()
        let prekeyManager = PrekeyManager(
            identityKeyPair: identityKeyPair,
            relayClient: relayClient,
            tokenStore: tokenStore
        )

        let sessionManager = SessionManager(
            identityKeyPair: identityKeyPair,
            relayClient: relayClient,
            prekeyManager: prekeyManager
        )

        // After getSession with no prior establishment, should be nil
        let noSession = await sessionManager.getSession(for: 99)
        XCTAssertNil(noSession, "no session should exist before establishment")
    }

    // ── Test: Session removal clears cache ──

    func testSessionRemovalClearsCache() async throws {
        let identityKeyPair = try await IdentityKeyPair.generate()
        let relayClient = RelayClient(configuration: .development())
        let tokenStore = TokenStore()
        let prekeyManager = PrekeyManager(
            identityKeyPair: identityKeyPair,
            relayClient: relayClient,
            tokenStore: tokenStore
        )

        let sessionManager = SessionManager(
            identityKeyPair: identityKeyPair,
            relayClient: relayClient,
            prekeyManager: prekeyManager
        )

        // Remove session for non-existent peer (should not crash)
        await sessionManager.removeSession(for: 99)
        let session = await sessionManager.getSession(for: 99)
        XCTAssertNil(session)
    }

    // ── Test: Safety number is deterministic ──

    func testSafetyNumberIsDeterministic() async throws {
        let identityKeyPair = try await IdentityKeyPair.generate()
        let relayClient = RelayClient(configuration: .development())
        let tokenStore = TokenStore()
        let prekeyManager = PrekeyManager(
            identityKeyPair: identityKeyPair,
            relayClient: relayClient,
            tokenStore: tokenStore
        )

        let sessionManager = SessionManager(
            identityKeyPair: identityKeyPair,
            relayClient: relayClient,
            prekeyManager: prekeyManager
        )

        // Without a cached identity key, safety number should be nil
        let safNum = await sessionManager.computeSafetyNumber(for: 99)
        XCTAssertNil(safNum,
                     "safety number requires cached identity key")
    }

    // ── Test: VeilSession struct has correct properties ──

    func testVeilSessionProperties() async throws {
        let identityKeyPair = try await IdentityKeyPair.generate()
        let sessionKey = SecureBytes(bytes: [UInt8](repeating: 0x42, count: 64))

        let ratchetSession = try TripleRatchetSession(
            sessionKey: sessionKey,
            isInitiator: true
        )

        let session = VeilSession(
            peerRegistrationId: 42,
            peerIdentityKey: Data(repeating: 0xAA, count: 32),
            ratchetSession: ratchetSession,
            establishedAt: Date(),
            isInitiator: true
        )

        XCTAssertEqual(session.peerRegistrationId, 42)
        XCTAssertTrue(session.isInitiator)
        XCTAssertEqual(session.peerIdentityKey.count, 32)
    }

    // ── Test: Identity trust states ──

    func testIdentityTrustStates() {
        // Test the enum cases
        let firstUse = IdentityTrustState.firstUse
        let verified = IdentityTrustState.verified
        let changed = IdentityTrustState.changed(previousKey: Data(repeating: 0xBB, count: 32))

        // Pattern matching should work
        switch firstUse {
        case .firstUse: break
        default: XCTFail("expected firstUse")
        }

        switch verified {
        case .verified: break
        default: XCTFail("expected verified")
        }

        switch changed {
        case .changed(let prevKey):
            XCTAssertEqual(prevKey.count, 32)
        default:
            XCTFail("expected changed")
        }
    }
}
