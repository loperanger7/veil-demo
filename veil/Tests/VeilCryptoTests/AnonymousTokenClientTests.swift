// VEIL — Anonymous Token Client Tests
// Ticket: VEIL-303
//
// Tests for the client-side blind signing protocol.
//
// Dijkstra-style invariants:
//   - Blinding factors are unique across tokens
//   - Blinded tokens have correct size (32 bytes compressed Ristretto)
//   - Unblinding requires matching count of signed tokens and contexts
//   - Spent tokens are 32 bytes and hex-encodable
//   - Token store tracks balance correctly

import XCTest
@testable import VeilCrypto

final class AnonymousTokenClientTests: XCTestCase {

    // ── Test: Blinded token generation produces correct count ──

    func testBlindedTokenGenerationCount() throws {
        let client = AnonymousTokenClient()
        let contexts = try client.generateBlindedTokens(count: 50)

        XCTAssertEqual(contexts.count, 50)
    }

    // ── Test: Blinded tokens are 32 bytes ──

    func testBlindedTokensAre32Bytes() throws {
        let client = AnonymousTokenClient()
        let contexts = try client.generateBlindedTokens(count: 10)

        for context in contexts {
            XCTAssertEqual(context.blindedToken.point.count, 32,
                           "blinded token must be 32 bytes (SHA-256 of scalar)")
        }
    }

    // ── Test: All blinded tokens are unique ──

    func testBlindedTokensAreUnique() throws {
        let client = AnonymousTokenClient()
        let contexts = try client.generateBlindedTokens(count: 100)

        var seen = Set<Data>()
        for context in contexts {
            let (inserted, _) = seen.insert(context.blindedToken.point)
            XCTAssertTrue(inserted, "each blinded token must be unique")
        }
    }

    // ── Test: Prepare token request returns matching wire tokens and contexts ──

    func testPrepareTokenRequest() throws {
        let client = AnonymousTokenClient()
        let (wireTokens, contexts) = try client.prepareTokenRequest(count: 25)

        XCTAssertEqual(wireTokens.count, 25)
        XCTAssertEqual(contexts.count, 25)

        // Wire tokens should match the contexts' blinded tokens
        for (wire, context) in zip(wireTokens, contexts) {
            XCTAssertEqual(wire.point, context.blindedToken.point)
        }
    }

    // ── Test: Unblinding requires matching count ──

    func testUnblindingRequiresMatchingCount() throws {
        let client = AnonymousTokenClient()
        let contexts = try client.generateBlindedTokens(count: 5)

        // Provide wrong number of signed tokens
        let wrongCount = [
            WireSignedBlindedToken(point: Data(repeating: 0xAA, count: 32)),
            WireSignedBlindedToken(point: Data(repeating: 0xBB, count: 32)),
        ]

        XCTAssertThrowsError(
            try client.unblindTokens(signedBlindedTokens: wrongCount, contexts: contexts),
            "unblinding with mismatched count must throw"
        )
    }

    // ── Test: Unblinded tokens are 32 bytes ──

    func testUnblindedTokensAre32Bytes() throws {
        let client = AnonymousTokenClient()
        let contexts = try client.generateBlindedTokens(count: 10)

        // Mock server response: signed blinded tokens
        let signedTokens = contexts.map { _ in
            WireSignedBlindedToken(point: Data(repeating: 0xCC, count: 32))
        }

        let spentTokens = try client.unblindTokens(
            signedBlindedTokens: signedTokens,
            contexts: contexts
        )

        XCTAssertEqual(spentTokens.count, 10)
        for token in spentTokens {
            XCTAssertEqual(token.point.count, 32,
                           "unblinded token must be 32 bytes")
        }
    }

    // ── Test: Spent token hex encoding ──

    func testSpentTokenHexEncoding() {
        let token = WireSpentToken(point: Data([0x01, 0x02, 0x0A, 0xFF]))
        XCTAssertEqual(token.hexEncoded, "01020aff")
    }

    // ── Test: Token store balance tracking ──

    func testTokenStoreBalance() async {
        let store = TokenStore(maxTokenCount: 100)

        // Initially depleted
        let initialState = await store.balanceState
        XCTAssertEqual(initialState, .depleted)

        // Add tokens
        let tokens = (0..<100).map { i in
            WireSpentToken(point: Data(repeating: UInt8(i), count: 32))
        }
        await store.addTokens(tokens)

        let healthyState = await store.balanceState
        XCTAssertEqual(healthyState, .healthy)
        XCTAssertEqual(await store.tokenCount, 100)

        // Consume tokens until low
        for _ in 0..<81 {
            let _ = await store.consumeToken()
        }

        let lowState = await store.balanceState
        XCTAssertEqual(lowState, .low)
        XCTAssertTrue(await store.needsReplenishment)

        // Consume remaining
        for _ in 0..<19 {
            let _ = await store.consumeToken()
        }

        let depletedState = await store.balanceState
        XCTAssertEqual(depletedState, .depleted)
        XCTAssertNil(await store.consumeToken(),
                     "consuming from empty store must return nil")
    }

    // ── Test: Token store replenishment count ──

    func testTokenStoreReplenishmentCount() async {
        let store = TokenStore(maxTokenCount: 100)

        // Empty store: need all 100
        XCTAssertEqual(await store.replenishmentCount, 100)

        // Add 50 tokens
        let tokens = (0..<50).map { i in
            WireSpentToken(point: Data(repeating: UInt8(i), count: 32))
        }
        await store.addTokens(tokens)

        // Need 50 more to reach max
        XCTAssertEqual(await store.replenishmentCount, 50)
    }

    // ── Test: Token store deletion ──

    func testTokenStoreDeletion() async {
        let store = TokenStore(maxTokenCount: 100)

        let tokens = [WireSpentToken(point: Data(repeating: 0xAA, count: 32))]
        await store.addTokens(tokens)

        XCTAssertEqual(await store.tokenCount, 1)

        await store.deleteAll()

        XCTAssertEqual(await store.tokenCount, 0)
        XCTAssertEqual(await store.balanceState, .depleted)
    }
}

// MARK: - TokenBalanceState Equatable

extension TokenBalanceState: Equatable {
    public static func == (lhs: TokenBalanceState, rhs: TokenBalanceState) -> Bool {
        switch (lhs, rhs) {
        case (.healthy, .healthy): return true
        case (.low, .low): return true
        case (.depleted, .depleted): return true
        default: return false
        }
    }
}
