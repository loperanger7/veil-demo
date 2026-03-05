// TransactionBuilderTests.swift
// VEIL — MobileCoin Payment Integration Tests
//
// VEIL-403: Tests for transaction construction with ring signatures
// and Bulletproofs+ range proofs.

import XCTest
@testable import VeilCrypto

final class TransactionBuilderTests: XCTestCase {

    private var client: MobileCoinClient!
    private var builder: TransactionBuilder!
    private var keyPair: MobileCoinKeyPair!
    private var selfAddress: PublicSubaddress!
    private var recipientAddress: PublicSubaddress!

    override func setUp() async throws {
        client = MobileCoinClient(sdk: MockMobileCoinSDK())

        let selector = TXOSelector(feeCalculator: FixedFeeCalculator(fee: 1000))
        builder = TransactionBuilder(
            client: client,
            selector: selector,
            ringProvider: MockRingMemberProvider()
        )

        let identityKey = SecureBytes(bytes: Array(repeating: 0x42, count: 32))
        keyPair = try await MobileCoinKeyPair.derive(from: identityKey, client: client)

        let deriver = SubaddressDeriver(client: client)
        selfAddress = try await deriver.deriveSelfAddress(keyPair: keyPair)

        let peerKey = Data(repeating: 0x99, count: 32)
        recipientAddress = try await deriver.deriveRecipientAddress(
            peerIdentityPublicKey: peerKey
        )
    }

    // MARK: - Helpers

    private func makeTXO(amount: UInt64, index: Int = 0) -> UnspentTXO {
        UnspentTXO(
            txoPublicKey: Data(repeating: UInt8(index & 0xFF), count: 32),
            amount: amount,
            blockIndex: 100
        )
    }

    // MARK: - Build Transaction

    func testBuildTransactionProducesEnvelope() async throws {
        let txos = [makeTXO(amount: 10000, index: 0)]

        let envelope = try await builder.buildTransaction(
            amount: 5000,
            recipientAddress: recipientAddress,
            senderKeyPair: keyPair,
            senderAddress: selfAddress,
            availableTXOs: txos
        )

        XCTAssertFalse(envelope.serializedTransaction.isEmpty)
        XCTAssertEqual(envelope.txHash.count, 32)
        XCTAssertEqual(envelope.outputs.count, 2) // recipient + change
        XCTAssertEqual(envelope.paymentAmount, 5000)
        XCTAssertEqual(envelope.fee, 1000)
        XCTAssertEqual(envelope.changeAmount, 4000) // 10000 - 5000 - 1000
    }

    func testBuildTransactionValidatesSelf() async throws {
        let txos = [makeTXO(amount: 10000, index: 0)]

        let envelope = try await builder.buildTransaction(
            amount: 5000,
            recipientAddress: recipientAddress,
            senderKeyPair: keyPair,
            senderAddress: selfAddress,
            availableTXOs: txos
        )

        // Mock SDK validates version byte == 0x02
        let isValid = await client.validateTransaction(envelope.serializedTransaction)
        XCTAssertTrue(isValid, "Built transaction must pass self-validation.")
    }

    func testBuildTransactionWithMultipleInputs() async throws {
        let txos = [
            makeTXO(amount: 3000, index: 0),
            makeTXO(amount: 4000, index: 1),
            makeTXO(amount: 5000, index: 2),
        ]

        let envelope = try await builder.buildTransaction(
            amount: 8000,
            recipientAddress: recipientAddress,
            senderKeyPair: keyPair,
            senderAddress: selfAddress,
            availableTXOs: txos
        )

        XCTAssertEqual(envelope.paymentAmount, 8000)
        XCTAssertTrue(envelope.totalInputAmount >= 8000 + envelope.fee)
    }

    func testBuildTransactionInsufficientBalance() async {
        let txos = [makeTXO(amount: 100, index: 0)]

        do {
            _ = try await builder.buildTransaction(
                amount: 50000,
                recipientAddress: recipientAddress,
                senderKeyPair: keyPair,
                senderAddress: selfAddress,
                availableTXOs: txos
            )
            XCTFail("Should throw insufficientBalance.")
        } catch let error as MobileCoinError {
            if case .insufficientBalance = error {
                // Expected
            } else {
                XCTFail("Expected insufficientBalance, got \(error)")
            }
        }
    }

    // MARK: - Fee Estimation

    func testEstimateFee() throws {
        let txos = [makeTXO(amount: 10000, index: 0)]
        let fee = try builder.estimateFee(amount: 5000, availableTXOs: txos)
        XCTAssertEqual(fee, 1000, "Fee should match the fixed fee calculator.")
    }

    // MARK: - Transaction Size

    func testTransactionSizeUnderLimit() async throws {
        let txos = [makeTXO(amount: 100000, index: 0)]

        let envelope = try await builder.buildTransaction(
            amount: 50000,
            recipientAddress: recipientAddress,
            senderKeyPair: keyPair,
            senderAddress: selfAddress,
            availableTXOs: txos
        )

        XCTAssertLessThanOrEqual(
            envelope.transactionSize,
            MobileCoinConstants.maxTransactionSize,
            "Transaction must not exceed max size."
        )
    }

    // MARK: - Mock Ring Members

    func testMockRingMemberProviderGeneratesCorrectCount() async throws {
        let provider = MockRingMemberProvider()
        let txo = makeTXO(amount: 5000)

        let members = try await provider.getRingMembers(for: txo, ringSize: 11)

        XCTAssertEqual(members.count, 10, "Ring size 11 should yield 10 decoys.")
        for member in members {
            XCTAssertEqual(member.publicKey.count, 32)
            XCTAssertEqual(member.membershipProof.count, 32)
        }
    }

    func testMockRingMembersAreDeterministic() async throws {
        let provider = MockRingMemberProvider()
        let txo = makeTXO(amount: 5000)

        let members1 = try await provider.getRingMembers(for: txo, ringSize: 11)
        let members2 = try await provider.getRingMembers(for: txo, ringSize: 11)

        XCTAssertEqual(members1.map(\.publicKey), members2.map(\.publicKey),
                        "Same TXO must produce same ring members.")
    }
}
