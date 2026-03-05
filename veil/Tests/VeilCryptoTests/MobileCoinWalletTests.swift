// MobileCoinWalletTests.swift
// VEIL — MobileCoin Payment Integration Tests
//
// Integration tests for the MobileCoinWallet orchestrator,
// covering receipt handling, TXO detection, and type round-trips.

import XCTest
@testable import VeilCrypto

final class MobileCoinWalletTests: XCTestCase {

    private var client: MobileCoinClient!

    override func setUp() async throws {
        client = MobileCoinClient(sdk: MockMobileCoinSDK())
    }

    // MARK: - PaymentReceiptMessage

    func testReceiptEncodeDecode() throws {
        let receipt = PaymentReceiptMessage(
            txHash: String(repeating: "ab", count: 32), // 64 hex chars
            sharedSecret: Data(repeating: 0x01, count: 32).base64EncodedString(),
            amountPicomob: 5_000_000_000_000,
            memo: "Coffee payment",
            receiptProof: Data(repeating: 0x02, count: 64).base64EncodedString(),
            blockIndex: 12345
        )

        let data = try receipt.encode()
        let decoded = try PaymentReceiptMessage.decode(from: data)

        XCTAssertEqual(decoded.txHash, receipt.txHash)
        XCTAssertEqual(decoded.amountPicomob, receipt.amountPicomob)
        XCTAssertEqual(decoded.memo, "Coffee payment")
        XCTAssertEqual(decoded.blockIndex, 12345)
    }

    func testReceiptValidation() {
        let validReceipt = PaymentReceiptMessage(
            txHash: String(repeating: "ab", count: 32),
            sharedSecret: Data(repeating: 0x01, count: 32).base64EncodedString(),
            amountPicomob: 1000,
            memo: "Valid",
            receiptProof: Data(repeating: 0x02, count: 32).base64EncodedString(),
            blockIndex: 1
        )
        XCTAssertTrue(validReceipt.isValid)

        // Zero amount
        let zeroAmount = PaymentReceiptMessage(
            txHash: String(repeating: "ab", count: 32),
            sharedSecret: Data(repeating: 0x01, count: 32).base64EncodedString(),
            amountPicomob: 0,
            receiptProof: "proof",
            blockIndex: 1
        )
        XCTAssertFalse(zeroAmount.isValid, "Zero amount should be invalid.")
    }

    func testReceiptMemoTruncation() {
        let longMemo = String(repeating: "a", count: 500)
        let receipt = PaymentReceiptMessage(
            txHash: String(repeating: "ab", count: 32),
            sharedSecret: Data(repeating: 0x01, count: 32).base64EncodedString(),
            amountPicomob: 1000,
            memo: longMemo,
            receiptProof: "proof",
            blockIndex: 1
        )

        XCTAssertEqual(receipt.memo.count, 256, "Memo should be truncated to 256 chars.")
    }

    func testReceiptAmountConversion() {
        let receipt = PaymentReceiptMessage(
            txHash: String(repeating: "ab", count: 32),
            sharedSecret: Data(repeating: 0x01, count: 32).base64EncodedString(),
            amountPicomob: 2_500_000_000_000, // 2.5 MOB
            receiptProof: "proof",
            blockIndex: 1
        )

        XCTAssertEqual(receipt.amountInMOB, 2.5, accuracy: 0.0001)
    }

    // MARK: - ReceiptEncryptor

    func testReceiptEncryptorPrepareAndParse() throws {
        let encryptor = ReceiptEncryptor()

        let receipt = PaymentReceiptMessage(
            txHash: String(repeating: "cd", count: 32),
            sharedSecret: Data(repeating: 0x03, count: 32).base64EncodedString(),
            amountPicomob: 1_000_000_000_000,
            memo: "Test",
            receiptProof: Data(repeating: 0x04, count: 32).base64EncodedString(),
            blockIndex: 500
        )

        let data = try encryptor.prepareForEncryption(receipt)
        let parsed = try encryptor.parseDecryptedReceipt(data)

        XCTAssertEqual(parsed.txHash, receipt.txHash)
        XCTAssertEqual(parsed.amountPicomob, receipt.amountPicomob)
        XCTAssertEqual(parsed.memo, "Test")
    }

    func testReceiptEncryptorRejectsInvalid() {
        let encryptor = ReceiptEncryptor()
        let invalidData = "not json".data(using: .utf8)!

        XCTAssertThrowsError(try encryptor.parseDecryptedReceipt(invalidData)) { error in
            XCTAssertEqual(error as? MobileCoinError, .receiptDecryptionFailed)
        }
    }

    // MARK: - TXO Detection

    func testTXODetectorFindsMatchingTXO() async {
        let detector = TXODetector(mobClient: client)
        let sharedSecret = Data(repeating: 0x05, count: 32)

        let receipt = PaymentReceiptMessage(
            txHash: String(repeating: "ee", count: 32),
            sharedSecret: sharedSecret.base64EncodedString(),
            amountPicomob: 1000,
            receiptProof: "proof",
            blockIndex: 100
        )

        let incomingTXOs = [
            IncomingTXO(
                txoPublicKey: Data(repeating: 0x10, count: 32),
                encryptedAmount: Data(repeating: 0x20, count: 16),
                sharedSecret: sharedSecret, // Matches!
                blockIndex: 100
            ),
            IncomingTXO(
                txoPublicKey: Data(repeating: 0x30, count: 32),
                encryptedAmount: Data(repeating: 0x40, count: 16),
                sharedSecret: Data(repeating: 0x99, count: 32), // Doesn't match
                blockIndex: 101
            ),
        ]

        let viewKey = SecureBytes(bytes: Array(repeating: 0x00, count: 32))
        let detected = await detector.findIncomingTXO(
            receipt: receipt,
            incomingTXOs: incomingTXOs,
            viewKey: viewKey
        )

        XCTAssertNotNil(detected, "Should find matching TXO by shared secret.")
        XCTAssertEqual(detected?.txoPublicKey, Data(repeating: 0x10, count: 32))
        XCTAssertEqual(detected?.receiptTxHash, String(repeating: "ee", count: 32))
    }

    func testTXODetectorReturnsNilForNoMatch() async {
        let detector = TXODetector(mobClient: client)

        let receipt = PaymentReceiptMessage(
            txHash: String(repeating: "ff", count: 32),
            sharedSecret: Data(repeating: 0x99, count: 32).base64EncodedString(),
            amountPicomob: 1000,
            receiptProof: "proof",
            blockIndex: 100
        )

        let incomingTXOs = [
            IncomingTXO(
                txoPublicKey: Data(repeating: 0x10, count: 32),
                encryptedAmount: Data(repeating: 0x20, count: 16),
                sharedSecret: Data(repeating: 0x01, count: 32), // Different
                blockIndex: 100
            ),
        ]

        let viewKey = SecureBytes(bytes: Array(repeating: 0x00, count: 32))
        let detected = await detector.findIncomingTXO(
            receipt: receipt,
            incomingTXOs: incomingTXOs,
            viewKey: viewKey
        )

        XCTAssertNil(detected, "Should return nil when no shared secret matches.")
    }

    // MARK: - Receipt Verifier

    func testReceiptVerifierPendingWhenNoMatchingTXO() async {
        let verifier = ReceiptVerifier(mobClient: client)

        let receipt = PaymentReceiptMessage(
            txHash: String(repeating: "ab", count: 32),
            sharedSecret: Data(repeating: 0x01, count: 32).base64EncodedString(),
            amountPicomob: 1000,
            receiptProof: "proof",
            blockIndex: 1
        )

        let result = await verifier.verify(
            receipt: receipt,
            viewKey: SecureBytes(bytes: Array(repeating: 0, count: 32)),
            incomingTXOs: [] // No TXOs yet
        )

        if case .pending = result {} else {
            XCTFail("Should be pending when no matching TXO found.")
        }
    }

    // MARK: - Data Hex Extension

    func testHexEncodedString() {
        let data = Data([0x00, 0x0F, 0xFF, 0xAB])
        XCTAssertEqual(data.hexEncodedString(), "000fffab")
    }

    func testHexStringInit() {
        let data = Data(hexString: "deadbeef")
        XCTAssertNotNil(data)
        XCTAssertEqual(data?.count, 4)
        XCTAssertEqual(data?[0], 0xDE)
        XCTAssertEqual(data?[3], 0xEF)
    }

    func testHexRoundTrip() {
        let original = Data(repeating: 0x42, count: 32)
        let hex = original.hexEncodedString()
        let restored = Data(hexString: hex)
        XCTAssertEqual(original, restored)
    }

    // MARK: - PaymentResult

    func testPaymentResultFields() {
        let result = PaymentResult(
            paymentId: "pay-001",
            txHash: Data(repeating: 0xAB, count: 32),
            blockIndex: 12345,
            amountPicomob: 5_000_000_000_000,
            fee: 400_000_000,
            memo: "Test",
            confirmedAt: Date()
        )

        XCTAssertEqual(result.paymentId, "pay-001")
        XCTAssertEqual(result.blockIndex, 12345)
        XCTAssertEqual(result.amountPicomob, 5_000_000_000_000)
    }

    // MARK: - WalletBalance

    func testWalletBalanceConversion() {
        let balance = WalletBalance(
            balancePicomob: 3_750_000_000_000,
            unspentTXOCount: 5,
            inFlightPaymentCount: 1,
            lastUpdated: Date()
        )

        XCTAssertEqual(balance.balanceInMOB, 3.75, accuracy: 0.0001)
    }
}
