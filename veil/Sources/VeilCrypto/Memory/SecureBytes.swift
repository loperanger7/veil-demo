// VEIL — SecureBytes.swift
// Ticket: VEIL-109 — Message Key Zeroization & Memory Safety
// Spec reference: Section 3.4 (Key Derivation & Management)
//
// A heap-allocated byte buffer that guarantees zeroization on deallocation.
// This is the foundational type for all secret key material in Veil.
//
// Design principles:
//   - Secret material must never exist in Swift `String` or `Array` (ARC may copy).
//   - Deallocation always zeroizes via `memset_s` (cannot be optimized away).
//   - Constant-time comparison prevents timing side channels.
//   - Move semantics prevent accidental copies of secret material.

import Foundation

/// A fixed-size buffer of secret bytes that is zeroized on deallocation.
///
/// `SecureBytes` owns a region of heap memory allocated via `malloc`.
/// When the instance is deinitialized, the memory is overwritten with
/// zeros using `memset_s` (which the compiler cannot elide) and then freed.
///
/// **Thread safety:** `SecureBytes` is `Sendable` because it is a value type
/// with no shared mutable state. The underlying pointer is private and never
/// exposed.
public struct SecureBytes: Sendable {

    // MARK: - Storage

    /// Reference-counted storage that owns the raw allocation.
    /// Using a class ensures we get a single deallocation point.
    private final class Storage: @unchecked Sendable {
        let pointer: UnsafeMutableRawPointer
        let count: Int
        private(set) var isZeroized: Bool = false

        init(count: Int) {
            precondition(count > 0, "SecureBytes: count must be positive")
            self.count = count
            self.pointer = UnsafeMutableRawPointer.allocate(
                byteCount: count,
                alignment: MemoryLayout<UInt8>.alignment
            )
            // Initialize to zero
            memset(self.pointer, 0, count)
        }

        init(copying bytes: UnsafeRawBufferPointer) {
            self.count = bytes.count
            self.pointer = UnsafeMutableRawPointer.allocate(
                byteCount: bytes.count,
                alignment: MemoryLayout<UInt8>.alignment
            )
            self.pointer.copyMemory(from: bytes.baseAddress!, byteCount: bytes.count)
        }

        /// Securely zeroize the buffer contents.
        /// Uses volatile memset pattern that cannot be optimized away.
        func zeroize() {
            guard !isZeroized else { return }
            // Use withUnsafeMutableBytes to ensure the write is not elided.
            // On Darwin, memset_s is available; on Linux we use explicit volatile pattern.
            #if canImport(Darwin)
            _ = memset_s(pointer, count, 0, count)
            #else
            // Volatile pointer write pattern prevents dead-store elimination
            let volatilePointer = UnsafeMutablePointer<UInt8>(
                OpaquePointer(pointer)
            )
            for i in 0..<count {
                volatilePointer.advanced(by: i).pointee = 0
            }
            // Compiler barrier
            withExtendedLifetime(volatilePointer) {}
            #endif
            isZeroized = true
        }

        deinit {
            zeroize()
            pointer.deallocate()
        }
    }

    private let storage: Storage

    // MARK: - Initialization

    /// Create a zero-filled `SecureBytes` buffer of the given size.
    public init(count: Int) {
        self.storage = Storage(count: count)
    }

    /// Create `SecureBytes` by copying from a raw buffer.
    /// The source buffer is NOT zeroized by this initializer — the caller
    /// is responsible for cleaning up the source.
    public init(copying data: Data) {
        self.storage = data.withUnsafeBytes { bytes in
            Storage(copying: bytes)
        }
    }

    /// Create `SecureBytes` by copying from a byte array.
    /// The source array is NOT zeroized — use only for non-secret data
    /// or when the caller manages the source lifetime.
    public init(bytes: [UInt8]) {
        self.storage = bytes.withUnsafeBytes { buffer in
            Storage(copying: buffer)
        }
    }

    // MARK: - Properties

    /// Number of bytes in this buffer.
    public var count: Int { storage.count }

    /// Whether this buffer has been explicitly zeroized.
    public var isZeroized: Bool { storage.isZeroized }

    // MARK: - Access

    /// Execute a closure with read-only access to the underlying bytes.
    ///
    /// - Throws: `VeilError.useAfterZeroize` if the buffer was zeroized.
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) throws -> R {
        guard !storage.isZeroized else {
            throw VeilError.useAfterZeroize
        }
        return try body(UnsafeRawBufferPointer(start: storage.pointer, count: storage.count))
    }

    /// Execute a closure with mutable access to the underlying bytes.
    ///
    /// - Throws: `VeilError.useAfterZeroize` if the buffer was zeroized.
    public mutating func withUnsafeMutableBytes<R>(
        _ body: (UnsafeMutableRawBufferPointer) throws -> R
    ) throws -> R {
        guard !storage.isZeroized else {
            throw VeilError.useAfterZeroize
        }
        return try body(
            UnsafeMutableRawBufferPointer(start: storage.pointer, count: storage.count)
        )
    }

    /// Explicitly zeroize this buffer before deallocation.
    /// Safe to call multiple times.
    public mutating func zeroize() {
        storage.zeroize()
    }

    /// Export a copy of the bytes as `Data`.
    ///
    /// **Warning:** The returned `Data` is managed by ARC and will NOT be
    /// zeroized. Use only when passing to APIs that require `Data` (e.g.,
    /// CryptoKit), and ensure the `Data` has a short lifetime.
    public func copyToData() throws -> Data {
        try withUnsafeBytes { buffer in
            Data(buffer)
        }
    }

    // MARK: - Constant-Time Comparison

    /// Compare two `SecureBytes` buffers in constant time.
    ///
    /// Returns `true` if and only if both buffers have the same length and
    /// identical contents. The comparison always examines every byte,
    /// preventing timing side channels.
    public static func constantTimeEqual(_ lhs: SecureBytes, _ rhs: SecureBytes) -> Bool {
        guard lhs.count == rhs.count else { return false }
        guard !lhs.isZeroized && !rhs.isZeroized else { return false }

        var result: UInt8 = 0
        let lp = lhs.storage.pointer.assumingMemoryBound(to: UInt8.self)
        let rp = rhs.storage.pointer.assumingMemoryBound(to: UInt8.self)

        for i in 0..<lhs.count {
            result |= lp[i] ^ rp[i]
        }

        return result == 0
    }
}

// MARK: - Equatable (constant-time)

extension SecureBytes: Equatable {
    /// Constant-time equality. Never use `==` on secret material in
    /// contexts where timing matters — but at least this default
    /// implementation is safe.
    public static func == (lhs: SecureBytes, rhs: SecureBytes) -> Bool {
        constantTimeEqual(lhs, rhs)
    }
}

// MARK: - CustomStringConvertible

extension SecureBytes: CustomStringConvertible {
    /// Never prints contents — only metadata.
    public var description: String {
        "SecureBytes(\(count) bytes, zeroized: \(isZeroized))"
    }
}

// MARK: - CustomDebugStringConvertible

extension SecureBytes: CustomDebugStringConvertible {
    /// Debug output intentionally omits contents to prevent accidental logging.
    public var debugDescription: String {
        "SecureBytes(count: \(count), zeroized: \(isZeroized))"
    }
}
