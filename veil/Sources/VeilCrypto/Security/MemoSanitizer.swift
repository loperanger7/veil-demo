// VEIL — MemoSanitizer.swift
// Ticket: VEIL-901 — Security Hardening (Red Team Finding: Memo Field Injection)
// Spec reference: Section 8.5 (Payment Receipts)
//
// MEDIUM FIX: The memo field previously accepted arbitrary strings with only
// length truncation. No Unicode normalization, no control character filtering.
// This could enable phishing via misleading instructions (e.g., Unicode RTL
// override characters that reverse displayed text).
//
// This module sanitizes memo text by:
//   1. Unicode NFC normalization (canonical decomposition + composition)
//   2. Control character stripping (C0, C1, directional overrides)
//   3. Length validation (max 256 UTF-8 bytes after normalization)
//   4. Optional homoglyph detection for common phishing patterns

import Foundation

// MARK: - Memo Sanitizer

/// Sanitizes payment memo text to prevent injection and phishing attacks.
///
/// Applies Unicode NFC normalization, strips dangerous control characters,
/// and enforces byte-length limits. All memo text should pass through this
/// sanitizer before being stored or displayed.
public struct MemoSanitizer: Sendable {

    /// Maximum memo length in UTF-8 bytes.
    public static let maxByteLength = 256

    /// Maximum memo length in characters (Unicode scalar values).
    public static let maxCharacterLength = 256

    public init() {}

    // MARK: - Sanitization

    /// Sanitize a memo string for safe storage and display.
    ///
    /// - Parameter memo: The raw memo input.
    /// - Returns: A sanitized memo string.
    public func sanitize(_ memo: String) -> SanitizedMemo {
        var result = memo
        var warnings: [MemoWarning] = []

        // Step 1: Unicode NFC normalization
        result = result.precomposedStringWithCanonicalMapping

        // Step 2: Strip dangerous control characters
        let (stripped, controlWarnings) = stripControlCharacters(result)
        result = stripped
        warnings.append(contentsOf: controlWarnings)

        // Step 3: Strip Unicode directional overrides
        let (dirStripped, dirWarnings) = stripDirectionalOverrides(result)
        result = dirStripped
        warnings.append(contentsOf: dirWarnings)

        // Step 4: Strip zero-width characters (used for invisible text injection)
        let (zwStripped, zwWarnings) = stripZeroWidthCharacters(result)
        result = zwStripped
        warnings.append(contentsOf: zwWarnings)

        // Step 5: Truncate to max byte length
        result = truncateToByteLimit(result, maxBytes: Self.maxByteLength)

        // Step 6: Check for homoglyph patterns (warning only, no modification)
        let homoglyphWarnings = detectHomoglyphs(result)
        warnings.append(contentsOf: homoglyphWarnings)

        return SanitizedMemo(
            text: result,
            originalLength: memo.count,
            sanitizedLength: result.count,
            warnings: warnings
        )
    }

    // MARK: - Control Character Stripping

    /// Remove C0 control characters (U+0000–U+001F) except tab, newline, CR.
    /// Remove C1 control characters (U+0080–U+009F).
    private func stripControlCharacters(_ text: String) -> (String, [MemoWarning]) {
        var warnings: [MemoWarning] = []
        let allowedControls: Set<Character> = ["\t", "\n", "\r"]

        let filtered = text.filter { char in
            let scalar = char.unicodeScalars.first!
            let value = scalar.value

            // C0 range (except allowed)
            if value <= 0x1F && !allowedControls.contains(char) {
                warnings.append(.controlCharacterRemoved(scalar))
                return false
            }

            // C1 range
            if value >= 0x80 && value <= 0x9F {
                warnings.append(.controlCharacterRemoved(scalar))
                return false
            }

            return true
        }

        return (filtered, warnings)
    }

    /// Remove Unicode directional override characters.
    ///
    /// These can be used to reverse the displayed text direction, enabling
    /// phishing attacks (e.g., "Send 10 MOB to ‮boBecilA" displays as
    /// "Send 10 MOB to AliceBob" but the actual text is reversed).
    private func stripDirectionalOverrides(_ text: String) -> (String, [MemoWarning]) {
        var warnings: [MemoWarning] = []

        let directionalOverrides: Set<Unicode.Scalar> = [
            Unicode.Scalar(0x200E)!, // LEFT-TO-RIGHT MARK
            Unicode.Scalar(0x200F)!, // RIGHT-TO-LEFT MARK
            Unicode.Scalar(0x202A)!, // LEFT-TO-RIGHT EMBEDDING
            Unicode.Scalar(0x202B)!, // RIGHT-TO-LEFT EMBEDDING
            Unicode.Scalar(0x202C)!, // POP DIRECTIONAL FORMATTING
            Unicode.Scalar(0x202D)!, // LEFT-TO-RIGHT OVERRIDE
            Unicode.Scalar(0x202E)!, // RIGHT-TO-LEFT OVERRIDE
            Unicode.Scalar(0x2066)!, // LEFT-TO-RIGHT ISOLATE
            Unicode.Scalar(0x2067)!, // RIGHT-TO-LEFT ISOLATE
            Unicode.Scalar(0x2068)!, // FIRST STRONG ISOLATE
            Unicode.Scalar(0x2069)!, // POP DIRECTIONAL ISOLATE
        ]

        let filtered = String(text.unicodeScalars.filter { scalar in
            if directionalOverrides.contains(scalar) {
                warnings.append(.directionalOverrideRemoved(scalar))
                return false
            }
            return true
        })

        return (filtered, warnings)
    }

    /// Remove zero-width characters that can hide injected text.
    private func stripZeroWidthCharacters(_ text: String) -> (String, [MemoWarning]) {
        var warnings: [MemoWarning] = []

        let zeroWidthChars: Set<Unicode.Scalar> = [
            Unicode.Scalar(0x200B)!, // ZERO WIDTH SPACE
            Unicode.Scalar(0x200C)!, // ZERO WIDTH NON-JOINER
            Unicode.Scalar(0x200D)!, // ZERO WIDTH JOINER
            Unicode.Scalar(0xFEFF)!, // ZERO WIDTH NO-BREAK SPACE (BOM)
        ]

        let filtered = String(text.unicodeScalars.filter { scalar in
            if zeroWidthChars.contains(scalar) {
                warnings.append(.zeroWidthCharacterRemoved(scalar))
                return false
            }
            return true
        })

        return (filtered, warnings)
    }

    /// Truncate a string to a maximum UTF-8 byte length without splitting characters.
    private func truncateToByteLimit(_ text: String, maxBytes: Int) -> String {
        guard text.utf8.count > maxBytes else { return text }

        var result = ""
        var byteCount = 0
        for char in text {
            let charBytes = String(char).utf8.count
            if byteCount + charBytes > maxBytes {
                break
            }
            result.append(char)
            byteCount += charBytes
        }
        return result
    }

    // MARK: - Homoglyph Detection

    /// Detect common homoglyph patterns that could be used for phishing.
    ///
    /// This is a warning-only check — the text is not modified.
    private func detectHomoglyphs(_ text: String) -> [MemoWarning] {
        var warnings: [MemoWarning] = []

        // Check for mixed scripts (Latin + Cyrillic, etc.)
        var hasLatin = false
        var hasCyrillic = false
        var hasGreek = false

        for scalar in text.unicodeScalars {
            let value = scalar.value
            if (0x0041...0x024F).contains(value) { hasLatin = true }
            if (0x0400...0x04FF).contains(value) { hasCyrillic = true }
            if (0x0370...0x03FF).contains(value) { hasGreek = true }
        }

        let scriptCount = [hasLatin, hasCyrillic, hasGreek].filter { $0 }.count
        if scriptCount > 1 {
            warnings.append(.mixedScriptsDetected)
        }

        return warnings
    }
}

// MARK: - Sanitized Memo Result

/// The result of memo sanitization, including the cleaned text and any warnings.
public struct SanitizedMemo: Sendable, Equatable {
    /// The sanitized memo text, safe for display.
    public let text: String
    /// Length of the original input.
    public let originalLength: Int
    /// Length of the sanitized output.
    public let sanitizedLength: Int
    /// Warnings generated during sanitization.
    public let warnings: [MemoWarning]

    /// Whether any modifications were made.
    public var wasModified: Bool {
        originalLength != sanitizedLength
    }

    /// Whether the memo is empty after sanitization.
    public var isEmpty: Bool {
        text.isEmpty
    }
}

// MARK: - Memo Warnings

/// Warnings generated during memo sanitization.
public enum MemoWarning: Sendable, Equatable {
    /// A C0/C1 control character was removed.
    case controlCharacterRemoved(Unicode.Scalar)
    /// A Unicode directional override was removed.
    case directionalOverrideRemoved(Unicode.Scalar)
    /// A zero-width character was removed.
    case zeroWidthCharacterRemoved(Unicode.Scalar)
    /// Multiple Unicode scripts detected (potential homoglyph attack).
    case mixedScriptsDetected
}
