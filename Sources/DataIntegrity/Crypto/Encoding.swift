import Foundation

/// base64url (no padding) — RFC 4648 §5. Used for the ecdsa-sd-2023
/// `proofValue` (multibase `u`) and JWK key components.
enum Base64URL {
    static func encode(_ data: Data) -> String {
        var s = data.base64EncodedString()
        s = s.replacingOccurrences(of: "+", with: "-")
        s = s.replacingOccurrences(of: "/", with: "_")
        s = s.replacingOccurrences(of: "=", with: "")
        return s
    }

    static func decode(_ string: String) -> Data? {
        var s = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = s.count % 4
        if remainder > 0 {
            s += String(repeating: "=", count: 4 - remainder)
        }
        return Data(base64Encoded: s)
    }
}

/// Base58 with the Bitcoin alphabet (base58btc). Used by multibase `z`
/// (did:key, `publicKeyMultibase`, and `proofValue` for the non-SD suites).
enum Base58 {
    private static let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8)
    private static let zero = UInt8(ascii: "1")

    /// Precomputed reverse map: ascii byte → base58 digit value (or 0xFF).
    private static let reverse: [UInt8] = {
        var table = [UInt8](repeating: 0xFF, count: 256)
        for (i, c) in alphabet.enumerated() { table[Int(c)] = UInt8(i) }
        return table
    }()

    static func decode(_ string: String) -> Data? {
        let input = Array(string.utf8)
        if input.isEmpty { return Data() }

        // Leading '1's encode leading zero bytes.
        var leadingZeros = 0
        for c in input {
            if c == zero { leadingZeros += 1 } else { break }
        }

        // Convert from base58 to base256 (big-endian) via repeated *58 + d.
        var bytes: [UInt8] = []  // little-endian during accumulation
        for c in input {
            let digit = reverse[Int(c)]
            if digit == 0xFF { return nil }  // invalid character
            var carry = Int(digit)
            for i in 0..<bytes.count {
                carry += Int(bytes[i]) * 58
                bytes[i] = UInt8(carry & 0xFF)
                carry >>= 8
            }
            while carry > 0 {
                bytes.append(UInt8(carry & 0xFF))
                carry >>= 8
            }
        }

        var out = [UInt8](repeating: 0, count: leadingZeros)
        out.append(contentsOf: bytes.reversed())
        return Data(out)
    }

    static func encode(_ data: Data) -> String {
        let input = Array(data)
        if input.isEmpty { return "" }

        var leadingZeros = 0
        for b in input {
            if b == 0 { leadingZeros += 1 } else { break }
        }

        var digits: [UInt8] = []  // little-endian base58
        for b in input {
            var carry = Int(b)
            for i in 0..<digits.count {
                carry += Int(digits[i]) << 8
                digits[i] = UInt8(carry % 58)
                carry /= 58
            }
            while carry > 0 {
                digits.append(UInt8(carry % 58))
                carry /= 58
            }
        }

        var out = String(repeating: "1", count: leadingZeros)
        for d in digits.reversed() {
            out.unicodeScalars.append(Unicode.Scalar(alphabet[Int(d)]))
        }
        return out
    }
}

/// Minimal multibase decoder for the prefixes used by Verifiable Credentials.
enum Multibase {
    /// Decode a multibase string. Supports `z` (base58btc) and `u`
    /// (base64url-no-pad).
    static func decode(_ string: String) throws -> Data {
        guard let prefix = string.first else {
            throw DataIntegrityError(.malformedProofValue, "empty multibase value")
        }
        let body = String(string.dropFirst())
        switch prefix {
        case "z":
            guard let data = Base58.decode(body) else {
                throw DataIntegrityError(.malformedProofValue, "invalid base58btc value")
            }
            return data
        case "u":
            guard let data = Base64URL.decode(body) else {
                throw DataIntegrityError(.malformedProofValue, "invalid base64url value")
            }
            return data
        default:
            throw DataIntegrityError(.malformedProofValue, "unsupported multibase prefix '\(prefix)'")
        }
    }
}
