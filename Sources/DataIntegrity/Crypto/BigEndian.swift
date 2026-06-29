import Foundation

/// Minimal fixed-width big-endian byte arithmetic, used only for ECDSA
/// low-S normalization. Both operands must be the same length.
enum BigEndian {
    /// Compare two equal-length big-endian byte arrays. Returns -1, 0, 1.
    static func compare(_ a: [UInt8], _ b: [UInt8]) -> Int {
        precondition(a.count == b.count)
        for i in 0..<a.count {
            if a[i] != b[i] { return a[i] < b[i] ? -1 : 1 }
        }
        return 0
    }

    /// `a - b` for equal-length big-endian arrays, assuming `a >= b`.
    static func subtract(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        precondition(a.count == b.count)
        var result = [UInt8](repeating: 0, count: a.count)
        var borrow = 0
        for i in stride(from: a.count - 1, through: 0, by: -1) {
            let diff = Int(a[i]) - Int(b[i]) - borrow
            if diff < 0 {
                result[i] = UInt8(diff + 256)
                borrow = 1
            } else {
                result[i] = UInt8(diff)
                borrow = 0
            }
        }
        return result
    }

    /// Parse a hex string into a byte array.
    static func bytes(fromHex hex: String) -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            if let byte = UInt8(hex[index..<next], radix: 16) {
                out.append(byte)
            }
            index = next
        }
        return out
    }
}

/// ECDSA curve orders (n) for low-S normalization.
enum CurveOrder {
    /// P-256 (secp256r1) group order.
    static let p256 = BigEndian.bytes(
        fromHex: "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")
    /// P-384 (secp384r1) group order.
    static let p384 = BigEndian.bytes(
        fromHex: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973")

    /// Normalize the S component of a raw `r||s` ECDSA signature to low-S
    /// (`s = min(s, n - s)`). Both forms verify the same message, so this
    /// makes verification independent of which S normalization the issuer
    /// emitted (matches the JS verifier's `lowS: false`).
    static func normalizeLowS(rawSignature: Data, order n: [UInt8]) -> Data? {
        let half = n.count
        guard rawSignature.count == half * 2 else { return nil }
        let bytes = Array(rawSignature)
        let r = Array(bytes[0..<half])
        let s = Array(bytes[half..<(half * 2)])
        guard BigEndian.compare(s, n) < 0 else { return nil }  // s must be < n
        let nMinusS = BigEndian.subtract(n, s)
        let lowS = BigEndian.compare(nMinusS, s) < 0 ? nMinusS : s
        return Data(r + lowS)
    }
}
