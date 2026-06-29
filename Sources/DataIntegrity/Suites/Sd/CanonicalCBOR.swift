import Foundation

/// Minimal canonical CBOR writer for the ecdsa-sd-2023 proof value.
///
/// Emits minimal-length integer encodings and sorts map keys numerically
/// ascending — which equals `cborg`'s default RFC 7049 length-first ordering
/// for non-negative integer keys. SwiftCBOR does not sort map keys, so we
/// encode the proof-value structures here to guarantee byte-for-byte parity
/// with the JS reference implementation.
enum CanonicalCBOR {
    /// CBOR head: major type (high 3 bits) + minimal length/value encoding.
    static func head(major: UInt8, value: UInt64) -> [UInt8] {
        let m = major << 5
        switch value {
        case 0..<24:
            return [m | UInt8(value)]
        case 24..<0x100:
            return [m | 24, UInt8(value)]
        case 0x100..<0x1_0000:
            return [m | 25, UInt8(value >> 8), UInt8(value & 0xFF)]
        case 0x1_0000..<0x1_0000_0000:
            return [m | 26,
                    UInt8((value >> 24) & 0xFF), UInt8((value >> 16) & 0xFF),
                    UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)]
        default:
            var out: [UInt8] = [m | 27]
            for shift in stride(from: 56, through: 0, by: -8) {
                out.append(UInt8((value >> UInt64(shift)) & 0xFF))
            }
            return out
        }
    }

    static func uint(_ value: UInt64) -> [UInt8] { head(major: 0, value: value) }

    static func byteString(_ data: Data) -> [UInt8] {
        head(major: 2, value: UInt64(data.count)) + Array(data)
    }

    static func arrayHeader(_ count: Int) -> [UInt8] { head(major: 4, value: UInt64(count)) }

    static func mapHeader(_ count: Int) -> [UInt8] { head(major: 5, value: UInt64(count)) }
}
