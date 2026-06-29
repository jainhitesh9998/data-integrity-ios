import Foundation

/// A CBOR value, limited to the types used by the ecdsa-sd-2023 proof value.
indirect enum CBORValue {
    case uint(UInt64)
    case byteString([UInt8])
    case textString(String)
    case array([CBORValue])
    case map([(CBORValue, CBORValue)])
    case tagged(UInt64, CBORValue)
}

/// Minimal RFC 8949 CBOR decoder for the ecdsa-sd-2023 proof value (unsigned
/// ints, byte/text strings, arrays, maps, tags — definite-length only).
///
/// We encode CBOR ourselves (``CanonicalCBOR``), so the library only needs to
/// *decode* this small, fixed structure; this avoids a third-party CBOR
/// dependency (which conflicted with the wallet's existing SwiftCBOR fork on
/// the `swiftcbor` package identity).
enum CBORDecode {
    static func decode(_ bytes: [UInt8]) throws -> CBORValue {
        var index = 0
        let value = try decodeItem(bytes, &index)
        return value
    }

    private static func decodeItem(_ bytes: [UInt8], _ index: inout Int) throws -> CBORValue {
        guard index < bytes.count else { throw error("unexpected end of CBOR") }
        let initial = bytes[index]
        index += 1
        let major = initial >> 5
        let info = initial & 0x1F
        let argument = try readArgument(bytes, &index, info: info)

        switch major {
        case 0:  // unsigned integer
            return .uint(argument)
        case 2:  // byte string
            let length = Int(argument)
            guard index + length <= bytes.count else { throw error("byte string overruns input") }
            let slice = Array(bytes[index..<index + length])
            index += length
            return .byteString(slice)
        case 3:  // text string
            let length = Int(argument)
            guard index + length <= bytes.count else { throw error("text string overruns input") }
            let slice = Array(bytes[index..<index + length])
            index += length
            guard let string = String(bytes: slice, encoding: .utf8) else {
                throw error("invalid UTF-8 text string")
            }
            return .textString(string)
        case 4:  // array
            var items: [CBORValue] = []
            items.reserveCapacity(Int(argument))
            for _ in 0..<argument { items.append(try decodeItem(bytes, &index)) }
            return .array(items)
        case 5:  // map
            var pairs: [(CBORValue, CBORValue)] = []
            pairs.reserveCapacity(Int(argument))
            for _ in 0..<argument {
                let key = try decodeItem(bytes, &index)
                let value = try decodeItem(bytes, &index)
                pairs.append((key, value))
            }
            return .map(pairs)
        case 6:  // tag
            return .tagged(argument, try decodeItem(bytes, &index))
        default:  // 1 (negative int), 7 (simple/float) are not used here
            throw error("unsupported CBOR major type \(major)")
        }
    }

    private static func readArgument(_ bytes: [UInt8], _ index: inout Int, info: UInt8) throws -> UInt64 {
        if info < 24 { return UInt64(info) }
        let count: Int
        switch info {
        case 24: count = 1
        case 25: count = 2
        case 26: count = 4
        case 27: count = 8
        default: throw error("unsupported/indefinite CBOR length")
        }
        guard index + count <= bytes.count else { throw error("argument overruns input") }
        var value: UInt64 = 0
        for _ in 0..<count {
            value = (value << 8) | UInt64(bytes[index])
            index += 1
        }
        return value
    }

    private static func error(_ message: String) -> DataIntegrityError {
        DataIntegrityError(.malformedProofValue, "CBOR decode: \(message)")
    }
}
