import Foundation

/// Components of an ecdsa-sd-2023 base proof (issuer side).
struct BaseProofComponents {
    let baseSignature: Data       // 64
    let publicKey: Data           // 35-byte P-256 multikey (ephemeral)
    let hmacKey: Data             // 32
    let signatures: [Data]        // each 64
    let mandatoryPointers: [String]
}

/// Components of an ecdsa-sd-2023 derived proof (holder → verifier).
struct DerivedProofComponents {
    let baseSignature: Data       // 64
    let publicKey: Data           // 35-byte P-256 multikey (ephemeral)
    let signatures: [Data]        // each 64
    /// `"c14nN"` → `"u" + base64url(HMAC)` (decompressed).
    let labelMap: [String: String]
    let mandatoryIndexes: [Int]
}

/// Parse / serialize ecdsa-sd-2023 `proofValue`s (multibase `u` + CBOR with a
/// 3-byte magic prefix). See vc-di-ecdsa §3.5.
enum SdProofValue {
    static let basePrefix: [UInt8] = [0xd9, 0x5d, 0x00]
    static let derivedPrefix: [UInt8] = [0xd9, 0x5d, 0x01]

    // MARK: - Derived (verify path)

    static func parseDerived(_ proofValue: String) throws -> DerivedProofComponents {
        let array = try decodePayload(proofValue, prefix: derivedPrefix, kind: "derived")

        let baseSignature = try byteString(array[0], expected: 64, field: "baseSignature")
        let publicKey = try byteString(array[1], expected: 35, field: "publicKey")
        let signatures = try byteStringArray(array[2], each: 64, field: "signatures")

        guard case .map(let pairs) = unwrap(array[3]) else {
            throw DataIntegrityError(.malformedProofValue, "compressed labelMap is not a CBOR map")
        }
        var labelMap: [String: String] = [:]
        for (key, value) in pairs {
            guard case .uint(let n) = unwrap(key) else {
                throw DataIntegrityError(.malformedProofValue, "labelMap key is not an integer")
            }
            let bytes = try byteString(value, expected: 32, field: "labelMap value")
            labelMap["c14n\(n)"] = "u" + Base64URL.encode(bytes)
        }

        guard case .array(let indexes) = unwrap(array[4]) else {
            throw DataIntegrityError(.malformedProofValue, "mandatoryIndexes is not a CBOR array")
        }
        let mandatoryIndexes = try indexes.map { element -> Int in
            guard case .uint(let n) = unwrap(element) else {
                throw DataIntegrityError(.malformedProofValue, "mandatoryIndex is not an integer")
            }
            return Int(n)
        }

        return DerivedProofComponents(
            baseSignature: baseSignature, publicKey: publicKey, signatures: signatures,
            labelMap: labelMap, mandatoryIndexes: mandatoryIndexes)
    }

    // MARK: - Base (derive path)

    static func parseBase(_ proofValue: String) throws -> BaseProofComponents {
        let array = try decodePayload(proofValue, prefix: basePrefix, kind: "base")

        let baseSignature = try byteString(array[0], expected: 64, field: "baseSignature")
        let publicKey = try byteString(array[1], expected: 35, field: "publicKey")
        let hmacKey = try byteString(array[2], expected: 32, field: "hmacKey")
        let signatures = try byteStringArray(array[3], each: 64, field: "signatures")
        guard case .array(let pointers) = unwrap(array[4]) else {
            throw DataIntegrityError(.malformedProofValue, "mandatoryPointers is not a CBOR array")
        }
        let mandatoryPointers = try pointers.map { element -> String in
            guard case .textString(let s) = unwrap(element) else {
                throw DataIntegrityError(.malformedProofValue, "mandatoryPointer is not a string")
            }
            return s
        }
        return BaseProofComponents(
            baseSignature: baseSignature, publicKey: publicKey, hmacKey: hmacKey,
            signatures: signatures, mandatoryPointers: mandatoryPointers)
    }

    // MARK: - Serialization

    /// Serialize a derived proof value: `u` + base64url( 0xd95d01 ‖ CBOR
    /// [baseSignature, publicKey, signatures, compressedLabelMap, mandatoryIndexes] ).
    static func serializeDerived(
        baseSignature: Data,
        publicKey: Data,
        signatures: [Data],
        labelMap: [String: String],
        mandatoryIndexes: [Int]
    ) throws -> String {
        var payload = derivedPrefix
        payload += CanonicalCBOR.arrayHeader(5)
        payload += CanonicalCBOR.byteString(baseSignature)
        payload += CanonicalCBOR.byteString(publicKey)
        payload += CanonicalCBOR.arrayHeader(signatures.count)
        for signature in signatures { payload += CanonicalCBOR.byteString(signature) }

        // compress labelMap: "c14nN" → N, "u"+base64url → 32 raw bytes; keys ascending.
        let entries = try labelMap.map { (key, value) -> (Int, Data) in
            guard key.hasPrefix("c14n"), let n = Int(key.dropFirst(4)) else {
                throw DataIntegrityError(.malformedProofValue, "labelMap key '\(key)' is not c14nN")
            }
            guard value.hasPrefix("u"), let bytes = Base64URL.decode(String(value.dropFirst())) else {
                throw DataIntegrityError(.malformedProofValue, "labelMap value '\(value)' is not multibase base64url")
            }
            return (n, bytes)
        }.sorted { $0.0 < $1.0 }

        payload += CanonicalCBOR.mapHeader(entries.count)
        for (key, bytes) in entries {
            payload += CanonicalCBOR.uint(UInt64(key))
            payload += CanonicalCBOR.byteString(bytes)
        }

        payload += CanonicalCBOR.arrayHeader(mandatoryIndexes.count)
        for index in mandatoryIndexes { payload += CanonicalCBOR.uint(UInt64(index)) }

        return "u" + Base64URL.encode(Data(payload))
    }

    /// Serialize a base proof value: `u` + base64url( 0xd95d00 ‖ CBOR
    /// [baseSignature, publicKey, hmacKey, signatures, mandatoryPointers] ).
    static func serializeBase(
        baseSignature: Data,
        publicKey: Data,
        hmacKey: Data,
        signatures: [Data],
        mandatoryPointers: [String]
    ) -> String {
        var payload = basePrefix
        payload += CanonicalCBOR.arrayHeader(5)
        payload += CanonicalCBOR.byteString(baseSignature)
        payload += CanonicalCBOR.byteString(publicKey)
        payload += CanonicalCBOR.byteString(hmacKey)
        payload += CanonicalCBOR.arrayHeader(signatures.count)
        for signature in signatures { payload += CanonicalCBOR.byteString(signature) }
        payload += CanonicalCBOR.arrayHeader(mandatoryPointers.count)
        for pointer in mandatoryPointers {
            let bytes = Array(pointer.utf8)
            payload += CanonicalCBOR.head(major: 3, value: UInt64(bytes.count)) + bytes
        }
        return "u" + Base64URL.encode(Data(payload))
    }

    // MARK: - Helpers

    /// Decode `u`-multibase + 3-byte-prefix + CBOR array-of-5 payload.
    private static func decodePayload(_ proofValue: String, prefix: [UInt8], kind: String) throws -> [CBORValue] {
        guard proofValue.hasPrefix("u") else {
            throw DataIntegrityError(.malformedProofValue, "\(kind) proofValue must be multibase base64url ('u')")
        }
        let decoded = Array(try Multibase.decode(proofValue))
        guard decoded.count > 3, Array(decoded[0..<3]) == prefix else {
            throw DataIntegrityError(.malformedProofValue, "\(kind) proofValue missing magic prefix")
        }
        let payload = Array(decoded[3...])
        let cbor = try CBORDecode.decode(payload)
        guard case .array(let array) = cbor, array.count == 5 else {
            throw DataIntegrityError(.malformedProofValue, "\(kind) proofValue is not a CBOR array of 5")
        }
        return array
    }

    /// Unwrap CBOR tags (the spec tolerates tag-wrapped byte strings).
    private static func unwrap(_ cbor: CBORValue) -> CBORValue {
        if case .tagged(_, let inner) = cbor { return unwrap(inner) }
        return cbor
    }

    private static func byteString(_ cbor: CBORValue, expected: Int, field: String) throws -> Data {
        guard case .byteString(let bytes) = unwrap(cbor) else {
            throw DataIntegrityError(.malformedProofValue, "\(field) is not a byte string")
        }
        guard bytes.count == expected else {
            throw DataIntegrityError(.malformedProofValue, "\(field) must be \(expected) bytes, got \(bytes.count)")
        }
        return Data(bytes)
    }

    private static func byteStringArray(_ cbor: CBORValue, each: Int, field: String) throws -> [Data] {
        guard case .array(let array) = unwrap(cbor) else {
            throw DataIntegrityError(.malformedProofValue, "\(field) is not an array")
        }
        return try array.map { try byteString($0, expected: each, field: "\(field) element") }
    }
}
