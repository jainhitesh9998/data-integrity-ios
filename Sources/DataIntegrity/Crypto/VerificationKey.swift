import Foundation
import Crypto

/// A public key for verifying Data Integrity signatures, across the curves
/// used by the supported cryptosuites.
enum VerificationKey: Sendable {
    case p256(P256.Signing.PublicKey)
    case p384(P384.Signing.PublicKey)
    case ed25519(Curve25519.Signing.PublicKey)

    /// Canonical curve name as used in proofs/JWKs.
    var curveName: String {
        switch self {
        case .p256: return "P-256"
        case .p384: return "P-384"
        case .ed25519: return "Ed25519"
        }
    }

    var isEd25519: Bool {
        if case .ed25519 = self { return true }
        return false
    }

    /// Verify `signature` over `message`.
    ///
    /// For ECDSA the message is hashed internally (SHA-256 for P-256,
    /// SHA-384 for P-384) — callers pass the *un-hashed* bytes that the
    /// issuer signed. The raw `r||s` signature is normalized to low-S first
    /// so high-S signatures (which some issuers emit) still verify.
    /// For Ed25519 the message is verified directly (EdDSA hashes internally
    /// with SHA-512).
    func isValidSignature(_ signature: Data, for message: Data) -> Bool {
        switch self {
        case .p256(let key):
            guard
                let normalized = CurveOrder.normalizeLowS(rawSignature: signature, order: CurveOrder.p256),
                let sig = try? P256.Signing.ECDSASignature(rawRepresentation: normalized)
            else { return false }
            return key.isValidSignature(sig, for: message)
        case .p384(let key):
            guard
                let normalized = CurveOrder.normalizeLowS(rawSignature: signature, order: CurveOrder.p384),
                let sig = try? P384.Signing.ECDSASignature(rawRepresentation: normalized)
            else { return false }
            return key.isValidSignature(sig, for: message)
        case .ed25519(let key):
            return key.isValidSignature(signature, for: message)
        }
    }
}

/// Decodes Multikey-encoded public keys (multicodec varint prefix +
/// key bytes), per the W3C Controller Document spec.
enum Multikey {
    // multicodec varint prefixes (little-endian base-128) for public keys.
    static let p256Prefix: [UInt8] = [0x80, 0x24]   // p256-pub  0x1200
    static let p384Prefix: [UInt8] = [0x81, 0x24]   // p384-pub  0x1201
    static let ed25519Prefix: [UInt8] = [0xed, 0x01] // ed25519-pub 0xed

    /// Decode raw Multikey bytes (the 2-byte multicodec prefix followed by
    /// the compressed EC point / raw Ed25519 key).
    static func decode(_ data: Data) throws -> VerificationKey {
        let bytes = Array(data)
        guard bytes.count >= 3 else {
            throw DataIntegrityError(.invalidMultikey, "multikey too short")
        }
        let prefix = [bytes[0], bytes[1]]
        let body = Data(bytes.dropFirst(2))
        switch prefix {
        case p256Prefix:
            // CryptoKit's compressed-point init is iOS 16+, so decompress the
            // SEC1 point ourselves and use the iOS 14 x963 initializer.
            guard let x963 = ECPoint.decompress(body, curve: ECPoint.p256),
                  let key = try? P256.Signing.PublicKey(x963Representation: x963) else {
                throw DataIntegrityError(.invalidMultikey, "invalid P-256 compressed point")
            }
            return .p256(key)
        case p384Prefix:
            guard let x963 = ECPoint.decompress(body, curve: ECPoint.p384),
                  let key = try? P384.Signing.PublicKey(x963Representation: x963) else {
                throw DataIntegrityError(.invalidMultikey, "invalid P-384 compressed point")
            }
            return .p384(key)
        case ed25519Prefix:
            guard let key = try? Curve25519.Signing.PublicKey(rawRepresentation: body) else {
                throw DataIntegrityError(.invalidMultikey, "invalid Ed25519 key")
            }
            return .ed25519(key)
        default:
            throw DataIntegrityError(
                .invalidMultikey,
                "unsupported multicodec prefix 0x\(String(format: "%02x%02x", prefix[0], prefix[1]))")
        }
    }

    /// Encode a P-256 public key as a 35-byte Multikey (prefix + compressed
    /// point). Used to reconstruct the ecdsa-sd-2023 ephemeral key bytes.
    /// Compression is derived from the iOS 14 x963 representation (the
    /// `compressedRepresentation` getter is iOS 16+).
    static func encodeP256(_ key: P256.Signing.PublicKey) -> Data {
        let compressed = ECPoint.compress(x963: key.x963Representation, fieldSize: 32)
            ?? Data(key.x963Representation.dropFirst().prefix(33))
        return Data(p256Prefix) + compressed
    }
}

/// Builds a ``VerificationKey`` from a JWK (`publicKeyJwk`).
enum JWKKey {
    static func decode(_ jwk: [String: JSONValue]) throws -> VerificationKey {
        let kty = jwk["kty"]?.stringValue
        let crv = jwk["crv"]?.stringValue

        if kty == "OKP" || crv == "Ed25519" {
            guard let x = jwk["x"]?.stringValue, let raw = Base64URL.decode(x),
                  let key = try? Curve25519.Signing.PublicKey(rawRepresentation: raw) else {
                throw DataIntegrityError(.invalidMultikey, "invalid Ed25519 JWK")
            }
            return .ed25519(key)
        }

        guard let xStr = jwk["x"]?.stringValue, let yStr = jwk["y"]?.stringValue,
              let x = Base64URL.decode(xStr), let y = Base64URL.decode(yStr) else {
            throw DataIntegrityError(.invalidMultikey, "EC JWK missing x/y")
        }
        // Uncompressed SEC1 point: 0x04 || X || Y.
        let point = Data([0x04]) + x + y
        if crv == "P-384" {
            guard let key = try? P384.Signing.PublicKey(x963Representation: point) else {
                throw DataIntegrityError(.invalidMultikey, "invalid P-384 JWK")
            }
            return .p384(key)
        }
        guard let key = try? P256.Signing.PublicKey(x963Representation: point) else {
            throw DataIntegrityError(.invalidMultikey, "invalid P-256 JWK")
        }
        return .p256(key)
    }
}
