import Foundation
import Crypto

/// SHA digest helpers.
enum DigestUtil {
    static func sha256(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }
    static func sha384(_ data: Data) -> Data { Data(SHA384.hash(data: data)) }

    /// The suite hash for a curve: SHA-384 for P-384, SHA-256 otherwise
    /// (P-256 and Ed25519).
    static func hash(_ data: Data, for key: VerificationKey) -> Data {
        if case .p384 = key { return sha384(data) }
        return sha256(data)
    }

    static func utf8(_ string: String) -> Data { Data(string.utf8) }

    /// HMAC-SHA-256 (used by ecdsa-sd-2023 blank-node label generation).
    static func hmacSHA256(key: Data, message: Data) -> Data {
        let mac = HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key))
        return Data(mac)
    }
}
