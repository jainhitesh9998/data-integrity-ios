import Foundation

/// Outcome of verifying a credential's Data Integrity proof.
public struct VerificationResult: Sendable, Codable, Equatable {
    /// Whether the proof verified successfully.
    public let verified: Bool
    /// The cryptosuite that was applied (e.g. `ecdsa-sd-2023`), when known.
    public let cryptosuite: String?
    /// Human-readable failure reason when `verified == false`.
    public let reason: String?

    public init(verified: Bool, cryptosuite: String? = nil, reason: String? = nil) {
        self.verified = verified
        self.cryptosuite = cryptosuite
        self.reason = reason
    }

    static func success(_ cryptosuite: String) -> VerificationResult {
        VerificationResult(verified: true, cryptosuite: cryptosuite, reason: nil)
    }

    static func failure(_ cryptosuite: String?, _ reason: String) -> VerificationResult {
        VerificationResult(verified: false, cryptosuite: cryptosuite, reason: reason)
    }

    /// Serialize to a JSON dictionary for the React Native bridge.
    public func toDictionary() -> [String: Any] {
        var dict: [String: Any] = ["verified": verified]
        if let cryptosuite = cryptosuite { dict["cryptosuite"] = cryptosuite }
        if let reason = reason { dict["reason"] = reason }
        return dict
    }
}
