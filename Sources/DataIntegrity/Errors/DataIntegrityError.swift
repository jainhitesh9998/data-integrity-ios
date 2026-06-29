import Foundation

/// Stable error codes surfaced by the library. The React Native bridge
/// maps these to JS rejection codes, so treat them as a public contract.
public enum DataIntegrityErrorCode: String, Sendable {
    case invalidJSON = "INVALID_JSON"
    case invalidCredential = "INVALID_CREDENTIAL"
    case canonicalizationFailed = "CANONICALIZATION_FAILED"
    case documentLoaderFailed = "DOCUMENT_LOADER_FAILED"
    case unsupportedCryptosuite = "UNSUPPORTED_CRYPTOSUITE"
    case malformedProof = "MALFORMED_PROOF"
    case malformedProofValue = "MALFORMED_PROOF_VALUE"
    case unsupportedVerificationMethod = "UNSUPPORTED_VERIFICATION_METHOD"
    case invalidMultikey = "INVALID_MULTIKEY"
    case keyResolutionFailed = "KEY_RESOLUTION_FAILED"
    case cryptosuiteKeyMismatch = "CRYPTOSUITE_KEY_MISMATCH"
    case signatureVerificationFailed = "SIGNATURE_VERIFICATION_FAILED"
    case nothingSelected = "NOTHING_SELECTED_FOR_DISCLOSURE"
    case invalidPointer = "INVALID_POINTER"
    case unsupportedOperation = "UNSUPPORTED_OPERATION"
}

/// Error type for all library operations. Conforms to `LocalizedError` so
/// `error.localizedDescription` (what the RN bridge forwards to JS) carries
/// the code and message.
public struct DataIntegrityError: Error, LocalizedError, Sendable {
    public let code: DataIntegrityErrorCode
    public let message: String

    public init(_ code: DataIntegrityErrorCode, _ message: String) {
        self.code = code
        self.message = message
    }

    public var errorDescription: String? { "[\(code.rawValue)] \(message)" }
}
