import Foundation
import JSONLD

/// Public entry point for W3C Verifiable Credential Data Integrity
/// operations: RDF canonicalization, proof verification, and ecdsa-sd-2023
/// selective-disclosure derivation.
///
/// Mirrors the `inji-vci-client-ios-swift` convention: a `public` class
/// constructed plainly, `async throws` methods, JSON crossing the boundary
/// as `String`, and a single `DataIntegrityError` error type.
///
/// ```swift
/// let client = DataIntegrityClient()
/// let nquads = try await client.canonicalize(jsonLd: docJSON)
/// let result = try await client.verifyCredential(credentialJSON)
/// ```
public final class DataIntegrityClient: Sendable {
    /// Library version, surfaced for diagnostics / the React Native bridge.
    public static let version = "0.1.0"

    private let documentLoader: any JSONLDDocumentLoader

    /// - Parameter documentLoader: resolves `@context` documents. Defaults
    ///   to ``ContextDocumentLoader`` (bundled offline contexts + network
    ///   fallback, with `@protected` stripping).
    public init(documentLoader: ContextDocumentLoader = ContextDocumentLoader()) {
        self.documentLoader = documentLoader
    }

    /// Inject any custom loader (e.g. a strict offline loader in tests).
    public init(documentLoader: any JSONLDDocumentLoader) {
        self.documentLoader = documentLoader
    }

    // MARK: - Canonicalization (exposed as a standalone function)

    /// Canonicalize a JSON-LD document to RDFC-1.0 (URDNA2015) N-Quads.
    ///
    /// This is the standalone canonicalization entry point and also backs
    /// the wallet's iOS `DataIntegrityCanonize.canonicalize` native module,
    /// unblocking the existing JS `ecdsa-rdfc-2019` / `eddsa-rdfc-2022` /
    /// `Ed25519Signature2020` verification on iOS.
    ///
    /// - Parameter jsonLd: a JSON-LD document (credential without proof, or
    ///   proof options) as a JSON string.
    /// - Returns: canonical N-Quads.
    public func canonicalize(jsonLd: String) async throws -> String {
        let json = try JSONValue(parsing: jsonLd)
        return try await Canonicalization.canonicalize(json, loader: documentLoader)
    }

    // MARK: - Verification

    /// Verify a credential's Data Integrity proof. Supports `ecdsa-sd-2023`
    /// (derived), `ecdsa-rdfc-2019`, `eddsa-rdfc-2022`, and the legacy
    /// `Ed25519Signature2020` suite. Never throws on a verification failure
    /// — it returns `VerificationResult(verified: false, reason:)`. It only
    /// throws for malformed input it cannot interpret at all.
    public func verifyCredential(_ credential: String) async throws -> VerificationResult {
        let json = try JSONValue(parsing: credential)
        return await CredentialVerifier(loader: documentLoader).verify(json)
    }

    // MARK: - Derivation (ecdsa-sd-2023 selective disclosure)

    /// Derive a selectively-disclosed `ecdsa-sd-2023` credential from a base
    /// credential, revealing only the statements named by `selectivePointers`
    /// (plus the issuer's mandatory statements).
    ///
    /// - Parameters:
    ///   - baseCredential: a credential carrying an `ecdsa-sd-2023` base proof.
    ///   - selectivePointers: JSON Pointers (RFC 6901) into the credential.
    /// - Returns: the derived credential as a JSON string.
    public func deriveCredential(
        baseCredential: String,
        selectivePointers: [String]
    ) async throws -> String {
        let json = try JSONValue(parsing: baseCredential)
        let derived = try await EcdsaSd2023.derive(
            baseCredential: json,
            selectivePointers: selectivePointers,
            loader: documentLoader
        )
        return try derived.serialized()
    }
}
