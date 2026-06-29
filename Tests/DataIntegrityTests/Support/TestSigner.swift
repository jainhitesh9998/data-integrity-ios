import Foundation
import Crypto
import JSONLD
@testable import DataIntegrity

/// Test-only signer used to generate sample valid VCs for round-trip
/// verification. Mirrors the issuer side of the Data Integrity algorithms
/// (the inverse of the library's verifier).
enum TestSigner {
    static func didKeyP256(_ publicKey: P256.Signing.PublicKey) -> String {
        // Uses the library's own compression (exercises ECPoint.compress, and
        // the verify path then exercises ECPoint.decompress).
        "did:key:z" + Base58.encode(Multikey.encodeP256(publicKey))
    }

    static func didKeyEd25519(_ publicKey: Curve25519.Signing.PublicKey) -> String {
        "did:key:z" + Base58.encode(Data([0xed, 0x01]) + publicKey.rawRepresentation)
    }

    static func didKeyP384(_ publicKey: P384.Signing.PublicKey) -> String {
        let compressed = ECPoint.compress(x963: publicKey.x963Representation, fieldSize: 48) ?? Data()
        return "did:key:z" + Base58.encode(Data([0x81, 0x24]) + compressed)
    }

    /// Build hashData = SHA(proofConfig) ‖ SHA(document) for a given proof config.
    private static func hashData(
        document: JSONValue,
        proofConfig: JSONValue,
        loader: any JSONLDDocumentLoader,
        sha384: Bool
    ) async throws -> Data {
        let canonicalProofConfig = try await Canonicalization.canonicalize(proofConfig, loader: loader)
        let canonicalDocument = try await Canonicalization.canonicalize(document, loader: loader)
        let pc = DigestUtil.utf8(canonicalProofConfig)
        let dc = DigestUtil.utf8(canonicalDocument)
        if sha384 {
            return DigestUtil.sha384(pc) + DigestUtil.sha384(dc)
        }
        return DigestUtil.sha256(pc) + DigestUtil.sha256(dc)
    }

    static func signEcdsaRdfc2019(
        credential: JSONValue,
        privateKey: P256.Signing.PrivateKey,
        verificationMethod: String? = nil,
        created: String = "2026-01-01T00:00:00Z",
        loader: any JSONLDDocumentLoader
    ) async throws -> JSONValue {
        let unsecured = credential.removing("proof")
        var proofConfig: JSONValue = .object([
            "type": .string("DataIntegrityProof"),
            "cryptosuite": .string("ecdsa-rdfc-2019"),
            "created": .string(created),
            "verificationMethod": .string(verificationMethod ?? didKeyP256(privateKey.publicKey)),
            "proofPurpose": .string("assertionMethod"),
        ])
        proofConfig["@context"] = credential["@context"]
        let data = try await hashData(document: unsecured, proofConfig: proofConfig, loader: loader, sha384: false)
        let signature = try privateKey.signature(for: data)
        return attach(proofConfig: proofConfig, signature: signature.rawRepresentation, to: unsecured)
    }

    static func signEcdsaRdfc2019P384(
        credential: JSONValue,
        privateKey: P384.Signing.PrivateKey,
        created: String = "2026-01-01T00:00:00Z",
        loader: any JSONLDDocumentLoader
    ) async throws -> JSONValue {
        let unsecured = credential.removing("proof")
        var proofConfig: JSONValue = .object([
            "type": .string("DataIntegrityProof"),
            "cryptosuite": .string("ecdsa-rdfc-2019"),
            "created": .string(created),
            "verificationMethod": .string(didKeyP384(privateKey.publicKey)),
            "proofPurpose": .string("assertionMethod"),
        ])
        proofConfig["@context"] = credential["@context"]
        // P-384 uses SHA-384 for the proof/document hashes.
        let data = try await hashData(document: unsecured, proofConfig: proofConfig, loader: loader, sha384: true)
        let signature = try privateKey.signature(for: data)
        return attach(proofConfig: proofConfig, signature: signature.rawRepresentation, to: unsecured)
    }

    static func signEcdsaJcs2019(
        credential: JSONValue,
        privateKey: P256.Signing.PrivateKey,
        created: String = "2026-01-01T00:00:00Z"
    ) async throws -> JSONValue {
        let unsecured = credential.removing("proof")
        var proofConfig: JSONValue = .object([
            "type": .string("DataIntegrityProof"),
            "cryptosuite": .string("ecdsa-jcs-2019"),
            "created": .string(created),
            "verificationMethod": .string(didKeyP256(privateKey.publicKey)),
            "proofPurpose": .string("assertionMethod"),
        ])
        proofConfig["@context"] = credential["@context"]
        // JCS canonicalization — no JSON-LD / document loader needed.
        let hashData = DigestUtil.sha256(DigestUtil.utf8(JCS.canonicalize(proofConfig)))
            + DigestUtil.sha256(DigestUtil.utf8(JCS.canonicalize(unsecured)))
        let signature = try privateKey.signature(for: hashData)
        return attach(proofConfig: proofConfig, signature: signature.rawRepresentation, to: unsecured)
    }

    static func signEddsaRdfc2022(
        credential: JSONValue,
        privateKey: Curve25519.Signing.PrivateKey,
        created: String = "2026-01-01T00:00:00Z",
        loader: any JSONLDDocumentLoader
    ) async throws -> JSONValue {
        let unsecured = credential.removing("proof")
        var proofConfig: JSONValue = .object([
            "type": .string("DataIntegrityProof"),
            "cryptosuite": .string("eddsa-rdfc-2022"),
            "created": .string(created),
            "verificationMethod": .string(didKeyEd25519(privateKey.publicKey)),
            "proofPurpose": .string("assertionMethod"),
        ])
        proofConfig["@context"] = credential["@context"]
        let data = try await hashData(document: unsecured, proofConfig: proofConfig, loader: loader, sha384: false)
        let signature = try privateKey.signature(for: data)
        return attach(proofConfig: proofConfig, signature: Data(signature), to: unsecured)
    }

    static func signEd25519Signature2020(
        credential: JSONValue,
        privateKey: Curve25519.Signing.PrivateKey,
        created: String = "2026-01-01T00:00:00Z",
        loader: any JSONLDDocumentLoader
    ) async throws -> JSONValue {
        let unsecured = credential.removing("proof")
        var proofConfig: JSONValue = .object([
            "type": .string("Ed25519Signature2020"),
            "created": .string(created),
            "verificationMethod": .string(didKeyEd25519(privateKey.publicKey)),
            "proofPurpose": .string("assertionMethod"),
        ])
        // Legacy suite canonicalizes its proof options under the suite context.
        proofConfig["@context"] = .string(Cryptosuite.ed25519Signature2020Context)
        let data = try await hashData(document: unsecured, proofConfig: proofConfig, loader: loader, sha384: false)
        let signature = try privateKey.signature(for: data)
        return attach(proofConfig: proofConfig, signature: Data(signature), to: unsecured)
    }

    private static func attach(proofConfig: JSONValue, signature: Data, to document: JSONValue) -> JSONValue {
        var proof = proofConfig.removing("@context")
        proof["proofValue"] = .string("z" + Base58.encode(signature))
        var out = document
        out["proof"] = proof
        return out
    }
}
