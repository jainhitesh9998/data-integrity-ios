import Foundation
import Crypto
import JSONLD
@testable import DataIntegrity

/// Test-only ecdsa-sd-2023 issuer: creates a valid BASE proof so the derive →
/// verify lifecycle can be exercised end to end. Mirrors digitalbazaar
/// `createBaseProofData` (sign side).
enum TestSdIssuer {
    static func issueBaseProof(
        credential: JSONValue,
        issuerKey: P256.Signing.PrivateKey,
        ephemeralKey: P256.Signing.PrivateKey,
        mandatoryPointers: [String],
        hmacKey: Data = Data(repeating: 0x2a, count: 32),
        created: String = "2026-01-01T00:00:00Z",
        loader: any JSONLDDocumentLoader
    ) async throws -> JSONValue {
        let document = credential.removing("proof")

        // proofHash = SHA-256(canonicalize(proof config)).
        var proofConfig: JSONValue = .object([
            "type": .string("DataIntegrityProof"),
            "cryptosuite": .string("ecdsa-sd-2023"),
            "created": .string(created),
            "verificationMethod": .string(TestSigner.didKeyP256(issuerKey.publicKey)),
            "proofPurpose": .string("assertionMethod"),
        ])
        proofConfig["@context"] = credential["@context"]
        let proofHash = DigestUtil.sha256(
            DigestUtil.utf8(try await Canonicalization.canonicalize(proofConfig, loader: loader)))

        // Group by mandatory pointers → mandatory + non-mandatory statements.
        let grouped = try await SdGroup.canonicalizeAndGroup(
            document: document, hmacKey: hmacKey,
            groups: ["mandatory": mandatoryPointers], loader: loader)
        let mandatoryGroup = grouped.groups["mandatory"]!
        let mandatory = mandatoryGroup.matchingNQuads
        let nonMandatory = mandatoryGroup.nonMatchingNQuads

        let mandatoryHash = DigestUtil.sha256(DigestUtil.utf8(NQuadLines.join(mandatory)))

        let publicKey = Multikey.encodeP256(ephemeralKey.publicKey)
        var signatures: [Data] = []
        for statement in nonMandatory {
            let signature = try ephemeralKey.signature(for: DigestUtil.utf8(statement + "\n"))
            signatures.append(signature.rawRepresentation)
        }

        let baseSignature = try issuerKey.signature(for: proofHash + publicKey + mandatoryHash).rawRepresentation

        let baseProofValue = SdProofValue.serializeBase(
            baseSignature: baseSignature, publicKey: publicKey, hmacKey: hmacKey,
            signatures: signatures, mandatoryPointers: mandatoryPointers)

        var proof = proofConfig.removing("@context")
        proof["proofValue"] = .string(baseProofValue)
        var out = document
        out["proof"] = proof
        return out
    }
}
