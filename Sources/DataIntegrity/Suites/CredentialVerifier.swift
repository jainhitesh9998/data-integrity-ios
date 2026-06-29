import Foundation
import JSONLD

/// Routes a credential to the correct Data Integrity suite verifier based on
/// its proof `type` / `cryptosuite`. Never throws: any failure becomes a
/// `VerificationResult(verified: false, reason:)`.
struct CredentialVerifier {
    let loader: any JSONLDDocumentLoader
    var keyResolver = KeyResolver()

    func verify(_ credential: JSONValue) async -> VerificationResult {
        let proofObjects = ProofExtractor.proofs(in: credential)
        guard !proofObjects.isEmpty else {
            return .failure(nil, "credential has no proof")
        }

        let parsed = proofObjects.compactMap(ProofExtractor.parse)
        guard let proof = parsed.first(where: {
            $0.type == "DataIntegrityProof" || $0.type == Cryptosuite.ed25519Signature2020
        }) else {
            return .failure(nil, "no supported DataIntegrityProof / Ed25519Signature2020 proof")
        }

        let suite = proof.effectiveCryptosuite
        switch suite {
        case Cryptosuite.ecdsaSd2023:
            return await EcdsaSd2023.verify(credential: credential, proof: proof, loader: loader, keyResolver: keyResolver)
        case Cryptosuite.ecdsaRdfc2019, Cryptosuite.eddsaRdfc2022:
            let verifier = RdfcSuiteVerifier(loader: loader, keyResolver: keyResolver)
            return await verifier.verify(credential: credential, proof: proof)
        case Cryptosuite.ecdsaJcs2019:
            return await JcsSuiteVerifier(keyResolver: keyResolver).verify(credential: credential, proof: proof)
        default:
            return .failure(suite, "unsupported cryptosuite: \(suite)")
        }
    }
}
