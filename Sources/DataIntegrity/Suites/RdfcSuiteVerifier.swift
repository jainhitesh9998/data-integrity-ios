import Foundation
import JSONLD

/// Verifier for the non-selective-disclosure Data Integrity suites:
/// `ecdsa-rdfc-2019` (P-256/P-384), `eddsa-rdfc-2022` (Ed25519), and the
/// legacy `Ed25519Signature2020`.
///
/// Algorithm (per vc-di-ecdsa §ecdsa-rdfc-2019 / vc-di-eddsa §eddsa-rdfc-2022):
///   1. canonicalize the document without `proof`         → docHash
///   2. canonicalize the proof options without proofValue → proofConfigHash
///   3. hashData = proofConfigHash ‖ docHash  (proof config first)
///   4. ecdsa: ECDSA-verify proofValue over hashData (curve hashes internally)
///      eddsa: Ed25519-verify proofValue over hashData directly
struct RdfcSuiteVerifier {
    let loader: any JSONLDDocumentLoader
    let keyResolver: KeyResolver

    func verify(credential: JSONValue, proof: DataIntegrityProof) async -> VerificationResult {
        let suite = proof.effectiveCryptosuite
        do {
            // 1. Resolve the issuer key.
            let key = try await keyResolver.resolve(verificationMethod: proof.verificationMethod)

            // Guard cryptosuite/key-type mismatch before doing any crypto.
            let isEddsa = (suite == Cryptosuite.eddsaRdfc2022)
            if isEddsa != key.isEd25519 {
                return .failure(suite, "cryptosuite \(suite) does not match key type \(key.curveName)")
            }

            // 2. Build the unsecured document and proof config.
            let unsecured = credential.removing("proof")
            var proofConfig = proof.object.removing("proofValue")
            if proof.type == Cryptosuite.ed25519Signature2020 {
                proofConfig["@context"] = .string(Cryptosuite.ed25519Signature2020Context)
            } else if let ctx = credential["@context"] {
                proofConfig["@context"] = ctx
            }

            // 3. Canonicalize + hash.
            let canonicalProofConfig = try await Canonicalization.canonicalize(proofConfig, loader: loader)
            let canonicalDocument = try await Canonicalization.canonicalize(unsecured, loader: loader)
            let proofConfigHash = DigestUtil.hash(DigestUtil.utf8(canonicalProofConfig), for: key)
            let documentHash = DigestUtil.hash(DigestUtil.utf8(canonicalDocument), for: key)
            let hashData = proofConfigHash + documentHash

            // 4. Verify the signature (multibase base58btc 'z').
            let signature = try Multibase.decode(proof.proofValue)
            let verified = key.isValidSignature(signature, for: hashData)
            return verified
                ? .success(suite)
                : .failure(suite, "\(suite) signature did not verify")
        } catch let error as DataIntegrityError {
            return .failure(suite, error.message)
        } catch {
            return .failure(suite, error.localizedDescription)
        }
    }
}
