import Foundation

/// Verifier for the JCS-based Data Integrity suites: `ecdsa-jcs-2019` (ECDSA,
/// P-256/P-384) and `eddsa-jcs-2022` (Ed25519). Identical to the RDFC suites
/// except the document and proof config are canonicalized with JCS (RFC 8785)
/// instead of RDFC-1.0 — so this path needs no JSON-LD processing or document
/// loader.
///
///   proofConfigHash = SHA(JCS(proof options))   (proof options carry the doc @context)
///   documentHash    = SHA(JCS(document − proof))
///   hashData        = proofConfigHash ‖ documentHash
///   verify proofValue over hashData with the issuer key
///   (ecdsa-jcs-2019: P-256 ⇒ SHA-256, P-384 ⇒ SHA-384; eddsa-jcs-2022: Ed25519, SHA-256)
struct JcsSuiteVerifier {
    let keyResolver: KeyResolver

    func verify(credential: JSONValue, proof: DataIntegrityProof) async -> VerificationResult {
        let suite = proof.effectiveCryptosuite
        do {
            let key = try await keyResolver.resolve(verificationMethod: proof.verificationMethod)

            // Guard cryptosuite/key-type mismatch before doing any crypto.
            let isEddsa = (suite == Cryptosuite.eddsaJcs2022)
            if isEddsa != key.isEd25519 {
                return .failure(suite, "cryptosuite \(suite) does not match key type \(key.curveName)")
            }

            let unsecured = credential.removing("proof")
            var proofConfig = proof.object.removing("proofValue")
            if let context = credential["@context"] {
                proofConfig["@context"] = context
            }

            let proofConfigHash = DigestUtil.hash(DigestUtil.utf8(JCS.canonicalize(proofConfig)), for: key)
            let documentHash = DigestUtil.hash(DigestUtil.utf8(JCS.canonicalize(unsecured)), for: key)
            let hashData = proofConfigHash + documentHash

            let signature = try Multibase.decode(proof.proofValue)
            return key.isValidSignature(signature, for: hashData)
                ? .success(suite)
                : .failure(suite, "\(suite) signature did not verify")
        } catch let error as DataIntegrityError {
            return .failure(suite, error.message)
        } catch {
            return .failure(suite, error.localizedDescription)
        }
    }
}
