import Foundation

/// Verifier for the `ecdsa-jcs-2019` cryptosuite. Identical to `ecdsa-rdfc-2019`
/// except the document and proof config are canonicalized with JCS (RFC 8785)
/// instead of RDFC-1.0 — so it needs no JSON-LD processing or document loader.
///
///   proofConfigHash = SHA(JCS(proof options))   (proof options carry the doc @context)
///   documentHash    = SHA(JCS(document − proof))
///   hashData        = proofConfigHash ‖ documentHash
///   verify proofValue over hashData with the issuer key (P-256 ⇒ SHA-256, P-384 ⇒ SHA-384)
struct JcsSuiteVerifier {
    let keyResolver: KeyResolver

    func verify(credential: JSONValue, proof: DataIntegrityProof) async -> VerificationResult {
        let suite = Cryptosuite.ecdsaJcs2019
        do {
            let key = try await keyResolver.resolve(verificationMethod: proof.verificationMethod)
            if key.isEd25519 {
                return .failure(suite, "ecdsa-jcs-2019 requires an ECDSA (P-256/P-384) key")
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
                : .failure(suite, "ecdsa-jcs-2019 signature did not verify")
        } catch let error as DataIntegrityError {
            return .failure(suite, error.message)
        } catch {
            return .failure(suite, error.localizedDescription)
        }
    }
}
