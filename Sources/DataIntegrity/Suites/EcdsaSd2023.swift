import Foundation
import JSONLD

/// ecdsa-sd-2023 selective-disclosure cryptosuite (verify + derive).
///
/// References: W3C vc-di-ecdsa §3.4–3.6, digitalbazaar
/// `ecdsa-sd-2023-cryptosuite` + `di-sd-primitives`.
enum EcdsaSd2023 {
    static let name = "ecdsa-sd-2023"

    // MARK: - Verify (derived proof)

    static func verify(
        credential: JSONValue,
        proof: DataIntegrityProof,
        loader: any JSONLDDocumentLoader,
        keyResolver: KeyResolver
    ) async -> VerificationResult {
        do {
            let verifyData = try await createVerifyData(credential: credential, proof: proof, loader: loader)

            // Number of disclosed non-mandatory statements must match the
            // number of revealed per-statement signatures.
            guard verifyData.signatures.count == verifyData.nonMandatory.count else {
                return .failure(
                    name,
                    "signature count (\(verifyData.signatures.count)) does not match non-mandatory statement count (\(verifyData.nonMandatory.count))")
            }

            // Base signature: issuer key over proofHash ‖ publicKey ‖ mandatoryHash.
            let issuerKey = try await keyResolver.resolve(verificationMethod: proof.verificationMethod)
            let toVerify = verifyData.proofHash + verifyData.publicKey + verifyData.mandatoryHash
            guard issuerKey.isValidSignature(verifyData.baseSignature, for: toVerify) else {
                return .failure(name, "base signature did not verify against the issuer key")
            }

            // Per-statement signatures: ephemeral (proof-scoped) key over each
            // non-mandatory n-quad (raw UTF-8, including trailing newline).
            let ephemeralKey = try Multikey.decode(verifyData.publicKey)
            for (index, signature) in verifyData.signatures.enumerated() {
                let message = DigestUtil.utf8(verifyData.nonMandatory[index] + "\n")
                guard ephemeralKey.isValidSignature(signature, for: message) else {
                    return .failure(name, "non-mandatory statement signature #\(index) did not verify")
                }
            }

            return .success(name)
        } catch let error as DataIntegrityError {
            return .failure(name, error.message)
        } catch {
            return .failure(name, error.localizedDescription)
        }
    }

    /// The data needed to verify a derived proof (vc-di-ecdsa §3.5.9
    /// createVerifyData).
    struct VerifyData {
        let baseSignature: Data
        let proofHash: Data
        let publicKey: Data
        let signatures: [Data]
        let nonMandatory: [String]   // each WITHOUT trailing newline
        let mandatoryHash: Data
    }

    static func createVerifyData(
        credential: JSONValue,
        proof: DataIntegrityProof,
        loader: any JSONLDDocumentLoader
    ) async throws -> VerifyData {
        let components = try SdProofValue.parseDerived(proof.proofValue)

        // proofHash = SHA-256( canonicalize(proof config) ).
        var proofConfig = proof.object.removing("proofValue")
        proofConfig["@context"] = credential["@context"]
        let canonicalProofConfig = try await Canonicalization.canonicalize(proofConfig, loader: loader)
        let proofHash = DigestUtil.sha256(DigestUtil.utf8(canonicalProofConfig))

        // Canonicalize the disclosed document, then relabel c14n blank-node
        // ids to the HMAC labels from the proof and re-sort (UTF-16). Because
        // the proof's labelMap is keyed by c14n labels, this is equivalent to
        // the reference labelReplacementCanonicalize without needing the
        // canonical-id map.
        let unsecured = credential.removing("proof")
        let canonical = try await Canonicalization.canonicalize(unsecured, loader: loader)
        let relabeled = NQuadLines.split(canonical).map {
            NQuadsRelabel.relabelLine($0, map: components.labelMap)
        }
        let sortedLines = NQuadsRelabel.sortUTF16(relabeled)

        // Split into mandatory / non-mandatory by index into the sorted list.
        let mandatoryIndexSet = Set(components.mandatoryIndexes)
        var mandatory: [String] = []
        var nonMandatory: [String] = []
        for (index, line) in sortedLines.enumerated() {
            if mandatoryIndexSet.contains(index) {
                mandatory.append(line)
            } else {
                nonMandatory.append(line)
            }
        }

        // mandatoryHash = SHA-256( UTF8( join(mandatory) ) ), lines joined with
        // their trailing newlines.
        let mandatoryHash = DigestUtil.sha256(DigestUtil.utf8(NQuadLines.join(mandatory)))

        return VerifyData(
            baseSignature: components.baseSignature,
            proofHash: proofHash,
            publicKey: components.publicKey,
            signatures: components.signatures,
            nonMandatory: nonMandatory,
            mandatoryHash: mandatoryHash
        )
    }

    // MARK: - Derive (selective disclosure)

    static func derive(
        baseCredential: JSONValue,
        selectivePointers: [String],
        loader: any JSONLDDocumentLoader
    ) async throws -> JSONValue {
        // 1. Find + parse the base proof.
        let proofObjects = ProofExtractor.proofs(in: baseCredential)
        guard let baseProofObject = proofObjects.first(where: {
            $0["type"]?.stringValue == "DataIntegrityProof" && $0["cryptosuite"]?.stringValue == name
        }), let proofValue = baseProofObject["proofValue"]?.stringValue else {
            throw DataIntegrityError(.malformedProof, "no ecdsa-sd-2023 base proof found")
        }
        let base = try SdProofValue.parseBase(proofValue)

        // 2. Ensure something is disclosed.
        guard !base.mandatoryPointers.isEmpty || !selectivePointers.isEmpty else {
            throw DataIntegrityError(.nothingSelected, "nothing selected for disclosure")
        }

        // 3-4. Canonicalize + group by mandatory / selective / combined pointers.
        let combinedPointers = base.mandatoryPointers + selectivePointers
        let document = baseCredential.removing("proof")
        let grouped = try await SdGroup.canonicalizeAndGroup(
            document: document,
            hmacKey: base.hmacKey,
            groups: [
                "mandatory": base.mandatoryPointers,
                "selective": selectivePointers,
                "combined": combinedPointers,
            ],
            loader: loader)
        guard let mandatoryGroup = grouped.groups["mandatory"],
              let selectiveGroup = grouped.groups["selective"],
              let combinedGroup = grouped.groups["combined"] else {
            throw DataIntegrityError(.canonicalizationFailed, "selective-disclosure grouping failed")
        }

        // 5. Relative mandatory indexes within the combined disclosed set.
        let mandatoryIndexSet = mandatoryGroup.matchingIndexSet
        var relativeIndex = 0
        var mandatoryIndexes: [Int] = []
        for (absoluteIndex, _) in combinedGroup.matching {
            if mandatoryIndexSet.contains(absoluteIndex) {
                mandatoryIndexes.append(relativeIndex)
            }
            relativeIndex += 1
        }

        // 6. Keep base signatures for selectively-disclosed, non-mandatory statements.
        let selectiveIndexSet = selectiveGroup.matchingIndexSet
        var index = 0
        var filteredSignatures: [Data] = []
        for signature in base.signatures {
            while mandatoryIndexSet.contains(index) { index += 1 }
            let keep = selectiveIndexSet.contains(index)
            index += 1
            if keep { filteredSignatures.append(signature) }
        }

        // 7. Reveal document = selection of the original document by combined pointers.
        guard let revealDoc = try JSONLDSelect.selectJsonLd(document: document, pointers: combinedPointers) else {
            throw DataIntegrityError(.nothingSelected, "nothing selected for disclosure")
        }

        // 8-9. Verifier label map: canonical (verifier) labels → HMAC labels.
        let joined = NQuadLines.join(combinedGroup.deskolemizedNQuads)
        let quads = try RDFCLabels.NQuadsParser.parse(joined)
        let (_, verifierCanonicalIdMap) = try RDFCLabels.canonicalizeWithLabels(quads: quads)
        var verifierLabelMap: [String: String] = [:]
        for (inputLabel, verifierLabel) in verifierCanonicalIdMap {
            if let hmacLabel = grouped.labelMap[inputLabel] {
                verifierLabelMap[verifierLabel] = hmacLabel
            }
        }

        // 10. Serialize the derived proof value and attach to the reveal doc.
        let derivedProofValue = try SdProofValue.serializeDerived(
            baseSignature: base.baseSignature,
            publicKey: base.publicKey,
            signatures: filteredSignatures,
            labelMap: verifierLabelMap,
            mandatoryIndexes: mandatoryIndexes)

        var newProof = baseProofObject.removing("@context")
        newProof["proofValue"] = .string(derivedProofValue)
        var out = revealDoc
        out["proof"] = newProof
        return out
    }
}
