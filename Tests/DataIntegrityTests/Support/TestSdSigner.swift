import Foundation
import Crypto
import JSONLD
@testable import DataIntegrity

/// Test-only ecdsa-sd-2023 issuer/deriver that produces a VALID derived
/// proof disclosing the full document, marking every `mandatoryEvery`-th
/// statement mandatory. Exercises the entire verify path (CBOR parse,
/// c14n→HMAC relabel, UTF-16 sort, mandatory split, base + per-statement
/// signatures) without needing the canonical-id-map fork.
enum TestSdSigner {
    static func deriveFullDisclosure(
        credential: JSONValue,
        issuerKey: P256.Signing.PrivateKey,
        hmacKey: Data = Data(repeating: 0x07, count: 32),
        created: String = "2026-01-01T00:00:00Z",
        mandatoryEvery: Int = 2,
        loader: any JSONLDDocumentLoader
    ) async throws -> JSONValue {
        let unsecured = credential.removing("proof")

        // 1. Canonicalize → c14n N-Quads; build the c14n → HMAC label map.
        let canonical = try await Canonicalization.canonicalize(unsecured, loader: loader)
        let c14nLines = NQuadLines.split(canonical)
        var labelMap: [String: String] = [:]
        for label in c14nLabels(in: c14nLines) {
            let mac = DigestUtil.hmacSHA256(key: hmacKey, message: DigestUtil.utf8(label))
            labelMap[label] = "u" + Base64URL.encode(mac)
        }

        // 2. Relabel + UTF-16 sort → final statement list.
        let relabeled = c14nLines.map { NQuadsRelabel.relabelLine($0, map: labelMap) }
        let finalStatements = NQuadsRelabel.sortUTF16(relabeled)

        // 3. Choose mandatory indexes.
        var mandatoryIndexes: [Int] = []
        var i = 0
        while i < finalStatements.count { mandatoryIndexes.append(i); i += max(mandatoryEvery, 1) }
        let mandatorySet = Set(mandatoryIndexes)
        var mandatory: [String] = []
        var nonMandatory: [String] = []
        for (index, line) in finalStatements.enumerated() {
            if mandatorySet.contains(index) { mandatory.append(line) } else { nonMandatory.append(line) }
        }
        let mandatoryHash = DigestUtil.sha256(DigestUtil.utf8(NQuadLines.join(mandatory)))

        // 4. Ephemeral key + per-statement signatures over each non-mandatory n-quad.
        let ephemeral = P256.Signing.PrivateKey()
        let publicKey = Multikey.encodeP256(ephemeral.publicKey)
        var signatures: [Data] = []
        for statement in nonMandatory {
            let signature = try ephemeral.signature(for: DigestUtil.utf8(statement + "\n"))
            signatures.append(signature.rawRepresentation)
        }

        // 5. proofHash + base signature (issuer key).
        var proofConfig: JSONValue = .object([
            "type": .string("DataIntegrityProof"),
            "cryptosuite": .string("ecdsa-sd-2023"),
            "created": .string(created),
            "verificationMethod": .string(TestSigner.didKeyP256(issuerKey.publicKey)),
            "proofPurpose": .string("assertionMethod"),
        ])
        proofConfig["@context"] = credential["@context"]
        let canonicalProofConfig = try await Canonicalization.canonicalize(proofConfig, loader: loader)
        let proofHash = DigestUtil.sha256(DigestUtil.utf8(canonicalProofConfig))
        let baseSignature = try issuerKey.signature(for: proofHash + publicKey + mandatoryHash).rawRepresentation

        // 6. Serialize derived proof value + attach.
        let proofValue = try SdProofValue.serializeDerived(
            baseSignature: baseSignature, publicKey: publicKey, signatures: signatures,
            labelMap: labelMap, mandatoryIndexes: mandatoryIndexes)
        var proof = proofConfig.removing("@context")
        proof["proofValue"] = .string(proofValue)
        var out = unsecured
        out["proof"] = proof
        return out
    }

    /// Collect all `c14nN` blank-node labels appearing in canonical N-Quads.
    static func c14nLabels(in lines: [String]) -> Set<String> {
        var labels = Set<String>()
        for line in lines {
            let scalars = Array(line.unicodeScalars)
            var i = 0
            while i < scalars.count {
                if scalars[i] == "_", i + 1 < scalars.count, scalars[i + 1] == ":" {
                    var j = i + 2
                    var label = ""
                    while j < scalars.count, scalars[j] != " ", scalars[j] != "\t" {
                        label.unicodeScalars.append(scalars[j]); j += 1
                    }
                    if label.hasPrefix("c14n") { labels.insert(label) }
                    i = j
                } else {
                    i += 1
                }
            }
        }
        return labels
    }
}
