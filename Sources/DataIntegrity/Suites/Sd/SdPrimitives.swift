import Foundation

/// Selective-disclosure canonicalization primitives. Port of digitalbazaar
/// `di-sd-primitives` `canonicalize.js` (the label-map factory, blank-node
/// relabeling, and label-replacement canonicalization).
enum SdPrimitives {
    /// `createHmacIdLabelMapFunction`: given the canonical id map
    /// (`input → c14n`), produce `input → "u"+base64url(HMAC(c14n))`.
    static func hmacIdLabelMapFunction(hmacKey: Data) -> ([String: String]) -> [String: String] {
        return { canonicalIdMap in
            var map: [String: String] = [:]
            for (input, c14nLabel) in canonicalIdMap {
                let mac = DigestUtil.hmacSHA256(key: hmacKey, message: DigestUtil.utf8(c14nLabel))
                map[input] = "u" + Base64URL.encode(mac)
            }
            return map
        }
    }

    /// `relabelBlankNodes`: replace each `_:label` with `_:` + `labelMap[label]`.
    static func relabelBlankNodes(nquads: [String], labelMap: [String: String]) -> [String] {
        nquads.map { NQuadsRelabel.relabelLine($0, map: labelMap) }
    }

    /// `labelReplacementCanonicalizeNQuads`: canonicalize the N-Quads (RDFC-1.0,
    /// capturing `input → c14n`), build the new label map via
    /// `labelMapFactoryFunction`, then relabel the canonical N-Quads from c14n
    /// labels to the new labels and re-sort (UTF-16). Returns the relabeled,
    /// sorted N-Quads plus the `input → newLabel` map.
    static func labelReplacementCanonicalizeNQuads(
        nquads: [String],
        labelMapFactoryFunction: ([String: String]) -> [String: String]
    ) throws -> (nquads: [String], labelMap: [String: String]) {
        let joined = NQuadLines.join(nquads)
        let quads: [RDFCLabels.Quad]
        let canonical: String
        let canonicalIdMap: [String: String]
        do {
            quads = try RDFCLabels.NQuadsParser.parse(joined)
            (canonical, canonicalIdMap) = try RDFCLabels.canonicalizeWithLabels(quads: quads)
        } catch {
            throw DataIntegrityError(.canonicalizationFailed, "label-replacement canonicalize failed: \(error)")
        }

        // input → newLabel
        let labelMap = labelMapFactoryFunction(canonicalIdMap)

        // Replace using c14n → newLabel, since the canonical N-Quads carry the
        // c14n labels (matches the reference implementation's note).
        var c14nToNewLabel: [String: String] = [:]
        for (input, newLabel) in labelMap {
            if let c14n = canonicalIdMap[input] {
                c14nToNewLabel[c14n] = newLabel
            }
        }

        let relabeled = NQuadLines.split(canonical).map {
            NQuadsRelabel.relabelLine($0, map: c14nToNewLabel)
        }
        let sorted = NQuadsRelabel.sortUTF16(relabeled)
        return (sorted, labelMap)
    }
}
