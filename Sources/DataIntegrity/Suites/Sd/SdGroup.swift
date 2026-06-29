import Foundation
import JSONLD

/// `canonicalizeAndGroup` — skolemize, canonicalize with HMAC blank-node
/// relabeling, then split the canonical N-Quads into matching / non-matching
/// sets per named group of JSON Pointers. Port of digitalbazaar
/// `di-sd-primitives` `group.js`.
enum SdGroup {
    /// One group's classification of the full canonical N-Quad list.
    struct Group {
        /// (absolute index into the full sorted N-Quads, n-quad) — ascending.
        let matching: [(index: Int, nquad: String)]
        let nonMatching: [(index: Int, nquad: String)]
        /// The group selection's deskolemized N-Quads.
        let deskolemizedNQuads: [String]

        var matchingIndexSet: Set<Int> { Set(matching.map { $0.index }) }
        var matchingNQuads: [String] { matching.map { $0.nquad } }
        var nonMatchingNQuads: [String] { nonMatching.map { $0.nquad } }
    }

    struct Result {
        let groups: [String: Group]
        let labelMap: [String: String]    // input → HMAC label
        let nquads: [String]              // full canonical, HMAC-relabeled, sorted
    }

    static func canonicalizeAndGroup(
        document: JSONValue,
        hmacKey: Data,
        groups: [String: [String]],
        loader: any JSONLDDocumentLoader
    ) async throws -> Result {
        // 1. Skolemize.
        let skolemized = try await Skolemize.skolemizeCompact(document: document, loader: loader)

        // 2. Deskolemized N-Quads for the whole document.
        let deskolemizedNQuads = try await Skolemize.toDeskolemizedNQuads(
            document: skolemized.expanded, loader: loader)

        // 3. Canonicalize with HMAC blank-node relabeling.
        let factory = SdPrimitives.hmacIdLabelMapFunction(hmacKey: hmacKey)
        let (nquads, labelMap) = try SdPrimitives.labelReplacementCanonicalizeNQuads(
            nquads: deskolemizedNQuads, labelMapFactoryFunction: factory)

        // 4-5. For each group: select, relabel, and split into matching / non-matching.
        var results: [String: Group] = [:]
        for (name, pointers) in groups {
            let selection = try JSONLDSelect.selectJsonLd(
                document: skolemized.compact, pointers: pointers) ?? .object([:])
            let selectionDeskolemized = try await Skolemize.toDeskolemizedNQuads(
                document: selection, loader: loader)
            let selectionNQuads = SdPrimitives.relabelBlankNodes(
                nquads: selectionDeskolemized, labelMap: labelMap)
            let selectionSet = Set(selectionNQuads)

            var matching: [(index: Int, nquad: String)] = []
            var nonMatching: [(index: Int, nquad: String)] = []
            for (index, nquad) in nquads.enumerated() {
                if selectionSet.contains(nquad) {
                    matching.append((index, nquad))
                } else {
                    nonMatching.append((index, nquad))
                }
            }
            results[name] = Group(
                matching: matching, nonMatching: nonMatching,
                deskolemizedNQuads: selectionDeskolemized)
        }

        return Result(groups: results, labelMap: labelMap, nquads: nquads)
    }
}
