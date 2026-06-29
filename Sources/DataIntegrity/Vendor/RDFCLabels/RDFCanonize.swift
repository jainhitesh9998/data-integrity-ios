import Foundation

/// Swift implementation of [RDF Dataset Canonicalization](https://www.w3.org/TR/rdf-canon/)
/// (RDFC-1.0, also known as URDNA2015).
///
/// `RDFCLabels` is the public namespace for the package. Public entry
/// points are static functions; there is no instance to construct.
///
/// See the catalog documentation for an overview, quickstart, and the
/// current conformance picture against the
/// [w3c/rdf-canon](https://github.com/w3c/rdf-canon) test suite.
public enum RDFCLabels {}

extension RDFCLabels {
    /// Canonicalize an N-Quads document. Returns canonical N-Quads
    /// with `_:c14n0`, `_:c14n1`, … blank-node labels in lexicographic
    /// order.
    public static func canonicalize(
        nquads: String,
        hashAlgorithm: HashAlgorithm = .sha256,
        workFactor: Int = .max
    ) throws -> String {
        let quads = try NQuadsParser.parse(nquads)
        return try canonicalize(
            quads: quads,
            hashAlgorithm: hashAlgorithm,
            workFactor: workFactor
        )
    }

    /// Canonicalize an already-parsed list of quads.
    public static func canonicalize(
        quads: [Quad],
        hashAlgorithm: HashAlgorithm = .sha256,
        workFactor: Int = .max
    ) throws -> String {
        // An RDF dataset is a set — duplicate quads collapse to one.
        // RDFC-1.0 operates on the deduplicated dataset.
        let dataset = deduplicate(quads)
        let labels = try Canonicalizer.canonicalLabels(
            for: dataset,
            hashAlgorithm: hashAlgorithm,
            workFactor: workFactor
        )
        let relabeled = dataset.map { relabel($0, with: labels) }
        return NQuadsWriter.serialize(quads: relabeled.sorted { $0.canonicalKey < $1.canonicalKey })
    }

    /// Canonicalize AND return the canonical blank-node label map
    /// (`inputId → c14nId`), both stripped of the `_:` prefix. This is the
    /// piece upstream `swift-rdf-canonize` computes internally but does not
    /// expose; the ecdsa-sd-2023 *derive* path needs it to compute the HMAC
    /// labels. (Verification and the standalone `canonicalize()` use the
    /// upstream package directly.)
    public static func canonicalizeWithLabels(
        quads: [Quad],
        hashAlgorithm: HashAlgorithm = .sha256,
        workFactor: Int = .max
    ) throws -> (canonical: String, labelMap: [String: String]) {
        let dataset = deduplicate(quads)
        let labels = try Canonicalizer.canonicalLabels(
            for: dataset, hashAlgorithm: hashAlgorithm, workFactor: workFactor)
        let relabeled = dataset.map { relabel($0, with: labels) }
        let canonical = NQuadsWriter.serialize(quads: relabeled.sorted { $0.canonicalKey < $1.canonicalKey })
        var stripped: [String: String] = [:]
        for (key, value) in labels {
            stripped[Self.stripUnderscore(key)] = Self.stripUnderscore(value)
        }
        return (canonical, stripped)
    }

    static func stripUnderscore(_ id: String) -> String {
        id.hasPrefix("_:") ? String(id.dropFirst(2)) : id
    }

    /// Stable dedup: keep first occurrence, preserve original order.
    private static func deduplicate(_ quads: [Quad]) -> [Quad] {
        var seen: Set<Quad> = []
        var out: [Quad] = []
        out.reserveCapacity(quads.count)
        for q in quads where seen.insert(q).inserted {
            out.append(q)
        }
        return out
    }

    private static func relabel(_ quad: Quad, with labels: [String: String]) -> Quad {
        Quad(
            subject: relabel(quad.subject, with: labels),
            predicate: quad.predicate,
            object: relabel(quad.object, with: labels),
            graph: quad.graph.map { relabel($0, with: labels) }
        )
    }

    private static func relabel(_ term: Term, with labels: [String: String]) -> Term {
        if case .blankNode(let id) = term, let canonical = labels[id] {
            return .blankNode(canonical)
        }
        return term
    }
}

extension RDFCLabels.Quad {
    /// Stable sort key for canonical N-Quads output (the canonical
    /// blank-node labels have already been applied).
    var canonicalKey: String {
        let w = RDFCLabels.NQuadsWriter.self
        var s = "\(w.serialize(term: subject)) \(w.serialize(term: predicate)) \(w.serialize(term: object))"
        if let g = graph { s += " \(w.serialize(term: g))" }
        return s
    }
}
