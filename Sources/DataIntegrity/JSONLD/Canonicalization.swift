import Foundation
import JSONLD
import RDFCanonize

/// JSON-LD → RDF → RDFC-1.0 canonical N-Quads.
///
/// Pipeline: expand + `toRDF` (`swift-jsonld`) → map quads → `canonicalize`
/// (`swift-rdf-canonize`, RDFC-1.0 / URDNA2015). RDF canonicalization always
/// hashes with SHA-256 internally regardless of the signature curve; the
/// suite-specific hash (SHA-256/384) is applied later to the canonical
/// N-Quads bytes.
enum Canonicalization {
    /// Expand `json` to an RDF dataset and return it as `RDFCanonize` quads.
    static func toRDFQuads(
        _ json: JSONValue,
        loader: any JSONLDDocumentLoader,
        base: URL? = nil
    ) async throws -> [RDFCanonize.Quad] {
        var options = JSONLD.Options()
        options.documentLoader = loader
        options.base = base
        let dataset: JSONLD.Dataset
        do {
            dataset = try await JSONLD.toRDF(json.jsonLD, options: options)
        } catch {
            throw DataIntegrityError(
                .canonicalizationFailed,
                "JSON-LD to RDF conversion failed: \(error.localizedDescription)"
            )
        }
        return dataset.allQuads.map(mapQuad)
    }

    /// Canonical N-Quads string (RDFC-1.0) for a JSON-LD document.
    static func canonicalize(
        _ json: JSONValue,
        loader: any JSONLDDocumentLoader,
        base: URL? = nil
    ) async throws -> String {
        let quads = try await toRDFQuads(json, loader: loader, base: base)
        do {
            return try RDFCanonize.canonicalize(quads: quads)
        } catch {
            throw DataIntegrityError(
                .canonicalizationFailed,
                "RDF canonicalization failed: \(error.localizedDescription)"
            )
        }
    }

    /// Canonical N-Quads as an array of lines (each WITHOUT the trailing
    /// newline). Used by the selective-disclosure paths, which index into
    /// the statement list.
    static func canonicalNQuadLines(
        _ json: JSONValue,
        loader: any JSONLDDocumentLoader,
        base: URL? = nil
    ) async throws -> [String] {
        let canonical = try await canonicalize(json, loader: loader, base: base)
        return NQuadLines.split(canonical)
    }

    // MARK: - Quad mapping (JSONLD.Quad -> RDFCanonize.Quad)

    private static func mapQuad(_ q: JSONLD.Quad) -> RDFCanonize.Quad {
        RDFCanonize.Quad(
            subject: mapTerm(q.subject),
            predicate: mapTerm(q.predicate),
            object: mapTerm(q.object),
            graph: q.graph.map(mapTerm)
        )
    }

    private static func mapTerm(_ t: JSONLD.Term) -> RDFCanonize.Term {
        switch t {
        case .iri(let s):
            return .iri(s)
        case .blankNode(let id):
            return .blankNode(id)
        case .literal(let l):
            return .literal(RDFCanonize.Literal(
                value: l.value,
                datatype: l.datatype,
                language: l.language,
                direction: l.direction
            ))
        }
    }
}

/// Helpers for working with canonical N-Quads line lists.
enum NQuadLines {
    /// Split a canonical N-Quads string into lines without trailing
    /// newlines (drops the final empty element after the trailing `\n`).
    static func split(_ nquads: String) -> [String] {
        var lines = nquads.components(separatedBy: "\n")
        if lines.last == "" { lines.removeLast() }
        return lines
    }

    /// Join lines back into a canonical N-Quads string (each line gets a
    /// trailing newline), matching `Array.join('')` over `"...\n"` lines in
    /// the reference implementation.
    static func join(_ lines: [String]) -> String {
        lines.map { $0 + "\n" }.joined()
    }
}
