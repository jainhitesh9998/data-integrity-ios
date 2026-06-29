import Foundation
import JSONLD

/// Skolemization of JSON-LD blank nodes (→ `urn:bnid:` IRIs) so that JSON
/// Pointer selections produce RDF statements with stable identities matching
/// the full document. Port of digitalbazaar `di-sd-primitives` `skolemize.js`.
enum Skolemize {
    static let prefix = "urn:bnid:"

    /// Expand → skolemize → compact. Returns both forms (expanded is used for
    /// the full N-Quads; compact is used for pointer selection).
    static func skolemizeCompact(
        document: JSONValue,
        loader: any JSONLDDocumentLoader
    ) async throws -> (expanded: JSONValue, compact: JSONValue) {
        guard let context = document["@context"] else {
            throw DataIntegrityError(.invalidCredential, "document must have an @context to skolemize")
        }
        var options = JSONLD.Options()
        options.documentLoader = loader

        let expandedLD: JSONLD.JSON
        do {
            expandedLD = try await JSONLD.expand(document.jsonLD, options: options)
        } catch {
            throw DataIntegrityError(.canonicalizationFailed, "expand failed: \(error.localizedDescription)")
        }

        var counter = 0
        let random = UUID().uuidString
        let skolemizedExpanded = skolemizeExpanded(
            JSONValue(jsonLD: expandedLD), counter: &counter, random: random)

        let compactLD: JSONLD.JSON
        do {
            compactLD = try await JSONLD.compact(skolemizedExpanded.jsonLD, context: context.jsonLD, options: options)
        } catch {
            throw DataIntegrityError(.canonicalizationFailed, "compact failed: \(error.localizedDescription)")
        }
        return (skolemizedExpanded, JSONValue(jsonLD: compactLD))
    }

    /// Walk an EXPANDED JSON-LD array, assigning `@id` to every node:
    /// id-less nodes get a fresh `urn:bnid:_<random>_<n>`; `_:` ids become
    /// `urn:bnid:<id>`. Literals/value objects are copied as-is.
    static func skolemizeExpanded(_ expanded: JSONValue, counter: inout Int, random: String) -> JSONValue {
        let elements = expanded.arrayValue ?? [expanded]
        var out: [JSONValue] = []
        for element in elements {
            guard case .object(let obj) = element, obj["@value"] == nil else {
                out.append(element)  // literal / value object / non-object
                continue
            }
            var node: [String: JSONValue] = [:]
            for (property, value) in obj {
                if case .array = value {
                    node[property] = skolemizeExpanded(value, counter: &counter, random: random)
                } else {
                    let skolemized = skolemizeExpanded(.array([value]), counter: &counter, random: random)
                    node[property] = skolemized.arrayValue?.first ?? value
                }
            }
            if node["@id"] == nil {
                node["@id"] = .string("\(prefix)_\(random)_\(counter)")
                counter += 1
            } else if case .string(let id)? = node["@id"], id.hasPrefix("_:") {
                node["@id"] = .string("\(prefix)\(id.dropFirst(2))")
            }
            out.append(.object(node))
        }
        return .array(out)
    }

    /// Convert a (skolemized) JSON-LD document to deskolemized N-Quad lines
    /// (blank nodes restored), serialized with the vendored canonical writer so
    /// they match the canonicalized output for string-based grouping.
    static func toDeskolemizedNQuads(
        document: JSONValue,
        loader: any JSONLDDocumentLoader
    ) async throws -> [String] {
        var options = JSONLD.Options()
        options.documentLoader = loader
        let dataset: JSONLD.Dataset
        do {
            dataset = try await JSONLD.toRDF(document.jsonLD, options: options)
        } catch {
            throw DataIntegrityError(.canonicalizationFailed, "toRDF failed: \(error.localizedDescription)")
        }
        return dataset.allQuads.map { RDFCLabels.NQuadsWriter.serialize(quad: deskolemize(mapQuad($0))) }
    }

    // MARK: - Quad mapping + deskolemization

    private static func mapQuad(_ q: JSONLD.Quad) -> RDFCLabels.Quad {
        RDFCLabels.Quad(
            subject: mapTerm(q.subject),
            predicate: mapTerm(q.predicate),
            object: mapTerm(q.object),
            graph: q.graph.map(mapTerm)
        )
    }

    private static func mapTerm(_ t: JSONLD.Term) -> RDFCLabels.Term {
        switch t {
        case .iri(let s): return .iri(s)
        case .blankNode(let id): return .blankNode(id)
        case .literal(let l):
            return .literal(RDFCLabels.Literal(
                value: l.value, datatype: l.datatype, language: l.language, direction: l.direction))
        }
    }

    /// `<urn:bnid:X>` → `_:X` at the term level.
    private static func deskolemize(_ q: RDFCLabels.Quad) -> RDFCLabels.Quad {
        RDFCLabels.Quad(
            subject: deskolemizeTerm(q.subject),
            predicate: deskolemizeTerm(q.predicate),
            object: deskolemizeTerm(q.object),
            graph: q.graph.map(deskolemizeTerm)
        )
    }

    private static func deskolemizeTerm(_ t: RDFCLabels.Term) -> RDFCLabels.Term {
        if case .iri(let s) = t, s.hasPrefix(prefix) {
            return .blankNode(String(s.dropFirst(prefix.count)))
        }
        return t
    }
}
