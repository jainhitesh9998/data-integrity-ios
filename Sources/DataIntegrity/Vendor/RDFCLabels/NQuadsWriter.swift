import Foundation

extension RDFCLabels {
    /// Serializer for RDF terms and quads in N-Quads form.
    enum NQuadsWriter {
        static func serialize(quads: [Quad]) -> String {
            var lines: [String] = []
            for q in quads { lines.append(serialize(quad: q)) }
            return lines.joined(separator: "\n") + (lines.isEmpty ? "" : "\n")
        }

        static func serialize(quad: Quad) -> String {
            var s = "\(serialize(term: quad.subject)) \(serialize(term: quad.predicate)) \(serialize(term: quad.object))"
            if let g = quad.graph { s += " \(serialize(term: g))" }
            s += " ."
            return s
        }

        static func serialize(term: Term) -> String {
            switch term {
            case .iri(let iri):
                return "<\(escapeIRI(iri))>"
            case .blankNode(let id):
                return id.hasPrefix("_:") ? id : "_:\(id)"
            case .literal(let lit):
                var s = "\"\(escapeLiteral(lit.value))\""
                if let lang = lit.language {
                    s += "@\(lang)"
                } else if lit.datatype != Literal.xsdString {
                    s += "^^<\(escapeIRI(lit.datatype))>"
                }
                return s
            }
        }

        /// Canonical N-Triples literal escapes —
        /// [§4.1](https://www.w3.org/TR/n-triples/#canonical-ntriples).
        /// Escape chars in `[
        /// for `\b \t \n \f \r \" \\`; everything else in the range as
        /// `\uXXXX` with upper-case hex.
        private static func escapeLiteral(_ s: String) -> String {
            var out = ""
            out.reserveCapacity(s.count)
            for scalar in s.unicodeScalars {
                let v = scalar.value
                switch v {
                case 0x22: out += "\\\""
                case 0x5C: out += "\\\\"
                case 0x08: out += "\\b"
                case 0x09: out += "\\t"
                case 0x0A: out += "\\n"
                case 0x0C: out += "\\f"
                case 0x0D: out += "\\r"
                case 0x00...0x1F, 0x7F:
                    out += String(format: "\\u%04X", v)
                default:
                    out.unicodeScalars.append(scalar)
                }
            }
            return out
        }

        // IRI escapes per the JS reference: controls (U+0000..U+0020),
        // structural delimiters <>"{}|^`\\, escaped as \uXXXX uppercase.
        private static func escapeIRI(_ s: String) -> String {
            var out = ""
            out.reserveCapacity(s.count)
            for scalar in s.unicodeScalars {
                let v = scalar.value
                if v <= 0x20
                    || v == 0x3C  // <
                    || v == 0x3E  // >
                    || v == 0x22  // "
                    || v == 0x7B  // {
                    || v == 0x7D  // }
                    || v == 0x7C  // |
                    || v == 0x5E  // ^
                    || v == 0x60  // `
                    || v == 0x5C  // \
                {
                    out += String(format: "\\u%04X", v)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
            return out
        }
    }
}
