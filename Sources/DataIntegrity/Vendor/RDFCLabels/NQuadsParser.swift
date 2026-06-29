import Foundation

extension RDFCLabels {
    /// Minimal N-Quads parser. Follows the [RDF 1.1 N-Quads grammar](https://www.w3.org/TR/n-quads/#sec-grammar)
    /// closely enough for the W3C rdf-canon test suite. Permissive
    /// rather than strict — invalid lines are skipped.
    enum NQuadsParser {
        enum ParseError: Error, CustomStringConvertible {
            case malformedLine(String)
            var description: String {
                switch self {
                case .malformedLine(let s): return "malformed N-Quads line: \(s)"
                }
            }
        }

        static func parse(_ input: String) throws -> [Quad] {
            var quads: [Quad] = []
            // Split on LF, CR, and CRLF only. Splitting on the
            // `Character("\n")` misses CRLF because Swift treats `\r\n`
            // as a single extended grapheme cluster, and using
            // `CharacterSet.newlines` would over-split on Unicode
            // newline-class characters (e.g. U+0085 NEL) that can
            // legitimately appear inside literal values (W3C `test060`).
            for raw in splitLines(input) {
                var line = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                // Strip trailing dot (and any whitespace before it).
                if line.hasSuffix(".") {
                    line = String(line.dropLast()).trimmingCharacters(in: .whitespacesAndNewlines)
                }
                if line.isEmpty || line.hasPrefix("#") { continue }
                let terms = try tokenize(line)
                guard terms.count == 3 || terms.count == 4 else {
                    throw ParseError.malformedLine(line)
                }
                quads.append(Quad(
                    subject: terms[0],
                    predicate: terms[1],
                    object: terms[2],
                    graph: terms.count == 4 ? terms[3] : nil
                ))
            }
            return quads
        }

        /// Split `input` into lines on LF, CR, or CRLF only. Walking
        /// the Unicode scalar view keeps surrogate pairs intact and
        /// avoids over-splitting on Unicode newline-class characters
        /// that legitimately appear inside literals (e.g. U+0085 NEL).
        private static func splitLines(_ input: String) -> [String] {
            var out: [String] = []
            var current = ""
            let scalars = input.unicodeScalars
            var i = scalars.startIndex
            while i < scalars.endIndex {
                let s = scalars[i]
                if s.value == 0x0D {
                    // CR — consume the optional LF that may follow.
                    out.append(current)
                    current = ""
                    let next = scalars.index(after: i)
                    if next < scalars.endIndex, scalars[next].value == 0x0A {
                        i = scalars.index(after: next)
                    } else {
                        i = next
                    }
                    continue
                }
                if s.value == 0x0A {
                    out.append(current)
                    current = ""
                    i = scalars.index(after: i)
                    continue
                }
                current.unicodeScalars.append(s)
                i = scalars.index(after: i)
            }
            out.append(current)
            return out
        }

        /// Tokenize a single (already dot-trimmed) N-Quads line into
        /// 3 or 4 RDF terms.
        private static func tokenize(_ line: String) throws -> [Term] {
            var out: [Term] = []
            var idx = line.startIndex
            let end = line.endIndex
            while idx < end {
                // Skip whitespace.
                while idx < end, line[idx].isWhitespace { idx = line.index(after: idx) }
                guard idx < end else { break }

                let ch = line[idx]
                if ch == "<" {
                    // IRI: <...>
                    guard let close = line.range(of: ">", range: idx..<end) else {
                        throw ParseError.malformedLine(line)
                    }
                    let raw = String(line[line.index(after: idx)..<close.lowerBound])
                    out.append(.iri(unescapeIRI(raw)))
                    idx = close.upperBound
                } else if ch == "_" {
                    // Blank node: _:label
                    var labelEnd = line.index(after: idx)
                    if labelEnd < end, line[labelEnd] == ":" {
                        labelEnd = line.index(after: labelEnd)
                    }
                    while labelEnd < end, !line[labelEnd].isWhitespace {
                        labelEnd = line.index(after: labelEnd)
                    }
                    out.append(.blankNode(String(line[idx..<labelEnd])))
                    idx = labelEnd
                } else if ch == "\"" {
                    // Literal: "lex"[^^<dt>|@lang][@dir? — 1.1 not parsed]
                    let lexStart = line.index(after: idx)
                    var i = lexStart
                    var escaped = false
                    while i < end {
                        if escaped { escaped = false; i = line.index(after: i); continue }
                        if line[i] == "\\" { escaped = true; i = line.index(after: i); continue }
                        if line[i] == "\"" { break }
                        i = line.index(after: i)
                    }
                    guard i < end else { throw ParseError.malformedLine(line) }
                    let lex = unescape(String(line[lexStart..<i]))
                    var datatype = Literal.xsdString
                    var lang: String? = nil
                    idx = line.index(after: i) // step past closing "
                    if idx < end, line[idx] == "@" {
                        idx = line.index(after: idx)
                        var langEnd = idx
                        while langEnd < end, !line[langEnd].isWhitespace { langEnd = line.index(after: langEnd) }
                        lang = String(line[idx..<langEnd])
                        datatype = Literal.rdfLangString
                        idx = langEnd
                    } else if idx < end, line[idx] == "^",
                              line.index(after: idx) < end,
                              line[line.index(after: idx)] == "^"
                    {
                        idx = line.index(idx, offsetBy: 2)
                        guard idx < end, line[idx] == "<",
                              let close = line.range(of: ">", range: idx..<end)
                        else { throw ParseError.malformedLine(line) }
                        datatype = unescapeIRI(String(line[line.index(after: idx)..<close.lowerBound]))
                        idx = close.upperBound
                    }
                    out.append(.literal(Literal(value: lex, datatype: datatype, language: lang)))
                } else {
                    throw ParseError.malformedLine(line)
                }
            }
            return out
        }

        /// Decode N-Quads literal escapes per
        /// [§3.1 STRING_LITERAL_QUOTE](https://www.w3.org/TR/n-quads/#sec-grammar):
        /// `\b \t \n \f \r \" \' \\` plus `\uXXXX` and `\UXXXXXXXX`.
        private static func unescape(_ s: String) -> String {
            var out = ""
            out.reserveCapacity(s.count)
            let chars = Array(s)
            var i = 0
            while i < chars.count {
                let ch = chars[i]
                if ch != "\\" { out.append(ch); i += 1; continue }
                guard i + 1 < chars.count else { out.append(ch); break }
                let next = chars[i + 1]
                switch next {
                case "b": out.append("\u{0008}"); i += 2
                case "t": out.append("\t");       i += 2
                case "n": out.append("\n");       i += 2
                case "f": out.append("\u{000C}"); i += 2
                case "r": out.append("\r");       i += 2
                case "\"": out.append("\"");      i += 2
                case "'":  out.append("'");       i += 2
                case "\\": out.append("\\");      i += 2
                case "u":
                    if let scalar = readHexScalar(chars, start: i + 2, length: 4) {
                        out.append(Character(scalar))
                        i += 6
                    } else {
                        out.append(next); i += 2
                    }
                case "U":
                    if let scalar = readHexScalar(chars, start: i + 2, length: 8) {
                        out.append(Character(scalar))
                        i += 10
                    } else {
                        out.append(next); i += 2
                    }
                default:
                    out.append(next); i += 2
                }
            }
            return out
        }

        /// Decode IRI escapes per
        /// [§3.1 IRIREF](https://www.w3.org/TR/n-quads/#sec-grammar):
        /// only `\uXXXX` and `\UXXXXXXXX` are recognized inside `<…>`.
        static func unescapeIRI(_ s: String) -> String {
            if !s.contains("\\") { return s }
            var out = ""
            out.reserveCapacity(s.count)
            let chars = Array(s)
            var i = 0
            while i < chars.count {
                let ch = chars[i]
                if ch != "\\" || i + 1 >= chars.count {
                    out.append(ch); i += 1; continue
                }
                let next = chars[i + 1]
                if next == "u", let scalar = readHexScalar(chars, start: i + 2, length: 4) {
                    out.append(Character(scalar)); i += 6
                } else if next == "U", let scalar = readHexScalar(chars, start: i + 2, length: 8) {
                    out.append(Character(scalar)); i += 10
                } else {
                    out.append(ch); i += 1
                }
            }
            return out
        }

        private static func readHexScalar(_ chars: [Character], start: Int, length: Int) -> Unicode.Scalar? {
            guard start + length <= chars.count else { return nil }
            var hex = ""
            hex.reserveCapacity(length)
            for j in start..<(start + length) {
                let c = chars[j]
                guard c.isHexDigit else { return nil }
                hex.append(c)
            }
            guard let value = UInt32(hex, radix: 16) else { return nil }
            return Unicode.Scalar(value)
        }
    }
}
