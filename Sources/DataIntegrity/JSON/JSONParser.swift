import Foundation

/// A small, strict, **correctly-rounded** JSON parser used by
/// `JSONValue(parsing:)`.
///
/// It replaces `JSONSerialization` for *parsing* because Foundation's parser is
/// not correctly-rounded for extreme decimal literals — e.g. it reads
/// `0.000…01` as a `Double` one ULP off from `1e-27`. A signer (typically JS,
/// which is correctly-rounded) would canonicalize the true value, so the
/// mis-rounding could change our canonical bytes and break a signature. Swift's
/// `Double(String)` and `Int64(String)` are correctly-rounded, so numbers are
/// parsed straight from their literal text.
///
/// It preserves the integer/double split that the JSON-LD → RDF mapping depends
/// on: a literal with no `.`/`e`/`E` that fits `Int64` is `.int`, otherwise
/// `.double`. Object/array/string/escape handling matches RFC 8259 (top-level
/// fragments are allowed, matching the previous `.fragmentsAllowed` behaviour).
enum JSONParser {
    static func parse(_ data: Data) throws -> JSONValue {
        guard let string = String(data: data, encoding: .utf8) else {
            throw DataIntegrityError(.invalidJSON, "input is not valid UTF-8")
        }
        var scanner = Scanner(Array(string.unicodeScalars))
        scanner.skipWhitespace()
        let value = try scanner.parseValue()
        scanner.skipWhitespace()
        guard scanner.isAtEnd else {
            throw DataIntegrityError(.invalidJSON, "unexpected trailing data in JSON")
        }
        return value
    }

    private struct Scanner {
        let s: [Unicode.Scalar]
        var i = 0
        init(_ scalars: [Unicode.Scalar]) { s = scalars }
        var isAtEnd: Bool { i >= s.count }

        func err(_ message: String) -> DataIntegrityError { DataIntegrityError(.invalidJSON, message) }

        mutating func skipWhitespace() {
            while i < s.count {
                switch s[i].value {
                case 0x20, 0x09, 0x0A, 0x0D: i += 1   // space, tab, LF, CR
                default: return
                }
            }
        }

        mutating func parseValue() throws -> JSONValue {
            guard i < s.count else { throw err("unexpected end of JSON") }
            switch s[i] {
            case "{": return try parseObject()
            case "[": return try parseArray()
            case "\"": return .string(try parseString())
            case "t": guard matches("true") else { throw err("invalid literal") };  return .bool(true)
            case "f": guard matches("false") else { throw err("invalid literal") }; return .bool(false)
            case "n": guard matches("null") else { throw err("invalid literal") };  return .null
            default: return try parseNumber()
            }
        }

        mutating func parseObject() throws -> JSONValue {
            i += 1 // consume {
            var obj: [String: JSONValue] = [:]
            skipWhitespace()
            if i < s.count, s[i] == "}" { i += 1; return .object(obj) }
            while true {
                skipWhitespace()
                guard i < s.count, s[i] == "\"" else { throw err("expected object key") }
                let key = try parseString()
                skipWhitespace()
                guard i < s.count, s[i] == ":" else { throw err("expected ':' after object key") }
                i += 1
                skipWhitespace()
                obj[key] = try parseValue()        // last value wins on duplicate keys (matches JSONSerialization)
                skipWhitespace()
                guard i < s.count else { throw err("unterminated object") }
                if s[i] == "," { i += 1; continue }
                if s[i] == "}" { i += 1; break }
                throw err("expected ',' or '}' in object")
            }
            return .object(obj)
        }

        mutating func parseArray() throws -> JSONValue {
            i += 1 // consume [
            var arr: [JSONValue] = []
            skipWhitespace()
            if i < s.count, s[i] == "]" { i += 1; return .array(arr) }
            while true {
                skipWhitespace()
                arr.append(try parseValue())
                skipWhitespace()
                guard i < s.count else { throw err("unterminated array") }
                if s[i] == "," { i += 1; continue }
                if s[i] == "]" { i += 1; break }
                throw err("expected ',' or ']' in array")
            }
            return .array(arr)
        }

        mutating func parseString() throws -> String {
            i += 1 // consume opening "
            var result = ""
            while i < s.count {
                let c = s[i]
                if c == "\"" { i += 1; return result }
                if c == "\\" {
                    i += 1
                    guard i < s.count else { throw err("unterminated escape") }
                    switch s[i] {
                    case "\"": result.unicodeScalars.append("\""); i += 1
                    case "\\": result.unicodeScalars.append("\\"); i += 1
                    case "/":  result.unicodeScalars.append("/");  i += 1
                    case "b":  result.unicodeScalars.append(Unicode.Scalar(0x08)!); i += 1
                    case "f":  result.unicodeScalars.append(Unicode.Scalar(0x0C)!); i += 1
                    case "n":  result.unicodeScalars.append("\n"); i += 1
                    case "r":  result.unicodeScalars.append("\r"); i += 1
                    case "t":  result.unicodeScalars.append("\t"); i += 1
                    case "u":
                        i += 1
                        let cp = try readHex4()
                        if (0xD800...0xDBFF).contains(cp) {
                            guard i + 1 < s.count, s[i] == "\\", s[i + 1] == "u" else {
                                throw err("unpaired high surrogate")
                            }
                            i += 2
                            let lo = try readHex4()
                            guard (0xDC00...0xDFFF).contains(lo) else { throw err("invalid low surrogate") }
                            let combined = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                            guard let scalar = Unicode.Scalar(combined) else { throw err("invalid surrogate pair") }
                            result.unicodeScalars.append(scalar)
                        } else if (0xDC00...0xDFFF).contains(cp) {
                            throw err("unexpected low surrogate")
                        } else {
                            guard let scalar = Unicode.Scalar(cp) else { throw err("invalid \\u escape") }
                            result.unicodeScalars.append(scalar)
                        }
                    default: throw err("invalid escape sequence")
                    }
                } else {
                    result.unicodeScalars.append(c)
                    i += 1
                }
            }
            throw err("unterminated string")
        }

        /// Read exactly four hex digits (i positioned at the first digit), advancing past them.
        mutating func readHex4() throws -> Int {
            guard i + 4 <= s.count else { throw err("incomplete \\u escape") }
            var value = 0
            for _ in 0..<4 {
                guard let digit = hexValue(s[i].value) else { throw err("invalid hex digit in \\u escape") }
                value = value * 16 + digit
                i += 1
            }
            return value
        }

        private func hexValue(_ v: UInt32) -> Int? {
            switch v {
            case 0x30...0x39: return Int(v - 0x30)          // 0-9
            case 0x41...0x46: return Int(v - 0x41 + 10)     // A-F
            case 0x61...0x66: return Int(v - 0x61 + 10)     // a-f
            default: return nil
            }
        }

        mutating func parseNumber() throws -> JSONValue {
            let start = i
            var isInteger = true
            loop: while i < s.count {
                switch s[i].value {
                case 0x30...0x39, 0x2D, 0x2B: i += 1            // 0-9, '-', '+'
                case 0x2E, 0x65, 0x45: isInteger = false; i += 1 // '.', 'e', 'E'
                default: break loop
                }
            }
            guard i > start else { throw err("invalid value") }
            var token = ""
            token.unicodeScalars.append(contentsOf: s[start..<i])
            // Correctly-rounded conversions (unlike JSONSerialization's parser).
            if isInteger, let n = Int64(token) { return .int(n) }
            guard let d = Double(token) else { throw err("invalid number '\(token)'") }
            return .double(d)
        }

        mutating func matches(_ literal: String) -> Bool {
            let lit = Array(literal.unicodeScalars)
            guard i + lit.count <= s.count else { return false }
            for k in 0..<lit.count where s[i + k] != lit[k] { return false }
            i += lit.count
            return true
        }
    }
}
