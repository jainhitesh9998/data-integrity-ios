import Foundation

/// JSON Canonicalization Scheme — RFC 8785. Used by the `ecdsa-jcs-2019`
/// cryptosuite, which canonicalizes the JSON document directly (object keys
/// sorted by UTF-16 code unit, no insignificant whitespace) rather than via RDF.
enum JCS {
    static func canonicalize(_ value: JSONValue) -> String {
        switch value {
        case .null:
            return "null"
        case .bool(let b):
            return b ? "true" : "false"
        case .int(let i):
            return String(i)
        case .double(let d):
            return number(d)
        case .string(let s):
            return string(s)
        case .array(let items):
            return "[" + items.map(canonicalize).joined(separator: ",") + "]"
        case .object(let object):
            let keys = object.keys.sorted(by: lessUTF16)
            let entries = keys.map { string($0) + ":" + canonicalize(object[$0]!) }
            return "{" + entries.joined(separator: ",") + "}"
        }
    }

    /// RFC 8785 §3.2.2.2 string serialization: escape `" \ \b \t \n \f \r` and
    /// other control characters as lowercase `\u00xx`; everything else literal.
    static func string(_ s: String) -> String {
        var out = "\""
        for scalar in s.unicodeScalars {
            switch scalar.value {
            case 0x22: out += "\\\""
            case 0x5C: out += "\\\\"
            case 0x08: out += "\\b"
            case 0x09: out += "\\t"
            case 0x0A: out += "\\n"
            case 0x0C: out += "\\f"
            case 0x0D: out += "\\r"
            case 0x00...0x1F: out += String(format: "\\u%04x", scalar.value)
            default: out.unicodeScalars.append(scalar)
            }
        }
        out += "\""
        return out
    }

    /// RFC 8785 §3.2.2.3 number serialization (ECMAScript `Number.toString`).
    /// Integers and integer-valued doubles serialize without a fractional part;
    /// other doubles use Swift's shortest round-trip form.
    static func number(_ d: Double) -> String {
        if d == 0 { return "0" }
        if d.rounded() == d && abs(d) < 9_007_199_254_740_992 {
            return String(Int64(d))
        }
        var s = String(d)
        if s.hasSuffix(".0") { s.removeLast(2) }
        return s
    }

    /// JS-compatible (UTF-16 code unit) string ordering for object keys.
    static func lessUTF16(_ a: String, _ b: String) -> Bool {
        let au = Array(a.utf16)
        let bu = Array(b.utf16)
        let n = Swift.min(au.count, bu.count)
        var i = 0
        while i < n {
            if au[i] != bu[i] { return au[i] < bu[i] }
            i += 1
        }
        return au.count < bu.count
    }
}
