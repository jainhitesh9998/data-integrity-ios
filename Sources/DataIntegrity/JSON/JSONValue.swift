import Foundation
import JSONLD

/// A JSON value model used internally for credential/proof manipulation
/// (field access, selection, skolemization) and as the bridge to
/// ``JSONLD/JSON`` for canonicalization.
///
/// Object keys are unordered: every downstream consumer either re-parses
/// the JSON (the React Native bridge) or canonicalizes it to RDF (which is
/// order-independent), so key order is never significant.
public indirect enum JSONValue: Sendable, Hashable {
    case null
    case bool(Bool)
    case int(Int64)
    case double(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])
}

// MARK: - Parsing / serialization

extension JSONValue {
    /// Parse a JSON document from a UTF-8 string.
    public init(parsing string: String) throws {
        guard let data = string.data(using: .utf8) else {
            throw DataIntegrityError(.invalidJSON, "input is not valid UTF-8")
        }
        try self.init(parsing: data)
    }

    /// Parse a JSON document from raw bytes.
    ///
    /// Uses a correctly-rounded parser (``JSONParser``) rather than
    /// `JSONSerialization`, whose number parsing is not correctly-rounded for
    /// extreme decimal literals (e.g. `0.000…01`) and could diverge from the
    /// signer's canonical bytes.
    public init(parsing data: Data) throws {
        self = try JSONParser.parse(data)
    }

    /// Bridge a Foundation JSON object (from `JSONSerialization`) into `JSONValue`.
    ///
    /// `NSNumber` is disambiguated the same way `swift-jsonld` does it
    /// internally: `CFBoolean` → `.bool`; floating objCTypes (`d`/`f`) →
    /// `.double`; everything else → `.int`. Preserving the integer/double
    /// split matters because JSON-LD maps them to distinct XSD datatypes,
    /// which changes the canonical N-Quads (and therefore the signature).
    public init(_ any: Any) {
        switch any {
        case is NSNull:
            self = .null
        case let n as NSNumber:
            if CFGetTypeID(n) == CFBooleanGetTypeID() {
                self = .bool(n.boolValue)
            } else {
                let objCType = String(cString: n.objCType)
                if objCType == "d" || objCType == "f" {
                    self = .double(n.doubleValue)
                } else {
                    self = .int(n.int64Value)
                }
            }
        case let s as String:
            self = .string(s)
        case let a as [Any]:
            self = .array(a.map(JSONValue.init))
        case let d as [String: Any]:
            self = .object(d.mapValues(JSONValue.init))
        default:
            // Bool can also arrive as a plain Swift Bool in some paths.
            if let b = any as? Bool { self = .bool(b) }
            else { self = .null }
        }
    }

    /// Convert back to a Foundation JSON object suitable for `JSONSerialization`.
    public var foundationObject: Any {
        switch self {
        case .null: return NSNull()
        case .bool(let b): return b
        case .int(let i): return i
        case .double(let d): return d
        case .string(let s): return s
        case .array(let a): return a.map { $0.foundationObject }
        case .object(let o): return o.mapValues { $0.foundationObject }
        }
    }

    /// Serialize back to a compact JSON string.
    public func serialized() throws -> String {
        let data = try JSONSerialization.data(
            withJSONObject: foundationObject,
            options: [.fragmentsAllowed, .withoutEscapingSlashes]
        )
        guard let s = String(data: data, encoding: .utf8) else {
            throw DataIntegrityError(.invalidJSON, "could not encode JSON output")
        }
        return s
    }
}

// MARK: - Accessors

extension JSONValue {
    public var objectValue: [String: JSONValue]? {
        if case .object(let o) = self { return o }
        return nil
    }

    public var arrayValue: [JSONValue]? {
        if case .array(let a) = self { return a }
        return nil
    }

    public var stringValue: String? {
        if case .string(let s) = self { return s }
        return nil
    }

    public var isNull: Bool {
        if case .null = self { return true }
        return false
    }

    public subscript(key: String) -> JSONValue? {
        get { objectValue?[key] }
        set {
            guard case .object(var o) = self else { return }
            o[key] = newValue
            self = .object(o)
        }
    }

    /// Return a copy of this object with `key` removed (no-op if not an object).
    public func removing(_ key: String) -> JSONValue {
        guard case .object(var o) = self else { return self }
        o.removeValue(forKey: key)
        return .object(o)
    }

    /// Treat the value as an array, returning `[self]` for a single object.
    /// Mirrors the JSON-LD convention where a property may be a single
    /// value or an array of values.
    public var asArray: [JSONValue] {
        switch self {
        case .array(let a): return a
        case .null: return []
        default: return [self]
        }
    }
}

// MARK: - Bridge to JSONLD.JSON

extension JSONValue {
    /// Convert to the `swift-jsonld` JSON model for canonicalization.
    public var jsonLD: JSONLD.JSON {
        switch self {
        case .null: return .null
        case .bool(let b): return .bool(b)
        case .int(let i): return .int(i)
        case .double(let d): return .double(d)
        case .string(let s): return .string(s)
        case .array(let a): return .array(a.map { $0.jsonLD })
        case .object(let o): return .object(o.mapValues { $0.jsonLD })
        }
    }

    /// Build from the `swift-jsonld` JSON model (e.g. expand/compact output).
    public init(jsonLD: JSONLD.JSON) {
        switch jsonLD {
        case .null: self = .null
        case .bool(let b): self = .bool(b)
        case .int(let i): self = .int(i)
        case .double(let d): self = .double(d)
        case .string(let s): self = .string(s)
        case .array(let a): self = .array(a.map(JSONValue.init(jsonLD:)))
        case .object(let o): self = .object(o.mapValues(JSONValue.init(jsonLD:)))
        }
    }
}
