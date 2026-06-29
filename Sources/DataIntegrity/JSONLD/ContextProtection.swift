import Foundation

/// Recursively removes `@protected` flags from a JSON-LD context.
///
/// Mirrors the Android wallet's `ProtectedStrippingLoader`
/// (DataIntegrityCanonizeModule.kt) and the server-side signer's loader.
/// Removing `@protected` relaxes only JSON-LD 1.1's strict
/// "protected term redefinition" check; it does NOT change any term→IRI
/// mapping, so the canonical N-Quads — and therefore the signature — are
/// byte-for-byte identical. This is required to expand credentials that
/// combine contexts from different ecosystems (e.g. OpenBadge 3.0.3 +
/// VCDM v2).
enum ContextProtection {
    static func stripProtected(_ value: JSONValue) -> JSONValue {
        switch value {
        case .object(let o):
            var out: [String: JSONValue] = [:]
            out.reserveCapacity(o.count)
            for (k, v) in o where k != "@protected" {
                out[k] = stripProtected(v)
            }
            return .object(out)
        case .array(let a):
            return .array(a.map(stripProtected))
        default:
            return value
        }
    }
}
