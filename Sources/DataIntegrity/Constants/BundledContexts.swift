import Foundation

/// Maps well-known `@context` URLs to the JSON files bundled with the
/// package (under `Resources/contexts`). Bundling these makes the common
/// VC verification paths deterministic and offline-capable.
///
/// Aliases (e.g. a versionless URL that redirects to a pinned version) map
/// to the same file. To add a context: drop the JSON under
/// `Resources/contexts/` and add a `url → filename` entry here.
public enum BundledContexts {
    /// `context URL` → `bundled filename` (without the `contexts/` prefix).
    public static let manifest: [String: String] = [
        "https://www.w3.org/ns/credentials/v2": "credentials-v2.json",
        "https://www.w3.org/2018/credentials/v1": "credentials-v1.json",
        "https://www.w3.org/ns/credentials/examples/v2": "credentials-examples-v2.json",
        "https://w3id.org/security/data-integrity/v2": "data-integrity-v2.json",
        "https://w3id.org/security/data-integrity/v1": "data-integrity-v1.json",
        "https://w3id.org/security/multikey/v1": "multikey-v1.json",
        "https://w3id.org/security/suites/ed25519-2020/v1": "ed25519-2020-v1.json",
        "https://w3id.org/security/suites/ed25519-2018/v1": "ed25519-2018-v1.json",
        "https://w3id.org/security/v2": "security-v2.json",
        "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json": "ob-v3p0-3.0.3.json",
        "https://purl.imsglobal.org/spec/ob/v3p0/context.json": "ob-v3p0-3.0.3.json",
        "https://w3id.org/first-responder/v1": "first-responder-v1.json",
        "https://w3id.org/vc/render-method/v2rc1": "render-method-v2rc1.json",
        "https://w3id.org/vc/render-method/v2rc2": "render-method-v2rc2.json",
    ]

    /// Load every bundled context that is present in the resource bundle.
    /// Missing files are skipped (so the loader simply falls back to the
    /// network for those), which keeps the package building before the
    /// JSON files are added.
    public static func load() -> [String: JSONValue] {
        var out: [String: JSONValue] = [:]
        for (url, filename) in manifest {
            let name = (filename as NSString).deletingPathExtension
            guard let fileURL = Bundle.module.url(
                forResource: name, withExtension: "json", subdirectory: "contexts"
            ) else { continue }
            guard
                let data = try? Data(contentsOf: fileURL),
                let json = try? JSONValue(parsing: data)
            else { continue }
            out[url] = json
        }
        return out
    }
}
