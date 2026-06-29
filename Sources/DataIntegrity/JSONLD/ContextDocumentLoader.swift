import Foundation
import JSONLD

/// A `JSONLDDocumentLoader` that resolves `@context` documents from a
/// bundled offline set first, then an in-memory cache, then (optionally)
/// the network — stripping `@protected` from every returned context.
///
/// Bundling the standard contexts makes verification deterministic,
/// offline-capable, and auditable; the network fallback keeps unknown
/// contexts working. See ``ContextProtection`` for why `@protected` is
/// stripped.
public final class ContextDocumentLoader: JSONLDDocumentLoader, @unchecked Sendable {
    public enum NetworkPolicy: Sendable {
        /// Fetch unknown contexts over the network (default).
        case allow
        /// Never touch the network; unknown contexts throw. Use for
        /// strict, fully-deterministic verification.
        case deny
    }

    private let bundled: [String: JSONValue]
    private let networkPolicy: NetworkPolicy
    private let stripProtected: Bool
    private let cache = ContextCache()

    public init(
        bundledContexts: [String: JSONValue]? = nil,
        networkPolicy: NetworkPolicy = .allow,
        stripProtected: Bool = true
    ) {
        let base = bundledContexts ?? BundledContexts.load()
        self.networkPolicy = networkPolicy
        self.stripProtected = stripProtected
        // Pre-strip the bundled contexts once so repeated loads are cheap.
        if stripProtected {
            self.bundled = base.mapValues { ContextProtection.stripProtected($0) }
        } else {
            self.bundled = base
        }
    }

    public func load(url: URL) async throws -> JSONLD.RemoteDocument {
        let key = url.absoluteString

        if let ctx = bundled[key] {
            return makeDocument(url: url, document: ctx)
        }
        if let ctx = await cache.get(key) {
            return makeDocument(url: url, document: ctx)
        }

        guard networkPolicy == .allow else {
            throw DataIntegrityError(
                .documentLoaderFailed,
                "context \(key) is not bundled and network access is disabled"
            )
        }

        let data = try await Self.fetch(url)
        var ctx: JSONValue
        do {
            ctx = try JSONValue(parsing: data)
        } catch {
            throw DataIntegrityError(.documentLoaderFailed, "context \(key) is not valid JSON")
        }
        if stripProtected {
            ctx = ContextProtection.stripProtected(ctx)
        }
        await cache.set(key, ctx)
        return makeDocument(url: url, document: ctx)
    }

    private func makeDocument(url: URL, document: JSONValue) -> JSONLD.RemoteDocument {
        JSONLD.RemoteDocument(
            contentType: "application/ld+json",
            documentURL: url,
            document: document.jsonLD
        )
    }

    /// iOS 14-compatible async fetch (the async `URLSession.data(from:)`
    /// API requires iOS 15), implemented over `dataTask` + a continuation.
    private static func fetch(_ url: URL) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            var request = URLRequest(url: url)
            request.setValue("application/ld+json, application/json", forHTTPHeaderField: "Accept")
            let task = URLSession.shared.dataTask(with: request) { data, response, error in
                if let error = error {
                    continuation.resume(throwing: DataIntegrityError(
                        .documentLoaderFailed, "failed to fetch \(url.absoluteString): \(error.localizedDescription)"))
                    return
                }
                if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
                    continuation.resume(throwing: DataIntegrityError(
                        .documentLoaderFailed, "failed to fetch \(url.absoluteString): HTTP \(http.statusCode)"))
                    return
                }
                guard let data = data else {
                    continuation.resume(throwing: DataIntegrityError(
                        .documentLoaderFailed, "empty response for \(url.absoluteString)"))
                    return
                }
                continuation.resume(returning: data)
            }
            task.resume()
        }
    }
}

/// Actor-isolated cache for network-fetched contexts.
private actor ContextCache {
    private var store: [String: JSONValue] = [:]
    func get(_ key: String) -> JSONValue? { store[key] }
    func set(_ key: String, _ value: JSONValue) { store[key] = value }
}
