import Foundation

/// Resolves a proof `verificationMethod` to a ``VerificationKey``.
///
/// Mirrors the wallet's `verifyDataIntegrity.ts`:
///  - `did:key:z…` → decode the embedded multikey locally (no network)
///  - `did:web:…` / `https://…` → fetch the controller/DID document and pick
///    the referenced method (`publicKeyMultibase` or `publicKeyJwk`).
struct KeyResolver {
    /// When false, only `did:key` resolves; `did:web`/`https` throw.
    var networkAllowed: Bool = true

    func resolve(verificationMethod: String) async throws -> VerificationKey {
        if verificationMethod.hasPrefix("did:key:") {
            let mb = String(verificationMethod.dropFirst("did:key:".count))
                .split(separator: "#").first.map(String.init) ?? ""
            let multikeyBytes = try Multibase.decode(mb)
            return try Multikey.decode(multikeyBytes)
        }

        guard networkAllowed else {
            throw DataIntegrityError(
                .keyResolutionFailed,
                "verificationMethod \(verificationMethod) requires network resolution, which is disabled")
        }

        let url = try Self.didToHTTPSURL(verificationMethod)
        let data = try await HTTP.get(url, accept: "application/json, application/did+json")
        let doc = try JSONValue(parsing: data)
        guard let vm = Self.findVerificationMethod(in: doc, id: verificationMethod) else {
            throw DataIntegrityError(.keyResolutionFailed, "verificationMethod not found in resolved document")
        }
        if let multibase = vm["publicKeyMultibase"]?.stringValue {
            return try Multikey.decode(try Multibase.decode(multibase))
        }
        if let jwk = vm["publicKeyJwk"]?.objectValue {
            return try JWKKey.decode(jwk)
        }
        throw DataIntegrityError(
            .unsupportedVerificationMethod, "verificationMethod has no supported public key encoding")
    }

    /// Map a `did:web` / `https` verification method to the document URL.
    static func didToHTTPSURL(_ verificationMethod: String) throws -> URL {
        let id = verificationMethod.split(separator: "#").first.map(String.init) ?? verificationMethod
        if id.hasPrefix("https://") {
            guard let url = URL(string: id) else {
                throw DataIntegrityError(.keyResolutionFailed, "invalid https verificationMethod")
            }
            return url
        }
        if id.hasPrefix("did:web:") {
            let rest = String(id.dropFirst("did:web:".count))
            let parts = rest.split(separator: ":", omittingEmptySubsequences: false)
                .map { $0.removingPercentEncoding ?? String($0) }
            guard let host = parts.first else {
                throw DataIntegrityError(.keyResolutionFailed, "invalid did:web verificationMethod")
            }
            let pathParts = Array(parts.dropFirst())
            let path = pathParts.isEmpty ? ".well-known" : pathParts.joined(separator: "/")
            guard let url = URL(string: "https://\(host)/\(path)/did.json") else {
                throw DataIntegrityError(.keyResolutionFailed, "could not build did:web URL")
            }
            return url
        }
        throw DataIntegrityError(
            .unsupportedVerificationMethod, "unsupported verificationMethod scheme: \(verificationMethod)")
    }

    /// Find the verification method entry whose `id` matches, searching the
    /// usual buckets and falling back to single-key controller documents.
    static func findVerificationMethod(in doc: JSONValue, id: String) -> [String: JSONValue]? {
        if let obj = doc.objectValue {
            if obj["id"]?.stringValue == id, obj["publicKeyMultibase"] != nil || obj["publicKeyJwk"] != nil {
                return obj
            }
            for bucket in ["verificationMethod", "assertionMethod", "authentication"] {
                for entry in (obj[bucket]?.arrayValue ?? []) {
                    if let e = entry.objectValue, e["id"]?.stringValue == id {
                        return e
                    }
                }
            }
            if obj["publicKeyMultibase"] != nil || obj["publicKeyJwk"] != nil {
                return obj
            }
        }
        return nil
    }
}
