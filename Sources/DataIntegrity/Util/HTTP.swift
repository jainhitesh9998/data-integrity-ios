import Foundation

/// Minimal async HTTP GET, iOS 14-compatible (the async `URLSession.data`
/// API requires iOS 15).
enum HTTP {
    static func get(_ url: URL, accept: String) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            var request = URLRequest(url: url)
            request.setValue(accept, forHTTPHeaderField: "Accept")
            let task = URLSession.shared.dataTask(with: request) { data, response, error in
                if let error = error {
                    continuation.resume(throwing: DataIntegrityError(
                        .keyResolutionFailed, "fetch \(url.absoluteString) failed: \(error.localizedDescription)"))
                    return
                }
                if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
                    continuation.resume(throwing: DataIntegrityError(
                        .keyResolutionFailed, "fetch \(url.absoluteString) failed: HTTP \(http.statusCode)"))
                    return
                }
                guard let data = data else {
                    continuation.resume(throwing: DataIntegrityError(
                        .keyResolutionFailed, "empty response for \(url.absoluteString)"))
                    return
                }
                continuation.resume(returning: data)
            }
            task.resume()
        }
    }
}
