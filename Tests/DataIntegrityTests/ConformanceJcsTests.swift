import XCTest
@testable import DataIntegrity

/// Conformance against the **RFC 8785 (JSON Canonicalization Scheme)** reference
/// test data: each `input/X.json` is canonicalized by this library's `JCS` and
/// compared to the expected `output/X.json`. This validates the canonicalization
/// used by the `ecdsa-jcs-2019` / `eddsa-jcs-2022` suites.
///
/// Vectors: <https://github.com/cyberphone/json-canonicalization> (`testdata`),
/// bundled under `Vectors/jcs/`. See `Vectors/ATTRIBUTION.md`.
final class ConformanceJcsTests: XCTestCase {
    /// All RFC 8785 reference vectors now pass — including `values.json`
    /// (extreme-float canonicalization, e.g. `1e-27` written as `0.000…01`) — since
    /// `JSONValue` parses numbers with a correctly-rounded parser (`JSONParser`)
    /// instead of `JSONSerialization`.
    private let knownLimitations: Set<String> = []

    func testJcsReferenceVectors() throws {
        let inputs = (Bundle.module.urls(forResourcesWithExtension: "json", subdirectory: "Vectors/jcs/input") ?? [])
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
        try XCTSkipIf(inputs.isEmpty, "JCS vectors not bundled")

        var passed = 0
        var failures: [String] = []
        var skipped: [String] = []
        for inputURL in inputs {
            let name = inputURL.lastPathComponent
            if knownLimitations.contains(name) { skipped.append(name); continue }
            let expectedURL = inputURL
                .deletingLastPathComponent()      // .../jcs/input
                .deletingLastPathComponent()      // .../jcs
                .appendingPathComponent("output")
                .appendingPathComponent(name)
            guard let expectedData = try? Data(contentsOf: expectedURL),
                  let expected = String(data: expectedData, encoding: .utf8) else { continue }

            let value = try JSONValue(parsing: try Data(contentsOf: inputURL))
            let output = JCS.canonicalize(value)
            if output == trimTrailingNewlines(expected) { passed += 1 }
            else { failures.append("\(name):\n    expected: \(prefix(expected))\n    actual:   \(prefix(output))") }
        }
        print("[cyberphone JCS / RFC 8785] \(passed) passed, \(failures.count) failed, skipped(known): \(skipped.sorted())")
        XCTAssertTrue(
            failures.isEmpty,
            "JCS (RFC 8785) conformance failures (\(failures.count)):\n" + failures.joined(separator: "\n"))
        XCTAssertGreaterThan(passed, 0)
    }

    private func trimTrailingNewlines(_ s: String) -> String {
        var s = s
        while s.hasSuffix("\n") || s.hasSuffix("\r") { s.removeLast() }
        return s
    }

    private func prefix(_ s: String) -> String { String(s.prefix(140)) }
}
