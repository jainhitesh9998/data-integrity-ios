import XCTest
@testable import DataIntegrity

/// Smoke tests for the JSON-LD → RDF → RDFC-1.0 pipeline using an inline
/// `@context` (no network / bundled contexts needed). Validates that the
/// canonical N-Quads output is byte-correct, since every signature path
/// depends on it.
final class CanonicalizeSmokeTests: XCTestCase {

    func testInlineContextCanonicalization() async throws {
        let doc = """
        {
          "@context": {
            "name": "http://schema.org/name",
            "knows": {"@id": "http://schema.org/knows", "@type": "@id"}
          },
          "@id": "http://example.com/alice",
          "name": "Alice",
          "knows": "http://example.com/bob"
        }
        """
        let client = DataIntegrityClient(documentLoader: ContextDocumentLoader(networkPolicy: .deny))
        let nquads = try await client.canonicalize(jsonLd: doc)

        let expected = """
        <http://example.com/alice> <http://schema.org/knows> <http://example.com/bob> .
        <http://example.com/alice> <http://schema.org/name> "Alice" .

        """
        XCTAssertEqual(nquads, expected)
    }

    func testBlankNodeCanonicalization() async throws {
        // Two anonymous nodes — exercises blank-node labeling (c14n).
        let doc = """
        {
          "@context": {"knows": {"@id": "http://schema.org/knows", "@type": "@id"},
                       "name": "http://schema.org/name"},
          "name": "Root",
          "knows": {"name": "Friend"}
        }
        """
        let client = DataIntegrityClient(documentLoader: ContextDocumentLoader(networkPolicy: .deny))
        let nquads = try await client.canonicalize(jsonLd: doc)
        // Blank nodes must be relabeled to _:c14nN in lexicographic order.
        XCTAssertTrue(nquads.contains("_:c14n0"))
        XCTAssertTrue(nquads.contains("\"Root\""))
        XCTAssertTrue(nquads.contains("\"Friend\""))
        XCTAssertTrue(nquads.hasSuffix("\n"))
    }
}
