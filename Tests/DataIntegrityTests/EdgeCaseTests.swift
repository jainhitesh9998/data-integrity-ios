import XCTest
@testable import DataIntegrity

/// Document-loader branches and verifier error paths.
final class EdgeCaseTests: XCTestCase {
    let loader = ContextDocumentLoader(networkPolicy: .deny)

    func testBundledContextLoadsOffline() async throws {
        let url = URL(string: "https://www.w3.org/ns/credentials/v2")!
        let doc = try await loader.load(url: url)
        XCTAssertEqual(doc.documentURL, url)
        XCTAssertEqual(doc.contentType, "application/ld+json")
    }

    func testUnbundledContextDeniedThrows() async {
        do {
            _ = try await loader.load(url: URL(string: "https://example.com/no-such-context")!)
            XCTFail("expected documentLoaderFailed")
        } catch let error as DataIntegrityError {
            XCTAssertEqual(error.code, .documentLoaderFailed)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testCredentialWithoutProofFails() async throws {
        let vc = """
        {"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],"issuer":"did:example:x"}
        """
        let result = try await DataIntegrityClient(documentLoader: loader).verifyCredential(vc)
        XCTAssertFalse(result.verified)
        XCTAssertNotNil(result.reason)
    }

    func testUnsupportedCryptosuiteFails() async throws {
        let vc = """
        {"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],
         "issuer":"did:example:x",
         "proof":{"type":"DataIntegrityProof","cryptosuite":"bbs-2023",
                  "verificationMethod":"did:key:zDnaeQa8zprPhHA7Yuxcgc2Uh6XNQgaKjmFZE4EaA9fk5svmJ",
                  "proofPurpose":"assertionMethod","proofValue":"zAbC"}}
        """
        let result = try await DataIntegrityClient(documentLoader: loader).verifyCredential(vc)
        XCTAssertFalse(result.verified)
        XCTAssertEqual(result.cryptosuite, "bbs-2023")
    }

    func testInvalidJSONThrows() async {
        do {
            _ = try await DataIntegrityClient(documentLoader: loader).verifyCredential("{not json")
            XCTFail("expected invalidJSON")
        } catch let error as DataIntegrityError {
            XCTAssertEqual(error.code, .invalidJSON)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }
}
