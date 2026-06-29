import XCTest
import Crypto
@testable import DataIntegrity

/// `did:web` / `https` URL derivation, verification-method lookup, and the
/// offline `did:key` path / error branches of `KeyResolver`.
final class KeyResolverTests: XCTestCase {
    func testDidWebBareHost() throws {
        XCTAssertEqual(try KeyResolver.didToHTTPSURL("did:web:example.com").absoluteString,
                       "https://example.com/.well-known/did.json")
    }

    func testDidWebWithPath() throws {
        XCTAssertEqual(
            try KeyResolver.didToHTTPSURL("did:web:jainhitesh9998.github.io:data-integrity-ios").absoluteString,
            "https://jainhitesh9998.github.io/data-integrity-ios/did.json")
    }

    func testDidWebStripsFragment() throws {
        XCTAssertEqual(try KeyResolver.didToHTTPSURL("did:web:example.com:u:r#key-1").absoluteString,
                       "https://example.com/u/r/did.json")
    }

    func testHttpsVerificationMethod() throws {
        XCTAssertEqual(try KeyResolver.didToHTTPSURL("https://example.com/issuer/did.json#k").absoluteString,
                       "https://example.com/issuer/did.json")
    }

    func testUnsupportedSchemeThrows() {
        XCTAssertThrowsError(try KeyResolver.didToHTTPSURL("did:example:123"))
    }

    func testFindVerificationMethod() throws {
        let doc = try JSONValue(parsing: """
        {"id":"did:web:e",
         "verificationMethod":[{"id":"did:web:e#key-1","type":"Multikey","publicKeyMultibase":"zABC"}],
         "assertionMethod":["did:web:e#key-1"]}
        """)
        XCTAssertEqual(
            KeyResolver.findVerificationMethod(in: doc, id: "did:web:e#key-1")?["publicKeyMultibase"]?.stringValue,
            "zABC")
        XCTAssertNil(KeyResolver.findVerificationMethod(in: doc, id: "did:web:e#missing"))
    }

    func testDidWebRequiresNetworkWhenDisabled() async {
        do {
            _ = try await KeyResolver(networkAllowed: false).resolve(verificationMethod: "did:web:example.com#k")
            XCTFail("expected failure when network is disabled")
        } catch let error as DataIntegrityError {
            XCTAssertEqual(error.code, .keyResolutionFailed)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testDidKeyP256ResolvesOffline() async throws {
        let didKey = TestSigner.didKeyP256(P256.Signing.PrivateKey().publicKey)
        let key = try await KeyResolver(networkAllowed: false).resolve(verificationMethod: didKey)
        XCTAssertEqual(key.curveName, "P-256")
    }

    func testDidKeyEd25519ResolvesOffline() async throws {
        let didKey = TestSigner.didKeyEd25519(Curve25519.Signing.PrivateKey().publicKey)
        let key = try await KeyResolver(networkAllowed: false).resolve(verificationMethod: didKey)
        XCTAssertTrue(key.isEd25519)
    }
}
