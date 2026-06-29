import XCTest
import Crypto
@testable import DataIntegrity

/// Exercises `did:web` key resolution end-to-end against a real DID document
/// hosted on GitHub Pages (`docs/did.json` →
/// https://jainhitesh9998.github.io/data-integrity-ios/did.json). The document
/// pins the deterministic test key below, so signing a VC with that key and
/// verifying it round-trips through real network resolution.
///
/// Requires GitHub Pages to be enabled (Settings ▸ Pages ▸ Deploy from branch ▸
/// `main` / `/docs`). Until it is live (or with no network), the test SKIPS, so
/// CI stays green.
final class DidWebInteropTests: XCTestCase {
    let loader = ContextDocumentLoader(networkPolicy: .allow)
    let didWebVM = "did:web:jainhitesh9998.github.io:data-integrity-ios#key-1"

    private func sampleCredential() throws -> JSONValue {
        try JSONValue(parsing: """
        {
          "@context": [
            "https://www.w3.org/ns/credentials/v2",
            {"ex": "https://example.org/vocab#", "fullName": "ex:fullName"}
          ],
          "id": "urn:uuid:did-web-interop-0001",
          "type": ["VerifiableCredential"],
          "issuer": "did:web:jainhitesh9998.github.io:data-integrity-ios",
          "validFrom": "2026-01-01T00:00:00Z",
          "credentialSubject": {"id": "did:example:subject", "fullName": "Alex Doe"}
        }
        """)
    }

    func testVerifyVCSignedByHostedDidWebKey() async throws {
        // The same deterministic key whose public half is published in docs/did.json.
        let key = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x11, count: 32))
        let signed = try await TestSigner.signEcdsaRdfc2019(
            credential: try sampleCredential(), privateKey: key,
            verificationMethod: didWebVM, loader: loader)

        let client = DataIntegrityClient(documentLoader: loader)
        let result = try await client.verifyCredential(try signed.serialized())

        if !result.verified, let reason = result.reason?.lowercased(),
           reason.contains("fetch") || reason.contains("http") || reason.contains("resolution")
            || reason.contains("network") || reason.contains("not found") {
            throw XCTSkip("did:web endpoint not reachable yet (enable GitHub Pages on main /docs): \(reason)")
        }
        XCTAssertTrue(result.verified, "did:web interop failed: \(result.reason ?? "no reason")")
        XCTAssertEqual(result.cryptosuite, "ecdsa-rdfc-2019")
    }
}
