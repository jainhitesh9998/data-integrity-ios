import XCTest
import Crypto
@testable import DataIntegrity

/// Round-trip tests for the non-selective-disclosure suites: sign a freshly
/// generated sample VC, then verify it. Runs fully offline against the
/// bundled contexts (network denied), so a pass proves canonicalization,
/// proof-config hashing, key resolution (did:key), multibase/multikey, and
/// the curve crypto are all consistent end-to-end.
final class RdfcVerifyTests: XCTestCase {
    let loader = ContextDocumentLoader(networkPolicy: .deny)

    /// A realistic VCDM 2.0 credential with a couple of custom-context terms.
    private func sampleCredential() throws -> JSONValue {
        try JSONValue(parsing: """
        {
          "@context": [
            "https://www.w3.org/ns/credentials/v2",
            {"ex": "https://example.org/vocab#", "fullName": "ex:fullName", "program": "ex:program"}
          ],
          "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
          "type": ["VerifiableCredential"],
          "issuer": "did:example:issuer-42",
          "validFrom": "2026-01-01T00:00:00Z",
          "credentialSubject": {
            "id": "did:example:subject-7",
            "fullName": "Alice Smith",
            "program": "BSc Computer Science"
          }
        }
        """)
    }

    private func tamper(_ signed: JSONValue) -> JSONValue {
        var obj = signed.objectValue!
        var subject = obj["credentialSubject"]!.objectValue!
        subject["fullName"] = .string("Mallory Jones")
        obj["credentialSubject"] = .object(subject)
        return .object(obj)
    }

    func testEcdsaRdfc2019RoundTrip() async throws {
        let key = P256.Signing.PrivateKey()
        let signed = try await TestSigner.signEcdsaRdfc2019(
            credential: try sampleCredential(), privateKey: key, loader: loader)
        let client = DataIntegrityClient(documentLoader: loader)

        let result = try await client.verifyCredential(try signed.serialized())
        XCTAssertTrue(result.verified, result.reason ?? "no reason")
        XCTAssertEqual(result.cryptosuite, "ecdsa-rdfc-2019")

        let tamperedResult = try await client.verifyCredential(try tamper(signed).serialized())
        XCTAssertFalse(tamperedResult.verified)
    }

    func testEcdsaRdfc2019P384RoundTrip() async throws {
        // P-384 exercises SHA-384 hashing + P-384 multikey/did:key + point decompression.
        let key = P384.Signing.PrivateKey()
        let signed = try await TestSigner.signEcdsaRdfc2019P384(
            credential: try sampleCredential(), privateKey: key, loader: loader)
        let client = DataIntegrityClient(documentLoader: loader)

        let result = try await client.verifyCredential(try signed.serialized())
        XCTAssertTrue(result.verified, result.reason ?? "no reason")
        XCTAssertEqual(result.cryptosuite, "ecdsa-rdfc-2019")

        let tamperedResult = try await client.verifyCredential(try tamper(signed).serialized())
        XCTAssertFalse(tamperedResult.verified)
    }

    func testEddsaRdfc2022RoundTrip() async throws {
        let key = Curve25519.Signing.PrivateKey()
        let signed = try await TestSigner.signEddsaRdfc2022(
            credential: try sampleCredential(), privateKey: key, loader: loader)
        let client = DataIntegrityClient(documentLoader: loader)

        let result = try await client.verifyCredential(try signed.serialized())
        XCTAssertTrue(result.verified, result.reason ?? "no reason")
        XCTAssertEqual(result.cryptosuite, "eddsa-rdfc-2022")

        let tamperedResult = try await client.verifyCredential(try tamper(signed).serialized())
        XCTAssertFalse(tamperedResult.verified)
    }

    func testEd25519Signature2020RoundTrip() async throws {
        let key = Curve25519.Signing.PrivateKey()
        let signed = try await TestSigner.signEd25519Signature2020(
            credential: try sampleCredential(), privateKey: key, loader: loader)
        let client = DataIntegrityClient(documentLoader: loader)

        let result = try await client.verifyCredential(try signed.serialized())
        XCTAssertTrue(result.verified, result.reason ?? "no reason")
        // Mapped onto the eddsa-rdfc-2022 algorithm.
        XCTAssertEqual(result.cryptosuite, "eddsa-rdfc-2022")

        let tamperedResult = try await client.verifyCredential(try tamper(signed).serialized())
        XCTAssertFalse(tamperedResult.verified)
    }

    func testCryptosuiteKeyMismatchFails() async throws {
        // Sign with Ed25519 but claim ecdsa-rdfc-2019 → must not verify.
        let key = Curve25519.Signing.PrivateKey()
        var signed = try await TestSigner.signEddsaRdfc2022(
            credential: try sampleCredential(), privateKey: key, loader: loader)
        var proof = signed["proof"]!.objectValue!
        proof["cryptosuite"] = .string("ecdsa-rdfc-2019")
        signed["proof"] = .object(proof)

        let client = DataIntegrityClient(documentLoader: loader)
        let result = try await client.verifyCredential(try signed.serialized())
        XCTAssertFalse(result.verified)
    }
}
