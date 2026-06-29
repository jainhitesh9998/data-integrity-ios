import XCTest
import Crypto
@testable import DataIntegrity

/// Full ecdsa-sd-2023 lifecycle: issue a base proof, derive a selectively
/// disclosed credential, then verify it. Exercises selectJsonLd, skolemize,
/// canonicalizeAndGroup, the HMAC label map, mandatory-index math, signature
/// filtering, and the verifier label map — all offline.
final class EcdsaSd2023DeriveTests: XCTestCase {
    let loader = ContextDocumentLoader(networkPolicy: .deny)

    private func sampleCredential() throws -> JSONValue {
        try JSONValue(parsing: """
        {
          "@context": [
            "https://www.w3.org/ns/credentials/v2",
            {
              "ex": "https://example.org/vocab#",
              "fullName": "ex:fullName",
              "program": "ex:program",
              "address": "ex:address",
              "city": "ex:city",
              "postalCode": "ex:postalCode"
            }
          ],
          "id": "urn:uuid:7c2e9a44-1111-4444-8888-aaaabbbbcccc",
          "type": ["VerifiableCredential"],
          "issuer": "did:example:university",
          "validFrom": "2026-01-01T00:00:00Z",
          "credentialSubject": {
            "id": "did:example:alice",
            "fullName": "Alice Smith",
            "program": "BSc Computer Science",
            "address": { "city": "Bengaluru", "postalCode": "560001" }
          }
        }
        """)
    }

    func testIssueDeriveVerifyLifecycle() async throws {
        let issuerKey = P256.Signing.PrivateKey()
        let ephemeralKey = P256.Signing.PrivateKey()
        let client = DataIntegrityClient(documentLoader: loader)

        // 1. Issuer creates a base proof; issuer/validFrom are mandatory.
        let base = try await TestSdIssuer.issueBaseProof(
            credential: try sampleCredential(),
            issuerKey: issuerKey,
            ephemeralKey: ephemeralKey,
            mandatoryPointers: ["/issuer", "/validFrom"],
            loader: loader)

        // 2. Holder derives, selectively disclosing only the address.
        let derivedJSON = try await client.deriveCredential(
            baseCredential: try base.serialized(),
            selectivePointers: ["/credentialSubject/address"])
        let derived = try JSONValue(parsing: derivedJSON)

        // 3. The derived credential discloses mandatory + selected fields only.
        let subject = derived["credentialSubject"]?.objectValue
        XCTAssertNotNil(derived["issuer"], "mandatory issuer must be disclosed")
        XCTAssertNotNil(derived["validFrom"], "mandatory validFrom must be disclosed")
        XCTAssertNotNil(subject?["address"], "selected address must be disclosed")
        XCTAssertNil(subject?["fullName"], "unselected fullName must NOT be disclosed")
        XCTAssertNil(subject?["program"], "unselected program must NOT be disclosed")
        XCTAssertEqual(derived["proof"]?["cryptosuite"]?.stringValue, "ecdsa-sd-2023")
        XCTAssertEqual(derived["proof"]?["proofValue"]?.stringValue?.first, "u")

        // 4. Verify the derived credential.
        let result = try await client.verifyCredential(derivedJSON)
        XCTAssertTrue(result.verified, result.reason ?? "no reason")
        XCTAssertEqual(result.cryptosuite, "ecdsa-sd-2023")
    }

    func testDeriveMandatoryOnly() async throws {
        let issuerKey = P256.Signing.PrivateKey()
        let ephemeralKey = P256.Signing.PrivateKey()
        let client = DataIntegrityClient(documentLoader: loader)

        let base = try await TestSdIssuer.issueBaseProof(
            credential: try sampleCredential(),
            issuerKey: issuerKey,
            ephemeralKey: ephemeralKey,
            mandatoryPointers: ["/issuer", "/validFrom", "/credentialSubject/fullName"],
            loader: loader)

        // Disclose nothing extra — only the mandatory statements.
        let derivedJSON = try await client.deriveCredential(
            baseCredential: try base.serialized(), selectivePointers: [])
        let result = try await client.verifyCredential(derivedJSON)
        XCTAssertTrue(result.verified, result.reason ?? "no reason")

        let derived = try JSONValue(parsing: derivedJSON)
        XCTAssertEqual(derived["credentialSubject"]?["fullName"]?.stringValue, "Alice Smith")
        XCTAssertNil(derived["credentialSubject"]?["program"])
    }

    func testTamperedDerivedFailsVerification() async throws {
        let issuerKey = P256.Signing.PrivateKey()
        let ephemeralKey = P256.Signing.PrivateKey()
        let client = DataIntegrityClient(documentLoader: loader)

        let base = try await TestSdIssuer.issueBaseProof(
            credential: try sampleCredential(),
            issuerKey: issuerKey, ephemeralKey: ephemeralKey,
            mandatoryPointers: ["/issuer"],
            loader: loader)
        let derivedJSON = try await client.deriveCredential(
            baseCredential: try base.serialized(),
            selectivePointers: ["/credentialSubject/address"])
        var derived = try JSONValue(parsing: derivedJSON)

        // Tamper the disclosed city.
        var subject = derived["credentialSubject"]!.objectValue!
        var address = subject["address"]!.objectValue!
        address["city"] = .string("Mumbai")
        subject["address"] = .object(address)
        derived["credentialSubject"] = .object(subject)

        let result = try await client.verifyCredential(try derived.serialized())
        XCTAssertFalse(result.verified)
    }
}
