import XCTest
import Crypto
@testable import DataIntegrity

/// Verifying / deriving credentials with assorted OPTIONAL fields and value
/// shapes — extra types, validUntil, name/description, an integer, a string
/// array, and a nested (blank-node) object — to exercise canonicalization and
/// selective disclosure beyond the minimal happy path.
final class OptionalFieldsTests: XCTestCase {
    let loader = ContextDocumentLoader(networkPolicy: .deny)
    var client: DataIntegrityClient { DataIntegrityClient(documentLoader: loader) }

    /// Custom terms live in an inline context; `name`/`description`/`validUntil`
    /// come from the bundled VCDM v2 context.
    private func minimalCredential() throws -> JSONValue {
        try JSONValue(parsing: """
        {
          "@context": ["https://www.w3.org/ns/credentials/v2",
                       {"ex":"https://example.org/vocab#","fullName":"ex:fullName"}],
          "id": "urn:uuid:min-0001",
          "type": ["VerifiableCredential"],
          "issuer": "did:example:issuer",
          "validFrom": "2026-01-01T00:00:00Z",
          "credentialSubject": {"id": "did:example:subject", "fullName": "Bob"}
        }
        """)
    }

    private func richCredential() throws -> JSONValue {
        try JSONValue(parsing: """
        {
          "@context": ["https://www.w3.org/ns/credentials/v2",
            {"ex":"https://example.org/vocab#",
             "fullName":"ex:fullName","email":"ex:email","age":"ex:age",
             "skills":"ex:skills","alumniOf":"ex:alumniOf","address":"ex:address",
             "city":"ex:city","postalCode":"ex:postalCode","country":"ex:country"}],
          "id": "urn:uuid:rich-0001",
          "type": ["VerifiableCredential", "ExampleCredential"],
          "issuer": "did:example:issuer",
          "validFrom": "2026-01-01T00:00:00Z",
          "validUntil": "2030-01-01T00:00:00Z",
          "name": "Example Credential",
          "description": "A credential exercising several optional fields.",
          "credentialSubject": {
            "id": "did:example:subject",
            "fullName": "Alice Smith",
            "email": "alice@example.org",
            "age": 30,
            "skills": ["Swift", "Cryptography", "RDF"],
            "alumniOf": "Example University",
            "address": {"city": "Bengaluru", "postalCode": "560001", "country": "IN"}
          }
        }
        """)
    }

    func testMinimalCredentialVerifies() async throws {
        let key = P256.Signing.PrivateKey()
        let signed = try await TestSigner.signEcdsaRdfc2019(
            credential: try minimalCredential(), privateKey: key, loader: loader)
        let result = try await client.verifyCredential(try signed.serialized())
        XCTAssertTrue(result.verified, result.reason ?? "no reason")
    }

    func testRichCredentialVerifiesAndTamperFails() async throws {
        let key = P256.Signing.PrivateKey()
        let signed = try await TestSigner.signEcdsaRdfc2019(
            credential: try richCredential(), privateKey: key, loader: loader)
        let result = try await client.verifyCredential(try signed.serialized())
        XCTAssertTrue(result.verified, result.reason ?? "no reason")

        // Tamper an optional field (the integer age) → must fail.
        var obj = signed.objectValue!
        var subject = obj["credentialSubject"]!.objectValue!
        subject["age"] = .int(31)
        obj["credentialSubject"] = .object(subject)
        let tampered = try await client.verifyCredential(try JSONValue.object(obj).serialized())
        XCTAssertFalse(tampered.verified)
    }

    func testRichCredentialEddsaVerifies() async throws {
        let key = Curve25519.Signing.PrivateKey()
        let signed = try await TestSigner.signEddsaRdfc2022(
            credential: try richCredential(), privateKey: key, loader: loader)
        let result = try await client.verifyCredential(try signed.serialized())
        XCTAssertTrue(result.verified, result.reason ?? "no reason")
    }

    func testSdDiscloseScalarAndArrayOptionalFields() async throws {
        let issuerKey = P256.Signing.PrivateKey()
        let ephemeralKey = P256.Signing.PrivateKey()
        let base = try await TestSdIssuer.issueBaseProof(
            credential: try richCredential(), issuerKey: issuerKey, ephemeralKey: ephemeralKey,
            mandatoryPointers: ["/issuer", "/validFrom"], loader: loader)

        // Disclose only the email (scalar) and skills (array).
        let derivedJSON = try await client.deriveCredential(
            baseCredential: try base.serialized(),
            selectivePointers: ["/credentialSubject/email", "/credentialSubject/skills"])
        let result = try await client.verifyCredential(derivedJSON)
        XCTAssertTrue(result.verified, result.reason ?? "no reason")

        let subject = try XCTUnwrap(try JSONValue(parsing: derivedJSON)["credentialSubject"]?.objectValue)
        XCTAssertEqual(subject["email"]?.stringValue, "alice@example.org")
        XCTAssertEqual(subject["skills"]?.arrayValue?.count, 3)
        XCTAssertNil(subject["age"], "undisclosed optional field must be absent")
        XCTAssertNil(subject["fullName"])
        XCTAssertNil(subject["address"])
    }

    func testSdDiscloseNestedObjectOptionalField() async throws {
        let issuerKey = P256.Signing.PrivateKey()
        let ephemeralKey = P256.Signing.PrivateKey()
        let base = try await TestSdIssuer.issueBaseProof(
            credential: try richCredential(), issuerKey: issuerKey, ephemeralKey: ephemeralKey,
            mandatoryPointers: ["/issuer"], loader: loader)

        // Disclose the nested address object (a blank node).
        let derivedJSON = try await client.deriveCredential(
            baseCredential: try base.serialized(),
            selectivePointers: ["/credentialSubject/address"])
        let result = try await client.verifyCredential(derivedJSON)
        XCTAssertTrue(result.verified, result.reason ?? "no reason")

        let address = try JSONValue(parsing: derivedJSON)["credentialSubject"]?["address"]?.objectValue
        XCTAssertEqual(address?["city"]?.stringValue, "Bengaluru")
        XCTAssertEqual(address?["country"]?.stringValue, "IN")
        XCTAssertNil(try JSONValue(parsing: derivedJSON)["credentialSubject"]?["email"])
    }
}
