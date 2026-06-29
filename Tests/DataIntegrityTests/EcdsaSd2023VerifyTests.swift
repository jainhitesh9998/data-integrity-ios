import XCTest
import Crypto
@testable import DataIntegrity

/// Verifies the ecdsa-sd-2023 derived-proof verification path end to end,
/// using a self-generated valid derived proof (full disclosure). Covers
/// CBOR proof-value parsing, c14n→HMAC relabeling, UTF-16 sort, mandatory
/// split, the base signature (issuer key), and the per-statement signatures
/// (ephemeral key). Runs offline against bundled contexts.
final class EcdsaSd2023VerifyTests: XCTestCase {
    let loader = ContextDocumentLoader(networkPolicy: .deny)

    /// A credential with nested objects (→ blank nodes), so the relabeling
    /// path is genuinely exercised.
    private func sampleCredential() throws -> JSONValue {
        try JSONValue(parsing: """
        {
          "@context": [
            "https://www.w3.org/ns/credentials/v2",
            {
              "ex": "https://example.org/vocab#",
              "fullName": "ex:fullName",
              "address": "ex:address",
              "city": "ex:city",
              "postalCode": "ex:postalCode",
              "program": "ex:program"
            }
          ],
          "id": "urn:uuid:9f7c2b1a-1111-2222-3333-444455556666",
          "type": ["VerifiableCredential"],
          "issuer": "did:example:issuer-99",
          "validFrom": "2026-01-01T00:00:00Z",
          "credentialSubject": {
            "id": "did:example:subject-12",
            "fullName": "Alice Smith",
            "program": "BSc Computer Science",
            "address": { "city": "Bengaluru", "postalCode": "560001" }
          }
        }
        """)
    }

    func testDerivedProofVerifies() async throws {
        let issuerKey = P256.Signing.PrivateKey()
        let derived = try await TestSdSigner.deriveFullDisclosure(
            credential: try sampleCredential(), issuerKey: issuerKey, loader: loader)

        let client = DataIntegrityClient(documentLoader: loader)
        let result = try await client.verifyCredential(try derived.serialized())
        XCTAssertTrue(result.verified, result.reason ?? "no reason")
        XCTAssertEqual(result.cryptosuite, "ecdsa-sd-2023")
    }

    func testTamperedSubjectFailsVerification() async throws {
        let issuerKey = P256.Signing.PrivateKey()
        let derived = try await TestSdSigner.deriveFullDisclosure(
            credential: try sampleCredential(), issuerKey: issuerKey, loader: loader)

        // Tamper a disclosed value.
        var obj = derived.objectValue!
        var subject = obj["credentialSubject"]!.objectValue!
        subject["fullName"] = .string("Mallory Jones")
        obj["credentialSubject"] = .object(subject)

        let client = DataIntegrityClient(documentLoader: loader)
        let result = try await client.verifyCredential(try JSONValue.object(obj).serialized())
        XCTAssertFalse(result.verified)
    }

    func testWrongIssuerKeyFailsVerification() async throws {
        let issuerKey = P256.Signing.PrivateKey()
        var derived = try await TestSdSigner.deriveFullDisclosure(
            credential: try sampleCredential(), issuerKey: issuerKey, loader: loader)

        // Swap the verificationMethod to a different did:key → base signature
        // must fail against the wrong issuer key.
        let otherKey = P256.Signing.PrivateKey()
        var proof = derived["proof"]!.objectValue!
        proof["verificationMethod"] = .string(TestSigner.didKeyP256(otherKey.publicKey))
        derived["proof"] = .object(proof)

        let client = DataIntegrityClient(documentLoader: loader)
        let result = try await client.verifyCredential(try derived.serialized())
        XCTAssertFalse(result.verified)
    }

    func testMalformedProofValueFails() async throws {
        var credential = try sampleCredential()
        credential["proof"] = .object([
            "type": .string("DataIntegrityProof"),
            "cryptosuite": .string("ecdsa-sd-2023"),
            "verificationMethod": .string("did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP"),
            "proofPurpose": .string("assertionMethod"),
            "proofValue": .string("uNOTVALIDCBOR"),
        ])
        let client = DataIntegrityClient(documentLoader: loader)
        let result = try await client.verifyCredential(try credential.serialized())
        XCTAssertFalse(result.verified)
        XCTAssertNotNil(result.reason)
    }
}
