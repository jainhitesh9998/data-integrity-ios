import XCTest
import Crypto
@testable import DataIntegrity

/// Negative tests: verification must FAIL (or derivation must throw) for
/// tampering, corruption, wrong keys, and structural attacks — across
/// ecdsa-rdfc-2019, eddsa-rdfc-2022, and ecdsa-sd-2023 at various disclosure
/// levels (mandatory, selective scalar/array/nested, add/remove statements).
final class NegativeTests: XCTestCase {
    let loader = ContextDocumentLoader(networkPolicy: .deny)
    var client: DataIntegrityClient { DataIntegrityClient(documentLoader: loader) }

    private func credential() throws -> JSONValue {
        try JSONValue(parsing: """
        {
          "@context": ["https://www.w3.org/ns/credentials/v2",
            {"ex":"https://example.org/vocab#","fullName":"ex:fullName","email":"ex:email",
             "skills":"ex:skills","address":"ex:address","city":"ex:city","postalCode":"ex:postalCode"}],
          "id": "urn:uuid:neg-0001",
          "type": ["VerifiableCredential"],
          "issuer": "did:example:issuer",
          "validFrom": "2026-01-01T00:00:00Z",
          "credentialSubject": {
            "id": "did:example:subject", "fullName": "Alice Smith", "email": "alice@example.org",
            "skills": ["Swift", "RDF"], "address": {"city": "Bengaluru", "postalCode": "560001"}
          }
        }
        """)
    }

    private func setSubjectField(_ vc: JSONValue, _ key: String, _ value: JSONValue?) -> JSONValue {
        var obj = vc.objectValue!
        var subject = obj["credentialSubject"]!.objectValue!
        subject[key] = value
        obj["credentialSubject"] = .object(subject)
        return .object(obj)
    }

    // MARK: - RDFC / EdDSA negatives

    func testRdfc2019WrongIssuerKeyFails() async throws {
        let signing = P256.Signing.PrivateKey()
        var signed = try await TestSigner.signEcdsaRdfc2019(
            credential: try credential(), privateKey: signing, loader: loader)
        // Point the proof at a DIFFERENT key's did:key.
        var proof = signed["proof"]!.objectValue!
        proof["verificationMethod"] = .string(TestSigner.didKeyP256(P256.Signing.PrivateKey().publicKey))
        signed["proof"] = .object(proof)
        let result = try await client.verifyCredential(try signed.serialized())
        XCTAssertFalse(result.verified)
    }

    func testRdfc2019CorruptedProofValueFails() async throws {
        let key = P256.Signing.PrivateKey()
        var signed = try await TestSigner.signEcdsaRdfc2019(
            credential: try credential(), privateKey: key, loader: loader)
        var proof = signed["proof"]!.objectValue!
        proof["proofValue"] = .string("z3yNQ111CorruptedSignatureValue111")
        signed["proof"] = .object(proof)
        let result = try await client.verifyCredential(try signed.serialized())
        XCTAssertFalse(result.verified)
    }

    func testEddsaWrongKeyFails() async throws {
        let signing = Curve25519.Signing.PrivateKey()
        var signed = try await TestSigner.signEddsaRdfc2022(
            credential: try credential(), privateKey: signing, loader: loader)
        var proof = signed["proof"]!.objectValue!
        proof["verificationMethod"] = .string(TestSigner.didKeyEd25519(Curve25519.Signing.PrivateKey().publicKey))
        signed["proof"] = .object(proof)
        let result = try await client.verifyCredential(try signed.serialized())
        XCTAssertFalse(result.verified)
    }

    // MARK: - ecdsa-sd-2023 negatives across disclosure levels

    private func derived(
        mandatory: [String], selective: [String]
    ) async throws -> (issuer: P256.Signing.PrivateKey, json: String) {
        let issuerKey = P256.Signing.PrivateKey()
        let ephemeralKey = P256.Signing.PrivateKey()
        let base = try await TestSdIssuer.issueBaseProof(
            credential: try credential(), issuerKey: issuerKey, ephemeralKey: ephemeralKey,
            mandatoryPointers: mandatory, loader: loader)
        let json = try await client.deriveCredential(
            baseCredential: try base.serialized(), selectivePointers: selective)
        return (issuerKey, json)
    }

    func testSdTamperDisclosedMandatoryFieldFails() async throws {
        // fullName is mandatory; tampering it breaks the mandatory hash → base signature.
        let (_, json) = try await derived(
            mandatory: ["/issuer", "/credentialSubject/fullName"],
            selective: ["/credentialSubject/email"])
        let tampered = setSubjectField(try JSONValue(parsing: json), "fullName", .string("Mallory"))
        let result = try await client.verifyCredential(try tampered.serialized())
        XCTAssertFalse(result.verified)
    }

    func testSdTamperDisclosedSelectiveFieldFails() async throws {
        let (_, json) = try await derived(
            mandatory: ["/issuer"], selective: ["/credentialSubject/email"])
        let tampered = setSubjectField(try JSONValue(parsing: json), "email", .string("evil@example.org"))
        let result = try await client.verifyCredential(try tampered.serialized())
        XCTAssertFalse(result.verified)
    }

    func testSdFlippedProofValueFails() async throws {
        let (_, json) = try await derived(
            mandatory: ["/issuer"], selective: ["/credentialSubject/email"])
        var vc = try JSONValue(parsing: json)
        var proof = vc["proof"]!.objectValue!
        let pv = proof["proofValue"]!.stringValue!
        // Corrupt a character in the middle of the multibase payload.
        var chars = Array(pv); chars[pv.count / 2] = (chars[pv.count / 2] == "A") ? "B" : "A"
        proof["proofValue"] = .string(String(chars))
        vc["proof"] = .object(proof)
        let result = try await client.verifyCredential(try vc.serialized())
        XCTAssertFalse(result.verified)
    }

    func testSdInjectUndisclosedStatementFails() async throws {
        // Disclose only email, then sneak in a never-disclosed field → an extra
        // non-mandatory statement with no matching signature.
        let (_, json) = try await derived(
            mandatory: ["/issuer"], selective: ["/credentialSubject/email"])
        let tampered = setSubjectField(try JSONValue(parsing: json), "fullName", .string("Injected"))
        let result = try await client.verifyCredential(try tampered.serialized())
        XCTAssertFalse(result.verified)
    }

    func testSdRemoveDisclosedStatementFails() async throws {
        // Disclose email + skills, then remove skills → statement/signature mismatch.
        let (_, json) = try await derived(
            mandatory: ["/issuer"], selective: ["/credentialSubject/email", "/credentialSubject/skills"])
        let tampered = setSubjectField(try JSONValue(parsing: json), "skills", nil)
        let result = try await client.verifyCredential(try tampered.serialized())
        XCTAssertFalse(result.verified)
    }

    func testSdTamperNestedDisclosedFieldFails() async throws {
        let (_, json) = try await derived(
            mandatory: ["/issuer"], selective: ["/credentialSubject/address"])
        var vc = try JSONValue(parsing: json)
        var obj = vc.objectValue!
        var subject = obj["credentialSubject"]!.objectValue!
        var address = subject["address"]!.objectValue!
        address["city"] = .string("Mumbai")
        subject["address"] = .object(address)
        obj["credentialSubject"] = .object(subject)
        let result = try await client.verifyCredential(try JSONValue.object(obj).serialized())
        XCTAssertFalse(result.verified)
    }

    // MARK: - derive error cases

    func testDeriveNothingSelectedThrows() async throws {
        let issuerKey = P256.Signing.PrivateKey()
        let ephemeralKey = P256.Signing.PrivateKey()
        let base = try await TestSdIssuer.issueBaseProof(
            credential: try credential(), issuerKey: issuerKey, ephemeralKey: ephemeralKey,
            mandatoryPointers: [], loader: loader)
        do {
            _ = try await client.deriveCredential(baseCredential: try base.serialized(), selectivePointers: [])
            XCTFail("expected nothing-selected error")
        } catch let error as DataIntegrityError {
            XCTAssertEqual(error.code, .nothingSelected)
        }
    }

    func testDeriveInvalidPointerThrows() async throws {
        let issuerKey = P256.Signing.PrivateKey()
        let ephemeralKey = P256.Signing.PrivateKey()
        let base = try await TestSdIssuer.issueBaseProof(
            credential: try credential(), issuerKey: issuerKey, ephemeralKey: ephemeralKey,
            mandatoryPointers: ["/issuer"], loader: loader)
        do {
            _ = try await client.deriveCredential(
                baseCredential: try base.serialized(), selectivePointers: ["/credentialSubject/doesNotExist"])
            XCTFail("expected invalid-pointer error")
        } catch let error as DataIntegrityError {
            XCTAssertEqual(error.code, .invalidPointer)
        }
    }

    // MARK: - Malicious holder: tamper the BASE credential, then derive

    func testSdTamperBaseMandatoryThenDeriveFails() async throws {
        let issuerKey = P256.Signing.PrivateKey()
        let ephemeralKey = P256.Signing.PrivateKey()
        // Issuer signs the ORIGINAL credential (fullName is mandatory).
        let base = try await TestSdIssuer.issueBaseProof(
            credential: try credential(), issuerKey: issuerKey, ephemeralKey: ephemeralKey,
            mandatoryPointers: ["/issuer", "/credentialSubject/fullName"], loader: loader)
        // Holder edits the mandatory fullName in their own base credential, then derives.
        let tamperedBase = setSubjectField(base, "fullName", .string("Mallory"))
        let derivedJSON = try await client.deriveCredential(
            baseCredential: try tamperedBase.serialized(), selectivePointers: ["/credentialSubject/email"])
        let result = try await client.verifyCredential(derivedJSON)
        XCTAssertFalse(result.verified, "tampered mandatory data must be caught by the base signature")
    }

    func testSdTamperBaseSelectiveThenDiscloseFails() async throws {
        let issuerKey = P256.Signing.PrivateKey()
        let ephemeralKey = P256.Signing.PrivateKey()
        let base = try await TestSdIssuer.issueBaseProof(
            credential: try credential(), issuerKey: issuerKey, ephemeralKey: ephemeralKey,
            mandatoryPointers: ["/issuer"], loader: loader)
        // Holder edits a selectively-disclosable field, then discloses it.
        let tamperedBase = setSubjectField(base, "email", .string("evil@example.org"))
        let derivedJSON = try await client.deriveCredential(
            baseCredential: try tamperedBase.serialized(), selectivePointers: ["/credentialSubject/email"])
        let result = try await client.verifyCredential(derivedJSON)
        XCTAssertFalse(result.verified, "tampered disclosed data must be caught by its per-statement signature")
    }
}
