import XCTest
@testable import DataIntegrity

/// Externally-issued `ecdsa-sd-2023` BASE credentials with a **custom inline
/// `@context`** (driver licence). Exercises the holder-side API end-to-end:
///   - `describeDisclosure` — what the issuer forced (mandatory) vs. what the
///     holder may choose (optional);
///   - `verifyBaseCredential` — verify-on-open (reveal *all* optional, then verify);
///   - `deriveCredential` — share a holder-chosen subset (presentation);
/// plus mandatory- and optional-field tamper negatives.
///
/// Fully offline: VCDM v2 is bundled, the domain terms are inline, the key is `did:key`.
final class DriverLicenseSdTests: XCTestCase {
    private func client() -> DataIntegrityClient {
        DataIntegrityClient(documentLoader: ContextDocumentLoader(networkPolicy: .deny))
    }
    private func base(_ name: String) throws -> String {
        guard let url = Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Vectors/driver-license") else {
            throw XCTSkip("\(name).json not bundled")
        }
        return try String(contentsOf: url, encoding: .utf8)
    }

    // MARK: describeDisclosure — the consent surface (mandatory shown as locked, optional as toggles)

    func testDescribeDisclosure_dl2() async throws {
        let d = try await client().describeDisclosure(baseCredential: try base("dl-valid-2"))
        XCTAssertEqual(d.mandatoryPointers, [
            "/credentialSubject/fullName", "/credentialSubject/licenseClass", "/issuer", "/validFrom",
        ])
        XCTAssertEqual(d.optionalPointers, [
            "/credentialSubject/address/city", "/credentialSubject/address/postalCode",
            "/credentialSubject/address/street", "/credentialSubject/dateOfBirth",
            "/credentialSubject/issuingState", "/credentialSubject/licenseNumber",
            "/credentialSubject/type", "/type", "/validUntil",
        ])
        XCTAssertTrue(Set(d.mandatoryPointers).isDisjoint(with: Set(d.optionalPointers)), "mandatory/optional must not overlap")
    }

    /// Different issuer, different mandatory choice — dl-1 fixed most of the subject.
    func testDescribeDisclosure_dl1_hasLargerMandatorySet() async throws {
        let d = try await client().describeDisclosure(baseCredential: try base("dl-valid-1"))
        XCTAssertEqual(d.mandatoryPointers.count, 7)
        XCTAssertTrue(d.mandatoryPointers.contains("/credentialSubject/address"))
        XCTAssertEqual(d.optionalPointers, [
            "/credentialSubject/licenseClass", "/credentialSubject/type", "/type", "/validUntil",
        ])
    }

    // MARK: verifyBaseCredential — verify on open (reveal all optional, then verify)

    func testVerifyBaseCredential_dl1_verifies() async throws {
        let r = try await client().verifyBaseCredential(try base("dl-valid-1"))
        XCTAssertTrue(r.verified, r.reason ?? "-")
        XCTAssertEqual(r.cryptosuite, "ecdsa-sd-2023")
    }
    func testVerifyBaseCredential_dl2_verifies() async throws {
        let r = try await client().verifyBaseCredential(try base("dl-valid-2"))
        XCTAssertTrue(r.verified, r.reason ?? "-")
    }
    /// dl-3 = dl-2 with mandatory `fullName` changed → the **base signature** rejects it.
    func testVerifyBaseCredential_tamperedMandatory_fails() async throws {
        let r = try await client().verifyBaseCredential(try base("dl-tampered-fullname"))
        XCTAssertFalse(r.verified, "tampered mandatory field must not verify")
    }
    /// optional `licenseNumber` changed → once revealed, its **per-statement signature** rejects it.
    func testVerifyBaseCredential_tamperedOptional_fails() async throws {
        let r = try await client().verifyBaseCredential(try base("dl-tampered-optional"))
        XCTAssertFalse(r.verified, "tampered (disclosed) optional field must not verify")
    }

    // MARK: share derivation — holder reveals a chosen subset (presentation)

    func testShareDerivation_revealsChosenSubsetOnly() async throws {
        let c = client()
        // Holder shares only the licence number (+ issuer-mandated fields); withholds DOB, state, address.
        let derivedJSON = try await c.deriveCredential(
            baseCredential: try base("dl-valid-2"), selectivePointers: ["/credentialSubject/licenseNumber"])

        let r = try await c.verifyCredential(derivedJSON)
        XCTAssertTrue(r.verified, r.reason ?? "-")

        let subject = try XCTUnwrap(JSONValue(parsing: derivedJSON)["credentialSubject"]?.objectValue)
        XCTAssertNotNil(subject["licenseNumber"], "disclosed field present")
        XCTAssertNotNil(subject["fullName"], "mandatory field auto-included")
        XCTAssertNil(subject["dateOfBirth"], "undisclosed optional field withheld")
        XCTAssertNil(subject["issuingState"], "undisclosed optional field withheld")
    }
}
