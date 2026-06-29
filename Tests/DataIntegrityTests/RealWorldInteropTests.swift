import XCTest
@testable import DataIntegrity

/// Interop against an externally-issued credential (`MedicalTechnician.json`,
/// a First Responder badge signed by the NREMT did:key issuer). It carries
/// three proofs — `ecdsa-rdfc-2019`, `ecdsa-jcs-2019`, and an `ecdsa-sd-2023`
/// BASE proof. We:
///   1. verify the real `ecdsa-rdfc-2019` signature (byte-for-byte interop with
///      a real issuer's RDF canonicalization), and
///   2. derive a selective disclosure from the real `ecdsa-sd-2023` base proof
///      and verify it (interop for the full SD pipeline).
final class RealWorldInteropTests: XCTestCase {
    // Fully offline: every @context this credential needs is bundled.
    let loader = ContextDocumentLoader(networkPolicy: .deny)

    private func loadCredential() throws -> JSONValue {
        guard let url = Bundle.module.url(
            forResource: "MedicalTechnician", withExtension: "json", subdirectory: "Vectors") else {
            throw XCTSkip("MedicalTechnician.json interop vector not bundled — skipping")
        }
        let root = try JSONValue(parsing: try Data(contentsOf: url))
        return try XCTUnwrap(root["credential"], "expected a top-level 'credential'")
    }

    /// Reduce the credential's proof set to the single proof for `cryptosuite`.
    private func isolatingProof(_ vc: JSONValue, cryptosuite: String) throws -> JSONValue {
        var obj = try XCTUnwrap(vc.objectValue)
        let proofs = obj["proof"]?.asArray ?? []
        let match = try XCTUnwrap(
            proofs.first { $0["cryptosuite"]?.stringValue == cryptosuite },
            "no \(cryptosuite) proof present")
        obj["proof"] = match
        return .object(obj)
    }

    func testVerifyRealEcdsaRdfc2019() async throws {
        let vc = try isolatingProof(try loadCredential(), cryptosuite: "ecdsa-rdfc-2019")
        let client = DataIntegrityClient(documentLoader: loader)
        let result = try await client.verifyCredential(try vc.serialized())
        XCTAssertTrue(result.verified, "rdfc-2019 interop failed: \(result.reason ?? "no reason")")
        XCTAssertEqual(result.cryptosuite, "ecdsa-rdfc-2019")
    }

    func testDeriveAndVerifyRealEcdsaSd2023() async throws {
        let base = try isolatingProof(try loadCredential(), cryptosuite: "ecdsa-sd-2023")
        let client = DataIntegrityClient(documentLoader: loader)

        // Selectively disclose the holder's name (plus the issuer's mandatory fields).
        let derivedJSON = try await client.deriveCredential(
            baseCredential: try base.serialized(),
            selectivePointers: ["/credentialSubject/name"])

        let result = try await client.verifyCredential(derivedJSON)
        XCTAssertTrue(result.verified, "sd-2023 derive→verify interop failed: \(result.reason ?? "no reason")")
        XCTAssertEqual(result.cryptosuite, "ecdsa-sd-2023")

        // The disclosed name must survive into the derived credential.
        let derived = try JSONValue(parsing: derivedJSON)
        XCTAssertNotNil(derived["credentialSubject"]?["name"])
    }
}
