import XCTest
import Crypto
@testable import DataIntegrity

/// Generates sample valid VCs into the package's `Samples/` directory and
/// re-verifies them. Uses deterministic keys so the output is reproducible.
/// Run with: `swift test --filter SampleGeneratorTests`.
final class SampleGeneratorTests: XCTestCase {
    let loader = ContextDocumentLoader(networkPolicy: .deny)

    private var samplesDir: URL {
        // .../Tests/DataIntegrityTests/SampleGeneratorTests.swift → package root
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Samples")
    }

    private func baseCredential() throws -> JSONValue {
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
          "id": "urn:uuid:0c1f9b2e-7a4d-4c2b-9b1a-2f3e4d5c6a7b",
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

    func testGenerateSamples() async throws {
        try FileManager.default.createDirectory(at: samplesDir, withIntermediateDirectories: true)
        let client = DataIntegrityClient(documentLoader: loader)

        // Deterministic keys for reproducible samples.
        let p256 = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x11, count: 32))
        let ed = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x22, count: 32))

        // 1. ecdsa-rdfc-2019
        let rdfc = try await TestSigner.signEcdsaRdfc2019(
            credential: try baseCredential(), privateKey: p256, loader: loader)
        try write(rdfc, "sample-ecdsa-rdfc-2019.json")
        let r1 = try await client.verifyCredential(try rdfc.serialized())
        XCTAssertTrue(r1.verified)

        // 2. eddsa-rdfc-2022
        let eddsa = try await TestSigner.signEddsaRdfc2022(
            credential: try baseCredential(), privateKey: ed, loader: loader)
        try write(eddsa, "sample-eddsa-rdfc-2022.json")
        let r2 = try await client.verifyCredential(try eddsa.serialized())
        XCTAssertTrue(r2.verified)

        // 3. ecdsa-sd-2023: issue a base proof, then derive a real selective
        //    disclosure (reveal issuer/validFrom [mandatory] + only the address).
        let ephemeral = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x33, count: 32))
        let base = try await TestSdIssuer.issueBaseProof(
            credential: try baseCredential(), issuerKey: p256, ephemeralKey: ephemeral,
            mandatoryPointers: ["/issuer", "/validFrom"], loader: loader)
        try write(base, "sample-ecdsa-sd-2023-base.json")

        let derivedJSON = try await client.deriveCredential(
            baseCredential: try base.serialized(),
            selectivePointers: ["/credentialSubject/address"])
        let sd = try JSONValue(parsing: derivedJSON)
        try write(sd, "sample-ecdsa-sd-2023-derived.json")
        let r3 = try await client.verifyCredential(derivedJSON)
        XCTAssertTrue(r3.verified)

        print("Samples written to \(samplesDir.path)")
    }

    private func write(_ json: JSONValue, _ name: String) throws {
        let data = try JSONSerialization.data(
            withJSONObject: json.foundationObject,
            options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        try data.write(to: samplesDir.appendingPathComponent(name))
    }
}
