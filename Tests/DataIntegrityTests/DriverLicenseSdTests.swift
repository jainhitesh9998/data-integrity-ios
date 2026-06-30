import XCTest
@testable import DataIntegrity

/// Externally-issued `ecdsa-sd-2023` BASE credentials with a **custom inline
/// `@context`** (driver licence). Exercises the verify-on-open flow — derive
/// revealing *all* optional statements, then verify — across two different
/// issuer-chosen mandatory sets, plus a tampered-mandatory negative.
///
/// Fully offline: VCDM v2 is bundled and the domain terms are defined inline, so
/// no `@context` fetch is needed; the issuer key is `did:key`.
final class DriverLicenseSdTests: XCTestCase {
    let loader = ContextDocumentLoader(networkPolicy: .deny)

    func testDl1_distinctMandatorySet_verifies() async throws {
        let r = try await run("dl-valid-1")
        XCTAssertTrue(r.verified, "dl-valid-1 should verify; reason=\(r.note)")
    }

    func testDl2_smallerMandatorySet_verifies() async throws {
        let r = try await run("dl-valid-2")
        XCTAssertTrue(r.verified, "dl-valid-2 should verify; reason=\(r.note)")
    }

    /// dl-3 is dl-2 with the mandatory `fullName` changed (Doe → Roe) but the same
    /// proof — the base signature over the mandatory hash must reject it.
    func testDl3_tamperedMandatoryFullName_fails() async throws {
        let r = try await run("dl-tampered-fullname")
        XCTAssertFalse(r.verified, "a tampered mandatory field must not verify (got verified=true)")
    }

    /// dl-optional is dl-2 with the **optional** `licenseNumber` changed but the
    /// same proof — once it's disclosed (we reveal all optional), its per-statement
    /// signature must reject it.
    func testDl4_tamperedOptionalLicenseNumber_fails() async throws {
        let r = try await run("dl-tampered-optional")
        XCTAssertFalse(r.verified, "a tampered optional field (disclosed) must not verify (got verified=true)")
    }

    // MARK: - helper: derive revealing all optional, then verify

    private func run(_ name: String) async throws -> (mandatory: [String], optional: [String], verified: Bool, note: String) {
        guard let url = Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Vectors/driver-license") else {
            throw XCTSkip("\(name).json not bundled")
        }
        let baseJSON = try String(contentsOf: url, encoding: .utf8)
        let doc = try JSONValue(parsing: baseJSON)
        let client = DataIntegrityClient(documentLoader: loader)

        let mandatory = ((try? SdProofValue.parseBase(doc["proof"]?["proofValue"]?.stringValue ?? ""))?.mandatoryPointers ?? []).sorted()
        var leaves: [String] = []
        // Enumerate claim paths only — skip `@context` (JSON-LD framing, produces
        // no RDF statements, so it's neither mandatory nor optional) and `proof`.
        enumerate(doc.removing("proof").removing("@context"), "", &leaves)
        let optional = leaves.filter { leaf in !mandatory.contains { leaf == $0 || leaf.hasPrefix($0 + "/") } }.sorted()

        var verified = false, note = "-"
        do {
            let derived = try await deriveRevealingAll(baseJSON, optional: optional, client: client)
            let v = try await client.verifyCredential(derived)
            verified = v.verified; note = v.reason ?? "-"
        } catch let e as DataIntegrityError {
            note = "derive threw [\(e.code)] \(e.message)"
        }
        print("""

        ══════ \(name) ══════
        issuer:    \(doc["issuer"]?.stringValue ?? "?")
        MANDATORY (\(mandatory.count)): \(mandatory)
        OPTIONAL  (\(optional.count)): \(optional)
        VERIFY:    \(verified ? "✅ verified" : "❌ NOT verified")   (\(note))
        """)
        return (mandatory, optional, verified, note)
    }

    private func deriveRevealingAll(_ base: String, optional: [String], client: DataIntegrityClient) async throws -> String {
        var ptrs = optional
        while true {
            do { return try await client.deriveCredential(baseCredential: base, selectivePointers: ptrs) }
            catch let e as DataIntegrityError {
                guard let bad = pointer(from: e.message), let i = ptrs.firstIndex(of: bad) else { throw e }
                ptrs.remove(at: i)
                if ptrs.isEmpty { return try await client.deriveCredential(baseCredential: base, selectivePointers: []) }
            }
        }
    }

    private func enumerate(_ v: JSONValue, _ prefix: String, _ out: inout [String]) {
        switch v {
        case .object(let o):
            for k in o.keys.sorted() {
                let p = prefix + "/" + k.replacingOccurrences(of: "~", with: "~0").replacingOccurrences(of: "/", with: "~1")
                if k == "type" || k == "@type" { out.append(p) } else { enumerate(o[k]!, p, &out) }
            }
        case .array(let a):
            if a.isEmpty { out.append(prefix) } else { for (i, e) in a.enumerated() { enumerate(e, prefix + "/\(i)", &out) } }
        default: out.append(prefix)
        }
    }

    private func pointer(from message: String) -> String? {
        guard let a = message.range(of: "\""),
              let b = message.range(of: "\"", range: a.upperBound..<message.endIndex) else { return nil }
        return String(message[a.upperBound..<b.lowerBound])
    }
}
