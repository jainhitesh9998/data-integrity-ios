import XCTest
import Crypto
@testable import DataIntegrity

/// Conformance against **Project Wycheproof** signature-verification vectors.
///
/// The public key of each group is decoded through *this library's* decoders —
/// the JWK path drives the full result matrix, and the compressed-point /
/// Multikey path (which exercises the in-house iOS-14 SEC1 point decompression,
/// `ECPointDecompression.swift`) is cross-checked once per group against a valid
/// signature. Signatures are verified with `VerificationKey.isValidSignature`.
///
/// Rules:
///  - `valid` must verify.
///  - `invalid` must be rejected, **except** vectors flagged `SignatureMalleability`
///    (non-canonical S): this library normalizes low-S and intentionally does not
///    enforce strict-S, so those are tolerated and counted.
///  - A group whose public key does not decode (Wycheproof point-at-infinity /
///    off-curve / x=0 keys) is expected **iff** it contains no `valid` test —
///    i.e. rejecting an invalid key is correct behaviour.
///
/// Vectors: <https://github.com/C2SP/wycheproof> (`testvectors_v1`), bundled
/// under `Vectors/wycheproof/`. See `Vectors/ATTRIBUTION.md`.
final class ConformanceWycheproofTests: XCTestCase {

    func testEcdsaP256() throws {
        try runEcdsa("ecdsa_secp256r1_sha256_p1363_test", fieldSize: 32, multikeyPrefix: Multikey.p256Prefix)
    }

    func testEcdsaP384() throws {
        try runEcdsa("ecdsa_secp384r1_sha384_p1363_test", fieldSize: 48, multikeyPrefix: Multikey.p384Prefix)
    }

    func testEd25519() throws {
        let groups = try loadGroups("ed25519_test")
        var valid = 0, invalid = 0, tolerated = 0, keyRejected = 0
        var failures: [String] = []
        for group in groups {
            let tests = group["tests"] as? [[String: Any]] ?? []
            let groupHasValid = tests.contains { ($0["result"] as? String) == "valid" }
            guard let pk = group["publicKey"] as? [String: Any],
                  let pkHex = pk["pk"] as? String, let raw = hex(pkHex),
                  // Decode through our Multikey path (ed25519 prefix + raw key).
                  let key = try? Multikey.decode(Data(Multikey.ed25519Prefix) + raw) else {
                if groupHasValid { failures.append("ed25519: valid-bearing group's key failed to decode") }
                else { keyRejected += 1 }
                continue
            }
            for t in tests {
                guard let result = t["result"] as? String,
                      let msg = hex(t["msg"] as? String ?? ""),
                      let sig = hex(t["sig"] as? String ?? "") else { continue }
                let flags = t["flags"] as? [String] ?? []
                let tcId = t["tcId"] as? Int ?? -1
                let verified = key.isValidSignature(sig, for: msg)
                switch result {
                case "valid":
                    valid += 1
                    if !verified { failures.append("ed25519 tc\(tcId): valid signature rejected") }
                case "invalid":
                    if flags.contains("SignatureMalleability") { tolerated += 1 }
                    else {
                        invalid += 1
                        if verified { failures.append("ed25519 tc\(tcId): invalid signature accepted (flags=\(flags))") }
                    }
                default: break
                }
            }
        }
        print("[Wycheproof ed25519] valid=\(valid) invalid=\(invalid) tolerated(malleability)=\(tolerated) keyRejected=\(keyRejected)")
        XCTAssertTrue(failures.isEmpty, "ed25519: \(failures.count) failures:\n" + failures.prefix(15).joined(separator: "\n"))
        XCTAssertGreaterThan(valid, 0)
    }

    // MARK: - ECDSA runner

    private func runEcdsa(_ file: String, fieldSize: Int, multikeyPrefix: [UInt8]) throws {
        let groups = try loadGroups(file)
        var valid = 0, invalid = 0, tolerated = 0, keyRejected = 0, decompressChecked = 0
        var failures: [String] = []

        for group in groups {
            let tests = group["tests"] as? [[String: Any]] ?? []
            let groupHasValid = tests.contains { ($0["result"] as? String) == "valid" }
            let pk = group["publicKey"] as? [String: Any]

            // Decode via our JWK decoder, when the group provides a JWK.
            var jwkKey: VerificationKey?
            if let jwkAny = group["publicKeyJwk"] as? [String: Any] {
                jwkKey = try? JWKKey.decode(jsonValueDict(jwkAny))
            }
            // Decode via our compressed-point / Multikey path — compress the
            // uncompressed point, decode through Multikey (exercising the
            // in-house SEC1 point decompression). The uncompressed point is
            // present for every group, so this also covers groups with no JWK.
            var compressedKey: VerificationKey?
            if let uncompressedHex = pk?["uncompressed"] as? String,
               let uncompressed = hex(uncompressedHex),
               let compressed = ECPoint.compress(x963: uncompressed, fieldSize: fieldSize) {
                compressedKey = try? Multikey.decode(Data(multikeyPrefix) + compressed)
            }

            // Primary verification key: prefer JWK, else the decompressed key.
            guard let key = jwkKey ?? compressedKey else {
                // Undecodable key is correct only for invalid-key groups
                // (point at infinity, x-coordinate 0, off-curve, …).
                if groupHasValid { failures.append("\(file): valid-bearing group's key failed to decode") }
                else { keyRejected += 1 }
                continue
            }
            var crossCheckedThisGroup = false

            for t in tests {
                guard let result = t["result"] as? String,
                      let msg = hex(t["msg"] as? String ?? ""),
                      let sig = hex(t["sig"] as? String ?? "") else { continue }
                let flags = t["flags"] as? [String] ?? []
                let tcId = t["tcId"] as? Int ?? -1
                let verified = key.isValidSignature(sig, for: msg)
                switch result {
                case "valid":
                    valid += 1
                    if !verified { failures.append("\(file) tc\(tcId): valid signature rejected") }
                    if !crossCheckedThisGroup, let ck = compressedKey {
                        crossCheckedThisGroup = true
                        decompressChecked += 1
                        if !ck.isValidSignature(sig, for: msg) {
                            failures.append("\(file) tc\(tcId): compressed-point (decompressed) key failed a valid signature")
                        }
                    }
                case "invalid":
                    if flags.contains("SignatureMalleability") { tolerated += 1 }
                    else {
                        invalid += 1
                        if verified { failures.append("\(file) tc\(tcId): invalid signature accepted (flags=\(flags))") }
                    }
                default: break
                }
            }
        }
        print("[Wycheproof \(file)] valid=\(valid) invalid=\(invalid) tolerated(malleability)=\(tolerated) keyRejected=\(keyRejected) decompressChecked=\(decompressChecked)")
        XCTAssertTrue(failures.isEmpty, "\(file): \(failures.count) failures:\n" + failures.prefix(15).joined(separator: "\n"))
        XCTAssertGreaterThan(valid, 0)
        XCTAssertGreaterThan(decompressChecked, 0, "decompression cross-check never ran")
    }

    // MARK: - helpers

    private func loadGroups(_ file: String) throws -> [[String: Any]] {
        guard let url = Bundle.module.url(forResource: file, withExtension: "json", subdirectory: "Vectors/wycheproof") else {
            throw XCTSkip("\(file).json not bundled")
        }
        let obj = try JSONSerialization.jsonObject(with: try Data(contentsOf: url)) as? [String: Any]
        return obj?["testGroups"] as? [[String: Any]] ?? []
    }

    private func hex(_ s: String) -> Data? {
        if s.isEmpty { return Data() }
        guard s.count % 2 == 0 else { return nil }
        var data = Data(capacity: s.count / 2)
        var idx = s.startIndex
        while idx < s.endIndex {
            let next = s.index(idx, offsetBy: 2)
            guard let b = UInt8(s[idx..<next], radix: 16) else { return nil }
            data.append(b)
            idx = next
        }
        return data
    }

    /// Convert a Wycheproof JWK (`[String: Any]`) into the `[String: JSONValue]`
    /// that `JWKKey.decode` consumes (the relevant JWK fields are strings).
    private func jsonValueDict(_ jwk: [String: Any]) -> [String: JSONValue] {
        var out: [String: JSONValue] = [:]
        for (k, v) in jwk { if let s = v as? String { out[k] = .string(s) } }
        return out
    }
}
