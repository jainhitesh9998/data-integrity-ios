import XCTest
import Crypto
@testable import DataIntegrity

/// Public-key decoding: `publicKeyJwk` (P-256 / P-384 / Ed25519) and the
/// P-384 Multikey path (compressed-point decompression).
final class KeyDecodingTests: XCTestCase {
    func testJWKP256() throws {
        let priv = P256.Signing.PrivateKey()
        let x963 = Array(priv.publicKey.x963Representation)   // 0x04 ‖ X(32) ‖ Y(32)
        let jwk: [String: JSONValue] = [
            "kty": .string("EC"), "crv": .string("P-256"),
            "x": .string(Base64URL.encode(Data(x963[1..<33]))),
            "y": .string(Base64URL.encode(Data(x963[33..<65]))),
        ]
        let key = try JWKKey.decode(jwk)
        XCTAssertEqual(key.curveName, "P-256")
        let message = Data("payload".utf8)
        let sig = try priv.signature(for: message).rawRepresentation
        XCTAssertTrue(key.isValidSignature(sig, for: message))
    }

    func testJWKP384() throws {
        let priv = P384.Signing.PrivateKey()
        let x963 = Array(priv.publicKey.x963Representation)   // 0x04 ‖ X(48) ‖ Y(48)
        let jwk: [String: JSONValue] = [
            "kty": .string("EC"), "crv": .string("P-384"),
            "x": .string(Base64URL.encode(Data(x963[1..<49]))),
            "y": .string(Base64URL.encode(Data(x963[49..<97]))),
        ]
        let key = try JWKKey.decode(jwk)
        XCTAssertEqual(key.curveName, "P-384")
        let message = Data("payload".utf8)
        let sig = try priv.signature(for: message).rawRepresentation
        XCTAssertTrue(key.isValidSignature(sig, for: message))
    }

    func testJWKEd25519() throws {
        let priv = Curve25519.Signing.PrivateKey()
        let jwk: [String: JSONValue] = [
            "kty": .string("OKP"), "crv": .string("Ed25519"),
            "x": .string(Base64URL.encode(priv.publicKey.rawRepresentation)),
        ]
        let key = try JWKKey.decode(jwk)
        XCTAssertTrue(key.isEd25519)
        let message = Data("payload".utf8)
        let sig = try priv.signature(for: message)
        XCTAssertTrue(key.isValidSignature(Data(sig), for: message))
    }

    func testP384MultikeyDecode() throws {
        let priv = P384.Signing.PrivateKey()
        let compressed = try XCTUnwrap(ECPoint.compress(x963: priv.publicKey.x963Representation, fieldSize: 48))
        let key = try Multikey.decode(Data([0x81, 0x24]) + compressed)
        XCTAssertEqual(key.curveName, "P-384")
        let message = Data("payload".utf8)
        let sig = try priv.signature(for: message).rawRepresentation
        XCTAssertTrue(key.isValidSignature(sig, for: message))
    }

    func testInvalidMultikeyPrefixThrows() {
        XCTAssertThrowsError(try Multikey.decode(Data([0x99, 0x99, 0x01, 0x02, 0x03])))
    }

    func testInvalidJWKThrows() {
        XCTAssertThrowsError(try JWKKey.decode(["kty": .string("EC"), "crv": .string("P-256")]))
    }
}
