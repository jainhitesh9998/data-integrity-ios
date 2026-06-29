import XCTest
import Crypto
@testable import DataIntegrity

/// Validates the custom SEC1 point compression/decompression (needed for
/// iOS 14/15, where CryptoKit's compressed-point APIs are unavailable) against
/// CryptoKit's own representations, which ARE available on macOS 13+.
final class ECPointTests: XCTestCase {
    func testP256DecompressMatchesCryptoKit() throws {
        for _ in 0..<10 {
            let key = P256.Signing.PrivateKey().publicKey
            let compressed = key.compressedRepresentation
            let decompressed = try XCTUnwrap(ECPoint.decompress(compressed, curve: ECPoint.p256))
            XCTAssertEqual(decompressed, key.x963Representation)
        }
    }

    func testP384DecompressMatchesCryptoKit() throws {
        for _ in 0..<10 {
            let key = P384.Signing.PrivateKey().publicKey
            let compressed = key.compressedRepresentation
            let decompressed = try XCTUnwrap(ECPoint.decompress(compressed, curve: ECPoint.p384))
            XCTAssertEqual(decompressed, key.x963Representation)
        }
    }

    func testP256CompressMatchesCryptoKit() throws {
        for _ in 0..<10 {
            let key = P256.Signing.PrivateKey().publicKey
            let compressed = try XCTUnwrap(ECPoint.compress(x963: key.x963Representation, fieldSize: 32))
            XCTAssertEqual(compressed, key.compressedRepresentation)
        }
    }

    func testDecompressRejectsOffCurvePoints() {
        // ~half of all x values are off-curve (rhs is a non-residue); the
        // y² == rhs guard must reject them. Over a small range we expect many.
        var rejected = 0
        for x in 1...16 {
            var xBytes = [UInt8](repeating: 0, count: 32)
            xBytes[31] = UInt8(x)
            if ECPoint.decompress(Data([0x02] + xBytes), curve: ECPoint.p256) == nil {
                rejected += 1
            }
        }
        XCTAssertGreaterThan(rejected, 0, "decompress must reject off-curve x values")
    }
}
