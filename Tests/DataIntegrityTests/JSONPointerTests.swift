import XCTest
@testable import DataIntegrity

/// RFC 6901 JSON Pointer parsing (used by ecdsa-sd-2023 selective disclosure).
final class JSONPointerTests: XCTestCase {
    func testSimpleKeys() throws {
        XCTAssertEqual(try JSONPointer.parse("/credentialSubject/address"),
                       [.key("credentialSubject"), .key("address")])
    }

    func testNumericIndex() throws {
        XCTAssertEqual(try JSONPointer.parse("/items/0/value"),
                       [.key("items"), .index(0), .key("value")])
        XCTAssertEqual(try JSONPointer.parse("/a/10"), [.key("a"), .index(10)])
    }

    func testEscapeSequences() throws {
        // ~1 -> "/", ~0 -> "~"
        XCTAssertEqual(try JSONPointer.parse("/a~1b"), [.key("a/b")])
        XCTAssertEqual(try JSONPointer.parse("/m~0n"), [.key("m~n")])
        XCTAssertEqual(try JSONPointer.parse("/~01"), [.key("~1")]) // ~0 then literal 1
    }

    func testEmptyPointerSelectsWholeDocument() throws {
        XCTAssertEqual(try JSONPointer.parse(""), [])
    }

    func testInvalidEscapeThrows() {
        XCTAssertThrowsError(try JSONPointer.parse("/a~2b"))
    }
}
