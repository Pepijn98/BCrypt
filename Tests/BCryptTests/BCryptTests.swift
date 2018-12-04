import XCTest
import Core
import BCrypt

final class BCryptTests: XCTestCase {
    func testValidity() throws {
        let salt = try Salt()

        let bytes = try BCrypt.make(message: "hello", salt: salt)
        let isEqual = try BCrypt.verify(message: "hello", matches: bytes)

        print(String(bytes: bytes, encoding: .utf8) ?? "none")

        XCTAssertEqual(isEqual, true)
    }

    func testBCrypt() throws {
        let bcrypt = try BCrypt()
        let digest = bcrypt.digest(message: "hello".bytes)
        let serializer = Serializer(bcrypt.salt, digest: digest)
        let bytes = serializer.serialize()

        print(String(bytes: bytes, encoding: .utf8) ?? "none")

        XCTAssertNotNil(bytes)
    }

    static var allTests = [
        ("testValidity", testValidity),
        ("testBCrypt", testBCrypt),
    ]
}