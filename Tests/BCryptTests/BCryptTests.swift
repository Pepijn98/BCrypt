import XCTest
import Core
import BCrypt

final class BCryptTests: XCTestCase {
    func testBCrypt() throws {
        let bcrypt = try BCrypt()
        let message = "Hello".makeBytes()
        let digest = bcrypt.digest(salt: bcrypt.salt, message: message)
        let serializer = Serializer(bcrypt.salt, digest: digest)
        let bytes = serializer.serialize()
        print(String(bytes: bytes, encoding: .utf8) ?? "none")
        XCTAssertNotNil(digest)
    }

    static var allTests = [
        ("testBCrypt", testBCrypt),
    ]
}