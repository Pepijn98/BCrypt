import XCTest
import Random
import BCrypt

final class BCryptTests: XCTestCase {
    func test() throws {
        let bcrypt = try BCrypt()
        let digest = bcrypt.digest(salt: bcrypt.salt, message: Bytes(repeating: 0, count: 1))
        print(digest)
        XCTAssertNotNil(digest)
    }

    static var allTests = [
        ("test", test),
    ]
}