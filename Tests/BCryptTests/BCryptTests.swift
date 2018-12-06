import XCTest
import Core
import BCrypt

final class BCryptTests: XCTestCase {
    func testValid() throws {
        let salt = try Salt()
        let bytes = try BCrypt.hash(message: "test", with: salt)
        let result = try BCrypt.compare(message: "test", against: bytes)
        XCTAssertEqual(result, true)
    }

    func testFail() throws {
        let salt = try Salt()
        let bytes = try BCrypt.hash(message: "test1", with: salt)
        let result = try BCrypt.compare(message: "test2", against: bytes)
        XCTAssertEqual(result, false)
    }

    func testBCrypt() throws {
        let bcrypt = try BCrypt()
        let digest = bcrypt.digest(message: "test".bytes)
        let serializer = Serializer(bcrypt.salt, digest: digest)
        let bytes = serializer.serialize()
        XCTAssertNotNil(bytes)
    }

    func testSalt() throws {
        let secret = "saltsaltsaltsalt"

        let salt =  try Salt(cost: 14, bytes: secret.bytes)
        let bytes = try BCrypt.hash(message: "test", with: salt)

        let parser = try Parser(bytes)
        let parsedSalt = try parser.parseSalt()

        XCTAssertEqual(secret, String(bytes: parsedSalt.bytes, encoding: .utf8) ?? "")
    }

    func testVerify() throws {
        for (desired, message) in tests {
            let result = try BCrypt.compare(message: message, against: desired)
            XCTAssert(result, "Message '\(message)' did not create \(desired)")
        }
    }

    static var allTests = [
        ("testValid", testValid),
        ("testFail", testFail),
        ("testBCrypt", testBCrypt),
        ("testSalt", testSalt),
        ("testVerify", testVerify),
    ]
}

// Hashes from vapor to test if it properly works
let tests = [
    "$2a$04$TI13sbmh3IHnmRepeEFoJOkVZWsn5S1O8QOwm8ZU5gNIpJog9pXZm": "vapor",
    "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.": "",
    "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe": "a",
    "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i": "abc",
    "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC": "abcdefghijklmnopqrstuvwxyz",
    "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO": "~!@#$%^&*()      ~!@#$%^&*()PNBFRD"
]