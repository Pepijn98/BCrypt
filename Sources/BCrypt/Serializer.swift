import Core
// import Foundation

public final class Serializer {
    let salt: Salt
    let digest: Bytes?

    public init(_ salt: Salt, digest: Bytes? = nil) {
        self.salt = salt
        self.digest = digest
    }

    public func serializeSalt() -> Bytes {
        let prefix: Bytes = [.dollar, .two, .b, .dollar]

        var bytes = Bytes()
        bytes.reserveCapacity(24)
        bytes.append(contentsOf: prefix)

        if salt.cost < 10 {
            bytes.append(.zero)
        }
        bytes.append(contentsOf: salt.cost.description.makeBytes())
        bytes.append(.dollar)

        let encodedSalt = Base64.encode(salt.bytes, count: 16)
        // print(String(bytes: encodedSalt, encoding: .utf8) ?? "none")
        bytes.append(contentsOf: encodedSalt)

        return bytes
    }

    public func serialize() -> Bytes {
        var bytes = serializeSalt()

        if let digest = digest {
            let encodedDigest = Base64.encode(digest, count: 23)
            bytes.append(contentsOf: encodedDigest)
        }

        return bytes
    }
}