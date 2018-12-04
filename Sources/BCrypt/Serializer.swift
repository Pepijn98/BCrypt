public final class Serializer {
    let salt: Salt
    let digest: [UInt8]?

    public init(_ salt: Salt, digest: [UInt8]? = nil) {
        self.salt = salt
        self.digest = digest
    }

    public func serializeSalt() -> [UInt8] {
        let prefix: [UInt8] = [.dollar, .two, .a, .dollar]

        var bytes = [UInt8]()
        bytes.reserveCapacity(24)
        bytes.append(contentsOf: prefix)

        if salt.cost < 10 {
            bytes.append(.zero)
        }
        bytes.append(contentsOf: salt.cost.description.makeBytes())
        bytes.append(.dollar)

        let encodedSalt = Base64.encode(salt.bytes, count: 16)
        bytes.append(contentsOf: encodedSalt)

        return bytes
    }

    public func serialize() -> [UInt8] {
        var bytes = serializeSalt()

        if let digest = digest {
            let encodedDigest = Base64.encode(digest, count: 23)
            bytes.append(contentsOf: encodedDigest)
        }

        return bytes
    }
}