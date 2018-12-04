public final class Parser {
    let costBytes: [UInt8]
    let encodedSalt: [UInt8]
    let encodedDigest: [UInt8]?

    public init(_ bytes: [UInt8]) throws {
        let parts = bytes.split(separator: .dollar)

        guard parts.count == 3 && (parts[2].count == 22 || parts[2].count == 53) else {
            throw BCryptError.invalidHash
        }

        costBytes = parts[1].array
        if parts[2].count == 22 {
            encodedSalt = parts[2].array
            encodedDigest = nil
        } else {
            let rest = parts[2].array

            encodedSalt = rest[0..<22].array
            encodedDigest = rest[22..<53].array
        }
    }

    public func parseDigest() throws -> [UInt8]? {
        guard let encodedDigest = self.encodedDigest else {
            return nil
        }

        return Base64.decode(encodedDigest, count: 23)
    }

    public func parseSalt() throws -> Salt {
        let cost = try parseCost()

        let decoded = Base64.decode(encodedSalt, count: 16)
        return try Salt(cost: numericCast(cost), bytes: decoded)
    }

    public func parseCost() throws -> UInt {
        guard let cost = costBytes.decimalInt else {
            throw BCryptError.invalidSaltCost
        }

        return numericCast(cost)
    }
}