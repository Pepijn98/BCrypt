import Core
import Foundation

fileprivate let plen: Int = 18
fileprivate let slen: Int = 1024

public struct Salt {
    public static var defaultCost: UInt = 14

    public let cost: UInt
    public let bytes: [UInt8]

    public init(cost: UInt = Salt.defaultCost, bytes: [UInt8]? = nil) throws {
        let bytes = bytes ?? BCrypt.generateRandomBytes(count: 16)

        guard bytes.count == 16 else {
            throw BCryptError.invalidSaltByteCount
        }

        self.cost = cost
        self.bytes = bytes
    }
}

public final class BCrypt {
    public let salt: Salt

    private var _digest: [UInt8]?
    private var p: UnsafeMutablePointer<UInt32>
    private var s: UnsafeMutablePointer<UInt32>

    public init(_ salt: Salt? = nil) throws {
        p = UnsafeMutablePointer<UInt32>.allocate(capacity: plen)
        p.initialize(
                from: UnsafeMutableRawPointer(mutating: BCryptConstants.P_orig).assumingMemoryBound(to: UInt32.self),
                count: plen
        )

        s = UnsafeMutablePointer<UInt32>.allocate(capacity: slen)
        s.initialize(
                from: UnsafeMutableRawPointer(mutating: BCryptConstants.S_orig).assumingMemoryBound(to: UInt32.self),
                count: slen
        )

        self.salt = try salt ?? Salt()
    }

    deinit {
        p.deinitialize(count: plen)
        p.deallocate()

        s.deinitialize(count: slen)
        s.deallocate()
    }

    /// Encrypt a message of bytes
    ///
    /// - Parameters:
    ///     - message: **Array<UInt8>** The data to encrypt
    ///
    /// - Returns: **Array<UInt8>** The encrypted data
    public func digest(message: [UInt8]) -> [UInt8] {
        if let digest = _digest {
            return digest
        }

        var j: Int
        let clen: Int = 6
        var cdata: [UInt32] = BCryptConstants.ctext

        var data: [UInt8] = salt.bytes
        var key: [UInt8] = message + [0]

        enhanceKeySchedule(data: &data, key: &key, dataLength: data.count, keyLength: key.count)

        let rounds = 1 << salt.cost
        for _ in 0..<rounds {
            expandKey(&key, length: key.count)
            expandKey(&data, length: data.count)
        }

        for _ in 0..<64 {
            for j in 0..<(clen >> 1) {
                self.encrypt(&cdata, off: j << 1)
            }
        }

        var result = [UInt8](repeating: 0, count: clen * 4)
        result.reserveCapacity(24)

        j = 0
        for i in 0..<clen {
            result[j] = numericCast((cdata[i] >> 24) & 0xff)
            j = j &+ 1
            result[j] = numericCast((cdata[i] >> 16) & 0xff)
            j = j &+ 1
            result[j] = numericCast((cdata[i] >> 8) & 0xff)
            j = j &+ 1
            result[j] = numericCast(cdata[i] & 0xff)
            j = j &+ 1
        }

        let digest = result[0..<23].array
        _digest = digest
        return digest
    }

    fileprivate static func generateRandomBytes(count: Int) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: count)
        bytes.reserveCapacity(count)

        for i in 0..<count {
            let random = UInt8.random(in: 0...UInt8.max)
            bytes[i] = random
        }

        return bytes
    }

    private func streamToWord(data: UnsafeMutablePointer<UInt8>, length: Int, off offp: inout UInt32) -> UInt32 {
        var _: Int
        var word: UInt32 = 0
        var off: UInt32 = offp

        for _ in 0..<4{
            word = (word << 8) | (numericCast(data[numericCast(off)]) & 0xff)
            off = (off &+ 1) % numericCast(length)
        }

        offp = off
        return word
    }

    private func encrypt(_ data: UnsafeMutablePointer<UInt32>, off: Int) {
        func f(_ x: UInt32) -> UInt32 {
            let h = s[numericCast(x >> 24)] &+ s[numericCast(0x100 &+ (x >> 16 & 0xff))]
            return (h ^ s[numericCast(0x200 &+ (x >> 8 & 0xff))]) &+ s[numericCast(0x300 &+ (x & 0xff))]
        }

        if off < 0 {
            return
        }

        var n: UInt32
        var L: UInt32 = data[off]
        var R: UInt32 = data[off &+ 1]

        L ^= p[0]
        var i: Int = 0
        while i <= 16 - 2 {
            // CPU parallel execution
            n = f(L)
            i = i &+ 1
            R ^= n ^ p[i]

            n = f(R)
            i = i &+ 1
            L ^= n ^ p[i]
        }
        data[off] = R ^ p[17]
        data[off &+ 1] = L
    }

    private func expandKey(_ key: UnsafeMutablePointer<UInt8>, length: Int) {
        var koffp: UInt32 = 0
        var data: [UInt32] = [0, 0]

        for i in 0..<plen {
            p[i] = p[i] ^ streamToWord(data: key, length: length, off: &koffp)
        }

        var i = 0

        while i < plen {
            self.encrypt(&data, off: 0)
            p[i] = data[0]
            p[i &+ 1] = data[1]
            i = i &+ 2
        }

        i = 0

        while i < slen {
            self.encrypt(&data, off: 0)
            s[i] = data[0]
            s[i &+ 1] = data[1]
            i = i &+ 2
        }
    }

    private func enhanceKeySchedule(
            data: UnsafeMutablePointer<UInt8>,
            key: UnsafeMutablePointer<UInt8>,
            dataLength dlen: Int,
            keyLength klen: Int
    ) {
        var doffp: UInt32 = 0
        var koffp: UInt32 = 0

        var LR: [UInt32] = [0, 0]

        for i in 0..<plen {
            p[i] = p[i] ^ streamToWord(data: key, length: klen, off: &koffp)
        }

        var i = 0

        while i < plen {
            LR[0] ^= streamToWord(data: data, length: dlen, off: &doffp)
            LR[1] ^= streamToWord(data: data, length: dlen, off: &doffp)
            self.encrypt(&LR, off: 0)
            p[i] = LR[0]
            p[i &+ 1] = LR[1]

            i = i &+ 2
        }

        i = 0

        while i < slen {
            LR[0] ^= streamToWord(data: data, length: dlen, off: &doffp)
            LR[1] ^= streamToWord(data: data, length: dlen, off: &doffp)
            self.encrypt(&LR, off: 0)
            s[i] = LR[0]
            s[i &+ 1] = LR[1]

            i = i &+ 2
        }
    }

    /// Encrypt and hash a message of bytes
    ///
    /// - Parameters:
    ///     - message: **Array<UInt8>** The data to encrypt
    ///     - salt: **Slat?** Optionally provide your own generated salt
    ///
    /// - Throws:
    ///     - `BCryptError.invalidSaltByteCount` if `salt` count is invalid (less than 16)
    ///
    /// - Returns: **Array<UInt8>** The encrypted data
    public static func hash(message: [UInt8], with salt: Salt? = nil) throws -> [UInt8] {
        let bcrypt = try BCrypt(salt)
        let digest = bcrypt.digest(message: message)
        let serializer = Serializer(bcrypt.salt, digest: digest)
        return serializer.serialize()
    }

    /// Encrypt and hash a string message
    ///
    /// - Parameters:
    ///     - message: **String** The data to encrypt
    ///     - salt: **Slat?** Optionally provide your own generated salt
    ///
    /// - Throws:
    ///     - `BCryptError.invalidSaltByteCount` if `salt` count is invalid (less than 16)
    ///
    /// - Returns: **Array<UInt8>** The encrypted data
    public static func hash(message: String, with salt: Salt? = nil) throws -> [UInt8] {
        return try hash(message: message.bytes, with: salt)
    }

    /// Compare a message against an encrypted hash
    ///
    /// - Parameters:
    ///     - message: **Array<UInt8>** The message to compare
    ///     - hash: **Array<UInt8>** The hash to compare against
    ///
    /// - Throws:
    ///     - `BCryptError.invalidSaltByteCount` if `salt` count is invalid (less than 16)
    ///     - `BCryptError.invalidHash` if `hash` is not a valid bcrypt hash
    ///     - `BCryptError.invalidSaltCost` if the salt cost is invalid
    ///
    /// - Returns: **Bool** True if message and hash are the same else false
    public static func compare(message: [UInt8], against hash: [UInt8]) throws -> Bool {
        let parser = try Parser(hash)
        let salt = try parser.parseSalt()
        let digest = parser.parseDigest()

        let bcrypt = try BCrypt(salt)
        let testDigest = bcrypt.digest(message: message)

        return testDigest == digest
    }

    /// Compare a message against an encrypted hash
    ///
    /// - Parameters:
    ///     - message: **String** The message to compare
    ///     - hash: **String** The hash to compare against
    ///
    /// - Throws:
    ///     - `BCryptError.invalidSaltByteCount` if `salt` count is invalid (less than 16)
    ///     - `BCryptError.invalidHash` if `hash` is not a valid bcrypt hash
    ///     - `BCryptError.invalidSaltCost` if the salt cost is invalid
    ///
    /// - Returns: **Bool** True if message and hash are the same else false
    public static func compare(message: String, against hash: String) throws -> Bool {
        return try compare(message: message.bytes, against: hash.bytes)
    }

    /// Compare a message against an encrypted hash
    ///
    /// - Parameters:
    ///     - message: **Array<UInt8>** The message to compare
    ///     - hash: **String** The hash to compare against
    ///
    /// - Throws:
    ///     - `BCryptError.invalidSaltByteCount` if `salt` count is invalid (less than 16)
    ///     - `BCryptError.invalidHash` if `hash` is not a valid bcrypt hash
    ///     - `BCryptError.invalidSaltCost` if the salt cost is invalid
    ///
    /// - Returns: **Bool** True if message and hash are the same else false
    public static func compare(message: [UInt8], against hash: String) throws -> Bool {
        return try compare(message: message, against: hash.bytes)
    }

    /// Compare a message against an encrypted hash
    ///
    /// - Parameters:
    ///     - message: **String** The message to compare
    ///     - hash: **Array<UInt8>** The hash to compare against
    ///
    /// - Throws:
    ///     - `BCryptError.invalidSaltByteCount` if `salt` count is invalid (less than 16)
    ///     - `BCryptError.invalidHash` if `hash` is not a valid bcrypt hash
    ///     - `BCryptError.invalidSaltCost` if the salt cost is invalid
    ///
    /// - Returns: **Bool** True if message and hash are the same else false
    public static func compare(message: String, against hash: [UInt8]) throws -> Bool {
        return try compare(message: message.bytes, against: hash)
    }
}

extension Array where Element == UInt8 {
    /// Convert UInt8 array to string
    ///
    /// - Returns: **String** The converted string, empty string if it wasn't possible to convert
    public func string() -> String {
        return String(bytes: self, encoding: .utf8) ?? ""
    }
}
