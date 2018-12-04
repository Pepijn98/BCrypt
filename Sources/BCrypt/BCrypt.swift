import Random

fileprivate let plen: Int = 18
fileprivate let slen: Int = 1024

public struct Salt {
    public static var defaultRandom: RandomProtocol = OSRandom()
    public static var defaultCost: UInt = 14

    public let cost: UInt
    public let bytes: [UInt8]

    public init(cost: UInt = Salt.defaultCost, bytes: [UInt8]? = nil) throws {
        let bytes = try bytes ?? Salt.defaultRandom.bytes(count: 16)

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

    private func streamToWord(data: UnsafeMutablePointer<UInt8>, length: Int, off offp: inout UInt32) -> UInt32 {
        var _: Int
        var word: UInt32 = 0
        var off: UInt32 = offp

        for _ in 0..<4{
            word = (word << 8) | (numericCast(data[numericCast(off)]) & 0xff)
            off = (off &+ 1) % numericCast(length)
        }

        /*
        data.withMemoryRebound(to: UInt32.self, capacity: 4) { data in
            word = (word << 8) | (data[numericCast(off)] & 0xff)
            off = (off &+ 1) % numericCast(length)
        }
        */

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

    private func enhanceKeySchedule(data: UnsafeMutablePointer<UInt8>, key: UnsafeMutablePointer<UInt8>, dataLength dlen: Int, keyLength klen: Int) {
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

    public static func make(message: [UInt8], salt: Salt? = nil) throws -> [UInt8] {
        let bcrypt = try BCrypt(salt)
        let digest = bcrypt.digest(message: message)
        let serializer = Serializer(bcrypt.salt, digest: digest)
        return serializer.serialize()
    }

    public static func make(message: String, salt: Salt? = nil) throws -> [UInt8] {
        return try make(message: message.bytes, salt: salt)
    }

    public static func verify(message: [UInt8], matches input: [UInt8]) throws -> Bool {
        let parser = try Parser(input)
        let salt = try parser.parseSalt()
        let digest = try parser.parseDigest() ?? []

        let bcrypt = try BCrypt(salt)
        let testDigest = bcrypt.digest(message: message)

        return testDigest == digest
    }

    public static func verify(message: String, matches input: String) throws -> Bool {
        return try verify(message: message.bytes, matches: input.bytes)
    }

    public static func verify(message: [UInt8], matches input: String) throws -> Bool {
        return try verify(message: message, matches: input.bytes)
    }

    public static func verify(message: String, matches input: [UInt8]) throws -> Bool {
        return try verify(message: message.bytes, matches: input)
    }
}
