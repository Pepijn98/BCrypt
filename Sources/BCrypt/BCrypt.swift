import Random

fileprivate let plen: Int = 18
fileprivate let slen: Int = 1024

public struct Salt {
    public static var defaultRandom: RandomProtocol = OSRandom()
    public static var defaultCost: UInt = 14

    public let cost: UInt
    public let bytes: Bytes

    public init(cost: UInt = Salt.defaultCost, bytes: Bytes? = nil) throws {
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

    private var _digest: Bytes?
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

    public func digest(salt: Salt, message: Bytes) -> Bytes {
        if let digest: Bytes = _digest {
            return digest
        }

        let message = message + [0]

        var j: Int
        let clen: Int = 6
        var cdata: [UInt32] = BCryptConstants.ctext

        let saltPointer: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>(mutating: salt.bytes)
        let messagePointer: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>(mutating: message)
        enhanceKeySchedule(data: saltPointer, key: messagePointer)

        let rounds = 1 << salt.cost

        for _ in 0..<rounds {
            expandKey(key: messagePointer)
            expandKey(key: saltPointer)
        }

        for _ in 0..<64 {
            for j in 0..<(clen >> 1) {
                self.encrypt(&cdata, off: j << 1)
            }
        }

        var result = Bytes(repeating: 0, count: clen * 4)

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

//    func encrypt(L: inout UnsafeMutablePointer<UInt32>, R: inout UnsafeMutablePointer<UInt32>) {
//        var i: Int = 0
//        while i < 16 {
//            i = i &+ 2
//            L ^= p[i]
//            R ^= f(L)
//            R ^= P[i &+ 1]
//            L ^= f(R)
//        }
//        L ^= p[16]
//        R ^= p[17]
//        //  TODO: Is this correct?
//        let oldL = L
//        L = R
//        R = oldL
//    }

    private func streamToWord(data: UnsafeMutablePointer<UInt8>, off offp: inout UInt32) -> UInt32 {
        var _ : Int
        var word : UInt32 = 0
        var off : UInt32 = offp

        data.withMemoryRebound(to: UInt32.self, capacity: 4) { data in
            word = (word << 8) | (data[numericCast(off)] & 0xff)
            off = (off &+ 1) % 4
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

    private func expandKey(key: UnsafeMutablePointer<UInt8>) {
        var koffp: UInt32 = 0
        var data: [UInt32] = [0, 0]

        for i in 0..<plen {
            p[i] = p[i] ^ streamToWord(data: key, off: &koffp)
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

    private func enhanceKeySchedule(data: UnsafeMutablePointer<UInt8>, key: UnsafeMutablePointer<UInt8>) {
        var doffp: UInt32 = 0
        var koffp: UInt32 = 0

        var LR: [UInt32] = [0, 0]

        for i in 0..<plen {
            p[i] = p[i] ^ streamToWord(data: key, off: &koffp)
        }

        var i = 0

        while i < plen {
            LR[0] ^= streamToWord(data: data, off: &doffp)
            LR[1] ^= streamToWord(data: data, off: &doffp)
            self.encrypt(&LR, off: 0)
            p[i] = LR[0]
            p[i &+ 1] = LR[1]

            i = i &+ 2
        }

        i = 0

        while i < slen {
            LR[0] ^= streamToWord(data: data, off: &doffp)
            LR[1] ^= streamToWord(data: data, off: &doffp)
            self.encrypt(&LR, off: 0)
            s[i] = LR[0]
            s[i &+ 1] = LR[1]

            i = i &+ 2
        }
    }
}
