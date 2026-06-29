import Foundation

/// Minimal arbitrary-precision unsigned integer for EC point decompression.
/// Little-endian `UInt32` limbs. Not constant-time — only used on PUBLIC keys.
struct BigUInt: Equatable {
    private(set) var limbs: [UInt32]

    init(limbs: [UInt32]) {
        var l = limbs
        while l.last == 0 { l.removeLast() }
        self.limbs = l
    }

    init(_ value: UInt32) { self.init(limbs: value == 0 ? [] : [value]) }

    /// Big-endian bytes → BigUInt.
    init(bytes: [UInt8]) {
        var padded = bytes
        while padded.count % 4 != 0 { padded.insert(0, at: 0) }
        var l: [UInt32] = []
        var i = padded.count
        while i > 0 {
            let limb = UInt32(padded[i - 4]) << 24 | UInt32(padded[i - 3]) << 16
                | UInt32(padded[i - 2]) << 8 | UInt32(padded[i - 1])
            l.append(limb)
            i -= 4
        }
        self.init(limbs: l)
    }

    /// Fixed-length big-endian byte serialization.
    func toBytes(count: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: count)
        for (i, limb) in limbs.enumerated() {
            let base = count - 4 * (i + 1)
            for j in 0..<4 {
                let pos = base + (3 - j)
                if pos >= 0 && pos < count { out[pos] = UInt8((limb >> (8 * j)) & 0xFF) }
            }
        }
        return out
    }

    var isZero: Bool { limbs.isEmpty }
    var isOdd: Bool { (limbs.first ?? 0) & 1 == 1 }

    var bitWidth: Int {
        guard let top = limbs.last else { return 0 }
        return (limbs.count - 1) * 32 + (32 - top.leadingZeroBitCount)
    }

    func bit(_ i: Int) -> Bool {
        let limb = i / 32
        guard limb < limbs.count else { return false }
        return (limbs[limb] >> (i % 32)) & 1 == 1
    }

    func compare(_ other: BigUInt) -> Int {
        if limbs.count != other.limbs.count { return limbs.count < other.limbs.count ? -1 : 1 }
        var i = limbs.count - 1
        while i >= 0 {
            if limbs[i] != other.limbs[i] { return limbs[i] < other.limbs[i] ? -1 : 1 }
            i -= 1
        }
        return 0
    }

    func adding(_ other: BigUInt) -> BigUInt {
        var res: [UInt32] = []
        let n = Swift.max(limbs.count, other.limbs.count)
        var carry: UInt64 = 0
        for i in 0..<n {
            let a = i < limbs.count ? UInt64(limbs[i]) : 0
            let b = i < other.limbs.count ? UInt64(other.limbs[i]) : 0
            let s = a + b + carry
            res.append(UInt32(s & 0xFFFF_FFFF))
            carry = s >> 32
        }
        if carry > 0 { res.append(UInt32(carry)) }
        return BigUInt(limbs: res)
    }

    /// `self - other`, assuming `self >= other`.
    func subtracting(_ other: BigUInt) -> BigUInt {
        var res: [UInt32] = []
        var borrow: Int64 = 0
        for i in 0..<limbs.count {
            let a = Int64(limbs[i])
            let b = i < other.limbs.count ? Int64(other.limbs[i]) : 0
            var d = a - b - borrow
            if d < 0 { d += 0x1_0000_0000; borrow = 1 } else { borrow = 0 }
            res.append(UInt32(truncatingIfNeeded: d))
        }
        return BigUInt(limbs: res)
    }

    func multiplying(_ other: BigUInt) -> BigUInt {
        if isZero || other.isZero { return BigUInt(0) }
        var res = [UInt32](repeating: 0, count: limbs.count + other.limbs.count)
        for i in 0..<limbs.count {
            var carry: UInt64 = 0
            let ai = UInt64(limbs[i])
            for j in 0..<other.limbs.count {
                let cur = UInt64(res[i + j]) + ai * UInt64(other.limbs[j]) + carry
                res[i + j] = UInt32(cur & 0xFFFF_FFFF)
                carry = cur >> 32
            }
            res[i + other.limbs.count] = res[i + other.limbs.count] &+ UInt32(carry)
        }
        return BigUInt(limbs: res)
    }

    func shiftedRight(_ n: Int) -> BigUInt {
        let limbShift = n / 32, bitShift = n % 32
        if limbShift >= limbs.count { return BigUInt(0) }
        var res = Array(limbs[limbShift...])
        if bitShift > 0 {
            for i in 0..<res.count {
                res[i] >>= bitShift
                if i + 1 < res.count { res[i] |= res[i + 1] << (32 - bitShift) }
            }
        }
        return BigUInt(limbs: res)
    }

    /// `self mod modulus` via bitwise long division, operating on an in-place
    /// limb buffer to avoid per-bit allocations (this is the hot path for EC
    /// point decompression during verification).
    func mod(_ modulus: BigUInt) -> BigUInt {
        if modulus.isZero { return self }
        if compare(modulus) < 0 { return self }
        let m = modulus.limbs
        var rem: [UInt32] = []
        rem.reserveCapacity(m.count + 1)
        var i = bitWidth - 1
        while i >= 0 {
            // rem <<= 1
            var carry: UInt32 = 0
            for k in 0..<rem.count {
                let shifted = (rem[k] << 1) | carry
                carry = rem[k] >> 31
                rem[k] = shifted
            }
            if carry > 0 { rem.append(carry) }
            // rem |= bit i of self
            if bit(i) {
                if rem.isEmpty { rem.append(1) } else { rem[0] |= 1 }
            }
            // if rem >= modulus: rem -= modulus
            if BigUInt.compareLimbs(rem, m) >= 0 {
                BigUInt.subtractLimbsInPlace(&rem, m)
            }
            i -= 1
        }
        return BigUInt(limbs: rem)
    }

    /// Compare little-endian limb arrays, ignoring trailing zero limbs.
    private static func compareLimbs(_ a: [UInt32], _ b: [UInt32]) -> Int {
        var ai = a.count - 1
        while ai >= 0 && a[ai] == 0 { ai -= 1 }
        var bi = b.count - 1
        while bi >= 0 && b[bi] == 0 { bi -= 1 }
        if ai != bi { return ai < bi ? -1 : 1 }
        while ai >= 0 {
            if a[ai] != b[ai] { return a[ai] < b[ai] ? -1 : 1 }
            ai -= 1
        }
        return 0
    }

    /// `a -= b` in place, assuming `a >= b`.
    private static func subtractLimbsInPlace(_ a: inout [UInt32], _ b: [UInt32]) {
        var borrow: Int64 = 0
        for k in 0..<a.count {
            let av = Int64(a[k])
            let bv = k < b.count ? Int64(b[k]) : 0
            var d = av - bv - borrow
            if d < 0 { d += 0x1_0000_0000; borrow = 1 } else { borrow = 0 }
            a[k] = UInt32(truncatingIfNeeded: d)
        }
    }

    static func modMul(_ a: BigUInt, _ b: BigUInt, _ m: BigUInt) -> BigUInt {
        a.multiplying(b).mod(m)
    }

    static func modPow(_ base: BigUInt, _ exp: BigUInt, _ m: BigUInt) -> BigUInt {
        var result = BigUInt(1)
        var acc = base.mod(m)
        let bits = exp.bitWidth
        for i in 0..<bits {
            if exp.bit(i) { result = modMul(result, acc, m) }
            acc = modMul(acc, acc, m)
        }
        return result
    }
}

/// SEC1 EC point compression/decompression for the NIST curves, so the
/// library can build public keys from compressed Multikey/did:key bytes on
/// iOS 14/15 (CryptoKit's `compressedRepresentation` is iOS 16+).
///
/// Decompression runs a modular square root (`~200` modular multiplications),
/// so it costs a few hundred ms with this simple `UInt32`-limb arithmetic.
/// That is fine for verification (1–2 key decompressions, not a hot loop); if
/// profiling ever shows it matters, switch the limbs to `UInt64`
/// (`multipliedFullWidth`) or add NIST-prime fast reduction.
enum ECPoint {
    struct Curve {
        let fieldSize: Int   // bytes
        let p: BigUInt
        let a: BigUInt       // p - 3
        let b: BigUInt
        let sqrtExp: BigUInt // (p + 1) / 4  (valid because p ≡ 3 mod 4)

        init(fieldSize: Int, pHex: String, bHex: String) {
            self.fieldSize = fieldSize
            let p = BigUInt(bytes: BigEndian.bytes(fromHex: pHex))
            self.p = p
            self.a = p.subtracting(BigUInt(3))
            self.b = BigUInt(bytes: BigEndian.bytes(fromHex: bHex))
            self.sqrtExp = p.adding(BigUInt(1)).shiftedRight(2)
        }
    }

    static let p256 = Curve(
        fieldSize: 32,
        pHex: "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
        bHex: "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B")

    static let p384 = Curve(
        fieldSize: 48,
        pHex: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
        bHex: "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF")

    /// Compressed SEC1 point (`0x02|0x03 ‖ X`) → uncompressed (`0x04 ‖ X ‖ Y`),
    /// or nil if the point isn't on the curve.
    static func decompress(_ compressed: Data, curve: Curve) -> Data? {
        let bytes = Array(compressed)
        guard bytes.count == curve.fieldSize + 1, bytes[0] == 0x02 || bytes[0] == 0x03 else {
            return nil
        }
        let prefix = bytes[0]
        let xBytes = Array(bytes[1...])
        let x = BigUInt(bytes: xBytes)
        guard x.compare(curve.p) < 0 else { return nil }

        // rhs = x^3 - 3x + b (mod p)
        let x2 = BigUInt.modMul(x, x, curve.p)
        let x3 = BigUInt.modMul(x2, x, curve.p)
        let ax = BigUInt.modMul(curve.a, x, curve.p)
        let rhs = x3.adding(ax).mod(curve.p).adding(curve.b).mod(curve.p)

        // y = sqrt(rhs) = rhs^((p+1)/4) mod p
        var y = BigUInt.modPow(rhs, curve.sqrtExp, curve.p)
        guard BigUInt.modMul(y, y, curve.p) == rhs else { return nil }  // not a quadratic residue

        // Choose the root whose parity matches the prefix.
        if y.isOdd != (prefix & 1 == 1) {
            y = curve.p.subtracting(y)
        }
        return Data([0x04] + xBytes + y.toBytes(count: curve.fieldSize))
    }

    /// Uncompressed (`0x04 ‖ X ‖ Y`) → compressed (`0x02|0x03 ‖ X`). Trivial:
    /// no field math, just the parity of Y.
    static func compress(x963 uncompressed: Data, fieldSize: Int) -> Data? {
        let bytes = Array(uncompressed)
        guard bytes.count == 1 + fieldSize * 2, bytes[0] == 0x04 else { return nil }
        let x = Array(bytes[1...(fieldSize)])
        let yLast = bytes[bytes.count - 1]
        let prefix: UInt8 = (yLast & 1) == 0 ? 0x02 : 0x03
        return Data([prefix] + x)
    }
}
