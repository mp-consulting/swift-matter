/// NIST P-256 point arithmetic for SPAKE2+, which needs scalar multiples of arbitrary points and point additions that
/// swift-crypto does not expose. Coordinates are in Montgomery form over 4×64-bit limbs; point addition uses the
/// complete formulas of Renes, Costello and Batina (2015, algorithm 4, a = -3), so doubling and the identity need no
/// branches, and scalar multiplication is a Montgomery ladder with constant-time swaps.

/// A 256-bit unsigned integer, least significant limb first.
struct U256: Equatable, Sendable {
    var limbs: SIMD4<UInt64>

    init(_ l0: UInt64, _ l1: UInt64, _ l2: UInt64, _ l3: UInt64) { limbs = SIMD4(l0, l1, l2, l3) }
    init(limbs: SIMD4<UInt64>) { self.limbs = limbs }

    static let zero = U256(0, 0, 0, 0)
    static let one = U256(1, 0, 0, 0)

    /// From 32 big-endian bytes.
    init?(bigEndian bytes: some Collection<UInt8>) {
        guard bytes.count == 32 else { return nil }
        let array = Array(bytes)
        var limbs = SIMD4<UInt64>()
        for index in 0..<4 {
            var limb: UInt64 = 0
            for byte in array[(24 - index * 8)..<(32 - index * 8)] { limb = limb << 8 | UInt64(byte) }
            limbs[index] = limb
        }
        self.limbs = limbs
    }

    var bigEndianBytes: [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(32)
        for index in (0..<4).reversed() { out.appendBigEndian(limbs[index]) }
        return out
    }

    var isZero: Bool { limbs == .zero }

    func bit(_ index: Int) -> UInt64 { (limbs[index / 64] >> UInt64(index % 64)) & 1 }

    /// self + other, and the carry out.
    func adding(_ other: U256) -> (U256, UInt64) {
        var result = SIMD4<UInt64>()
        var carry: UInt64 = 0
        for index in 0..<4 {
            let (sum1, overflow1) = limbs[index].addingReportingOverflow(other.limbs[index])
            let (sum2, overflow2) = sum1.addingReportingOverflow(carry)
            result[index] = sum2
            carry = (overflow1 ? 1 : 0) + (overflow2 ? 1 : 0)
        }
        return (U256(limbs: result), carry)
    }

    /// self - other, and the borrow out.
    func subtracting(_ other: U256) -> (U256, UInt64) {
        var result = SIMD4<UInt64>()
        var borrow: UInt64 = 0
        for index in 0..<4 {
            let (difference1, overflow1) = limbs[index].subtractingReportingOverflow(other.limbs[index])
            let (difference2, overflow2) = difference1.subtractingReportingOverflow(borrow)
            result[index] = difference2
            borrow = (overflow1 ? 1 : 0) + (overflow2 ? 1 : 0)
        }
        return (U256(limbs: result), borrow)
    }

    /// `a` when `mask` is all ones, `b` when it is zero, without a branch.
    static func select(_ mask: UInt64, _ a: U256, _ b: U256) -> U256 {
        let wide = SIMD4<UInt64>(repeating: mask)
        return U256(limbs: (a.limbs & wide) | (b.limbs & ~wide))
    }
}

/// Arithmetic modulo an odd 256-bit modulus, in Montgomery form (R = 2^256).
struct MontgomeryField: Sendable {
    let modulus: U256
    /// -modulus^-1 mod 2^64.
    private let inverse: UInt64
    /// R^2 mod modulus.
    private let rSquared: U256

    init(modulus: U256) {
        self.modulus = modulus
        var inverse: UInt64 = 1
        for _ in 0..<6 { inverse = inverse &* (2 &- modulus.limbs[0] &* inverse) }
        self.inverse = 0 &- inverse
        // R mod m is 2^256 - m (m > 2^255), then doubled 256 times gives R^2 mod m.
        var value = U256.zero.subtracting(modulus).0
        for _ in 0..<256 { value = Self.addMod(value, value, modulus) }
        rSquared = value
    }

    private static func addMod(_ a: U256, _ b: U256, _ modulus: U256) -> U256 {
        let (sum, carry) = a.adding(b)
        let (reduced, borrow) = sum.subtracting(modulus)
        // Keep the reduced value when the sum overflowed or did not underflow when reduced.
        let keepReduced = (0 &- carry) | (0 &- (1 &- borrow))
        return U256.select(keepReduced, reduced, sum)
    }

    func add(_ a: U256, _ b: U256) -> U256 { Self.addMod(a, b, modulus) }

    func subtract(_ a: U256, _ b: U256) -> U256 {
        let (difference, borrow) = a.subtracting(b)
        let corrected = difference.adding(modulus).0
        return U256.select(0 &- borrow, corrected, difference)
    }

    func negate(_ a: U256) -> U256 { subtract(.zero, a) }

    /// a·b·R^-1 mod m (CIOS).
    func multiply(_ a: U256, _ b: U256) -> U256 {
        var t = SIMD8<UInt64>()
        let n = modulus.limbs
        for i in 0..<4 {
            var carry: UInt64 = 0
            for j in 0..<4 {
                let (high, low) = a.limbs[j].multipliedFullWidth(by: b.limbs[i])
                let (sum1, overflow1) = low.addingReportingOverflow(t[j])
                let (sum2, overflow2) = sum1.addingReportingOverflow(carry)
                t[j] = sum2
                carry = high &+ (overflow1 ? 1 : 0) &+ (overflow2 ? 1 : 0)
            }
            let (sum, overflow) = t[4].addingReportingOverflow(carry)
            t[4] = sum
            t[5] = overflow ? 1 : 0

            let m = t[0] &* inverse
            let (high0, low0) = m.multipliedFullWidth(by: n[0])
            carry = high0 &+ (low0.addingReportingOverflow(t[0]).overflow ? 1 : 0)
            for j in 1..<4 {
                let (high, low) = m.multipliedFullWidth(by: n[j])
                let (sum1, overflow1) = low.addingReportingOverflow(t[j])
                let (sum2, overflow2) = sum1.addingReportingOverflow(carry)
                t[j - 1] = sum2
                carry = high &+ (overflow1 ? 1 : 0) &+ (overflow2 ? 1 : 0)
            }
            let (sum3, overflow3) = t[4].addingReportingOverflow(carry)
            t[3] = sum3
            t[4] = t[5] &+ (overflow3 ? 1 : 0)
        }
        let value = U256(t[0], t[1], t[2], t[3])
        let (reduced, borrow) = value.subtracting(modulus)
        let keepReduced = (0 &- t[4]) | (0 &- (1 &- borrow))
        return U256.select(keepReduced, reduced, value)
    }

    func square(_ a: U256) -> U256 { multiply(a, a) }

    func toMontgomery(_ a: U256) -> U256 { multiply(a, rSquared) }
    func fromMontgomery(_ a: U256) -> U256 { multiply(a, .one) }

    /// The Montgomery form of 1.
    var one: U256 { toMontgomery(.one) }

    /// base^exponent, both the base and the result in Montgomery form; the exponent is public.
    func power(_ base: U256, _ exponent: U256) -> U256 {
        var result = one
        for index in (0..<256).reversed() {
            result = square(result)
            if exponent.bit(index) == 1 { result = multiply(result, base) }
        }
        return result
    }

    /// a^-1 by Fermat (the modulus is prime), in Montgomery form.
    func invert(_ a: U256) -> U256 { power(a, modulus.subtracting(U256(2, 0, 0, 0)).0) }

    /// Reduces big-endian bytes of any length modulo the modulus (normal form).
    func reduce(bigEndian bytes: some Collection<UInt8>) -> U256 {
        var accumulator = U256.zero
        for byte in bytes {
            for _ in 0..<8 { accumulator = add(accumulator, accumulator) }
            accumulator = add(accumulator, U256(UInt64(byte), 0, 0, 0))
        }
        return accumulator
    }
}

public enum P256Error: Error, Equatable, Sendable {
    case invalidPointEncoding
    case pointNotOnCurve
    case pointAtInfinity
    case invalidScalar
}

/// A point on P-256 in projective coordinates (X:Y:Z), Montgomery form; the identity is (0:1:0).
struct P256Point: Sendable {
    var x: U256
    var y: U256
    var z: U256

    static let field = MontgomeryField(modulus: U256(0xFFFF_FFFF_FFFF_FFFF, 0x0000_0000_FFFF_FFFF, 0, 0xFFFF_FFFF_0000_0001))
    static let order = MontgomeryField(modulus: U256(0xF3B9_CAC2_FC63_2551, 0xBCE6_FAAD_A717_9E84, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_0000_0000))
    private static let b = field.toMontgomery(U256(0x3BCE_3C3E_27D2_604B, 0x651D_06B0_CC53_B0F6, 0xB3EB_BD55_7698_86BC, 0x5AC6_35D8_AA3A_93E7))

    static let identity = P256Point(x: .zero, y: field.one, z: .zero)
    static let generator = P256Point(
        affineX: U256(0xF4A1_3945_D898_C296, 0x7703_7D81_2DEB_33A0, 0xF8BC_E6E5_63A4_40F2, 0x6B17_D1F2_E12C_4247),
        affineY: U256(0xCBB6_4068_37BF_51F5, 0x2BCE_3357_6B31_5ECE, 0x8EE7_EB4A_7C0F_9E16, 0x4FE3_42E2_FE1A_7F9B)
    )

    init(x: U256, y: U256, z: U256) {
        self.x = x
        self.y = y
        self.z = z
    }

    /// From affine coordinates in normal form.
    init(affineX: U256, affineY: U256) {
        x = Self.field.toMontgomery(affineX)
        y = Self.field.toMontgomery(affineY)
        z = Self.field.one
    }

    /// From SEC 1 encoding: uncompressed (65 bytes) or compressed (33 bytes); the point is checked to be on the curve.
    init(sec1 bytes: some Collection<UInt8>) throws {
        let bytes = Array(bytes)
        let field = Self.field
        guard bytes.count == 65 && bytes[0] == 0x04 || bytes.count == 33 && (bytes[0] == 0x02 || bytes[0] == 0x03),
              let affineX = U256(bigEndian: bytes[1..<33]),
              affineX.subtracting(field.modulus).1 == 1
        else { throw P256Error.invalidPointEncoding }

        let mx = field.toMontgomery(affineX)
        let rightSide = field.add(field.multiply(field.square(mx), mx),
                                  field.add(field.negate(field.add(field.add(mx, mx), mx)), Self.b))
        if bytes.count == 65 {
            guard let affineY = U256(bigEndian: bytes[33..<65]), affineY.subtracting(field.modulus).1 == 1
            else { throw P256Error.invalidPointEncoding }
            let my = field.toMontgomery(affineY)
            guard field.square(my) == rightSide else { throw P256Error.pointNotOnCurve }
            self.init(x: mx, y: my, z: field.one)
        } else {
            // p ≡ 3 (mod 4): a square root is rightSide^((p+1)/4).
            let exponent = U256(0, 0x0000_0000_4000_0000, 0x4000_0000_0000_0000, 0x3FFF_FFFF_C000_0000)
            var my = field.power(rightSide, exponent)
            guard field.square(my) == rightSide else { throw P256Error.pointNotOnCurve }
            if field.fromMontgomery(my).bit(0) != UInt64(bytes[0] & 1) { my = field.negate(my) }
            self.init(x: mx, y: my, z: field.one)
        }
    }

    var isIdentity: Bool { z.isZero }

    /// Uncompressed SEC 1 encoding (65 bytes).
    func sec1Uncompressed() throws -> [UInt8] {
        guard !isIdentity else { throw P256Error.pointAtInfinity }
        let field = Self.field
        let zInverse = field.invert(z)
        return [0x04] + field.fromMontgomery(field.multiply(x, zInverse)).bigEndianBytes
            + field.fromMontgomery(field.multiply(y, zInverse)).bigEndianBytes
    }

    static func + (p: P256Point, q: P256Point) -> P256Point {
        let f = field
        var t0 = f.multiply(p.x, q.x), t1 = f.multiply(p.y, q.y), t2 = f.multiply(p.z, q.z)
        var t3 = f.add(p.x, p.y), t4 = f.add(q.x, q.y)
        t3 = f.multiply(t3, t4)
        t4 = f.add(t0, t1)
        t3 = f.subtract(t3, t4)
        t4 = f.add(p.y, p.z)
        var x3 = f.add(q.y, q.z)
        t4 = f.multiply(t4, x3)
        x3 = f.add(t1, t2)
        t4 = f.subtract(t4, x3)
        x3 = f.add(p.x, p.z)
        var y3 = f.add(q.x, q.z)
        x3 = f.multiply(x3, y3)
        y3 = f.add(t0, t2)
        y3 = f.subtract(x3, y3)
        var z3 = f.multiply(b, t2)
        x3 = f.subtract(y3, z3)
        z3 = f.add(x3, x3)
        x3 = f.add(x3, z3)
        z3 = f.subtract(t1, x3)
        x3 = f.add(t1, x3)
        y3 = f.multiply(b, y3)
        t1 = f.add(t2, t2)
        t2 = f.add(t1, t2)
        y3 = f.subtract(y3, t2)
        y3 = f.subtract(y3, t0)
        t1 = f.add(y3, y3)
        y3 = f.add(t1, y3)
        t1 = f.add(t0, t0)
        t0 = f.add(t1, t0)
        t0 = f.subtract(t0, t2)
        t1 = f.multiply(t4, y3)
        t2 = f.multiply(t0, y3)
        y3 = f.multiply(x3, z3)
        y3 = f.add(y3, t2)
        x3 = f.multiply(t3, x3)
        x3 = f.subtract(x3, t1)
        z3 = f.multiply(t4, z3)
        t1 = f.multiply(t3, t0)
        z3 = f.add(z3, t1)
        return P256Point(x: x3, y: y3, z: z3)
    }

    static prefix func - (p: P256Point) -> P256Point {
        P256Point(x: p.x, y: field.negate(p.y), z: p.z)
    }

    static func - (p: P256Point, q: P256Point) -> P256Point { p + -q }

    /// scalar·point by a Montgomery ladder over all 256 bits.
    static func * (scalar: U256, point: P256Point) -> P256Point {
        var r0 = identity, r1 = point
        for index in (0..<256).reversed() {
            let mask = 0 &- scalar.bit(index)
            swap(mask, &r0, &r1)
            r1 = r0 + r1
            r0 = r0 + r0
            swap(mask, &r0, &r1)
        }
        return r0
    }

    private static func swap(_ mask: UInt64, _ a: inout P256Point, _ b: inout P256Point) {
        let newA = P256Point(x: U256.select(mask, b.x, a.x), y: U256.select(mask, b.y, a.y), z: U256.select(mask, b.z, a.z))
        b = P256Point(x: U256.select(mask, a.x, b.x), y: U256.select(mask, a.y, b.y), z: U256.select(mask, a.z, b.z))
        a = newA
    }

    /// Projective equality.
    static func == (p: P256Point, q: P256Point) -> Bool {
        let f = field
        if p.isIdentity || q.isIdentity { return p.isIdentity == q.isIdentity }
        return f.multiply(p.x, q.z) == f.multiply(q.x, p.z) && f.multiply(p.y, q.z) == f.multiply(q.y, p.z)
    }
}

/// A scalar in [0, n), from big-endian bytes of any length reduced modulo the group order.
struct P256Scalar: Sendable {
    let value: U256

    init(reducing bytes: some Collection<UInt8>) { value = P256Point.order.reduce(bigEndian: bytes) }

    /// Exactly 32 bytes below the order.
    init(bytes: some Collection<UInt8>) throws {
        guard let value = U256(bigEndian: bytes), value.subtracting(P256Point.order.modulus).1 == 1
        else { throw P256Error.invalidScalar }
        self.value = value
    }

    var bytes: [UInt8] { value.bigEndianBytes }
}
