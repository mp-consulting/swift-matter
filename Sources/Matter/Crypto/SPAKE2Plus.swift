import Crypto

/// SPAKE2+ over P-256 with SHA-256 (draft-bar-cfrg-spake2plus-02), as Matter's PASE uses it (Core §3.10): the
/// commissioner is the prover, the commissionee the verifier.
public enum SPAKE2Plus {
    static let m = try! P256Point(sec1: hex("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"))
    static let n = try! P256Point(sec1: hex("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"))
    static let mEncoded = try! m.sec1Uncompressed()
    static let nEncoded = try! n.sec1Uncompressed()

    /// scalar·G through swift-crypto, which is faster than the ladder and constant-time.
    static func generatorMultiple(_ scalar: P256Scalar) throws -> P256Point {
        try P256Point(sec1: P256.KeyAgreement.PrivateKey(rawRepresentation: scalar.bytes).publicKey.x963Representation)
    }

    /// The prefix of the context hash (Core §3.10.3).
    public static let contextPrefix = Array("CHIP PAKE V1 Commissioning".utf8)

    public struct Verifier: Sendable, Equatable {
        public var w0: [UInt8]
        /// L = w1·P, uncompressed.
        public var l: [UInt8]

        public init(w0: [UInt8], l: [UInt8]) {
            self.w0 = w0
            self.l = l
        }

        /// The verifier as a commissionee stores it and as Open Commissioning Window sends it: w0 || L (97 bytes).
        public var serialized: [UInt8] { w0 + l }

        public init(serialized: [UInt8]) throws {
            guard serialized.count == 97 else { throw P256Error.invalidPointEncoding }
            _ = try P256Point(sec1: serialized[32...])
            self.init(w0: Array(serialized[..<32]), l: Array(serialized[32...]))
        }
    }

    /// (w0, w1) from the passcode (Core §3.10, Crypto_PAKEValues_Initiator).
    public static func proverValues(passcode: UInt32, salt: [UInt8], iterations: Int) throws -> (w0: [UInt8], w1: [UInt8]) {
        var input: [UInt8] = []
        input.appendLittleEndian(passcode)
        let ws = try PBKDF2.sha256(password: input, salt: salt, iterations: iterations, length: 80)
        return (P256Scalar(reducing: ws[0..<40]).bytes, P256Scalar(reducing: ws[40..<80]).bytes)
    }

    /// (w0, L) from the passcode (Crypto_PAKEValues_Responder).
    public static func verifier(passcode: UInt32, salt: [UInt8], iterations: Int) throws -> Verifier {
        let (w0, w1) = try proverValues(passcode: passcode, salt: salt, iterations: iterations)
        return Verifier(w0: w0, l: try generatorMultiple(try P256Scalar(bytes: w1)).sec1Uncompressed())
    }

    /// The keys both sides derive from the transcript.
    public struct Keys: Sendable, Equatable {
        /// cA = HMAC(KcA, pB): the prover's confirmation.
        public var confirmationA: [UInt8]
        /// cB = HMAC(KcB, pA): the verifier's confirmation.
        public var confirmationB: [UInt8]
        /// The shared secret Ke.
        public var sharedSecret: [UInt8]
    }

    /// A random scalar in [1, n).
    static func randomScalar() -> [UInt8] {
        Array(P256.KeyAgreement.PrivateKey().rawRepresentation)
    }

    /// The prover's side (the commissioner).
    public struct Prover: Sendable {
        let context: [UInt8]
        let w0: P256Scalar
        let w1: P256Scalar
        let x: P256Scalar
        /// pA, sent in Pake1.
        public let share: [UInt8]

        public init(context: [UInt8], w0: [UInt8], w1: [UInt8], random: [UInt8]? = nil) throws {
            self.context = context
            self.w0 = try P256Scalar(bytes: w0)
            self.w1 = try P256Scalar(bytes: w1)
            x = try P256Scalar(bytes: random ?? SPAKE2Plus.randomScalar())
            share = try (SPAKE2Plus.generatorMultiple(x) + self.w0.value * SPAKE2Plus.m).sec1Uncompressed()
        }

        /// The keys from the verifier's share pB.
        public func keys(verifierShare: [UInt8]) throws -> Keys {
            let y = try P256Point(sec1: verifierShare)
            let base = y - w0.value * SPAKE2Plus.n
            let z = try (x.value * base).sec1Uncompressed()
            let v = try (w1.value * base).sec1Uncompressed()
            return SPAKE2Plus.keys(context: context, pA: share, pB: verifierShare, z: z, v: v, w0: w0.bytes)
        }
    }

    /// The verifier's side (the commissionee).
    public struct VerifierSession: Sendable {
        let context: [UInt8]
        let w0: P256Scalar
        let l: P256Point
        let y: P256Scalar
        /// pB, sent in Pake2.
        public let share: [UInt8]

        public init(context: [UInt8], verifier: Verifier, random: [UInt8]? = nil) throws {
            self.context = context
            w0 = try P256Scalar(bytes: verifier.w0)
            l = try P256Point(sec1: verifier.l)
            y = try P256Scalar(bytes: random ?? SPAKE2Plus.randomScalar())
            share = try (SPAKE2Plus.generatorMultiple(y) + w0.value * SPAKE2Plus.n).sec1Uncompressed()
        }

        /// The keys from the prover's share pA.
        public func keys(proverShare: [UInt8]) throws -> Keys {
            let x = try P256Point(sec1: proverShare)
            let z = try (y.value * (x - w0.value * SPAKE2Plus.m)).sec1Uncompressed()
            let v = try (y.value * l).sec1Uncompressed()
            return SPAKE2Plus.keys(context: context, pA: proverShare, pB: share, z: z, v: v, w0: w0.bytes)
        }
    }

    static func keys(context: [UInt8], pA: [UInt8], pB: [UInt8], z: [UInt8], v: [UInt8], w0: [UInt8]) -> Keys {
        var transcript: [UInt8] = []
        for part in [context, [], [], mEncoded, nEncoded, pA, pB, z, v, w0] {
            transcript.appendLittleEndian(UInt64(part.count))
            transcript.append(contentsOf: part)
        }
        let hash = Array(SHA256.hash(data: transcript))
        let ka = Array(hash[0..<16])
        let confirmation = MatterCrypto.kdf(key: ka, salt: [], info: Array("ConfirmationKeys".utf8), length: 32)
        return Keys(
            confirmationA: MatterCrypto.hmac(key: Array(confirmation[0..<16]), message: pB),
            confirmationB: MatterCrypto.hmac(key: Array(confirmation[16..<32]), message: pA),
            sharedSecret: Array(hash[16..<32])
        )
    }
}
