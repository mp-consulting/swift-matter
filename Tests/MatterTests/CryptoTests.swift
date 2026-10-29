import Crypto
import Foundation
import Testing
@testable import Matter

struct P256Tests {
    @Test func scalarMultiplesOfTheGeneratorMatchSwiftCrypto() throws {
        for _ in 0..<8 {
            let key = P256.Signing.PrivateKey()
            let scalar = U256(bigEndian: key.rawRepresentation)!
            #expect(try (scalar * P256Point.generator).sec1Uncompressed() == Array(key.publicKey.x963Representation))
        }
    }

    @Test func scalarMultiplesOfOtherPointsMatchECDH() throws {
        // ECDH's shared secret is the x coordinate of a·(b·G).
        let a = P256.KeyAgreement.PrivateKey(), b = P256.KeyAgreement.PrivateKey()
        let point = try P256Point(sec1: b.publicKey.x963Representation)
        let product = try (U256(bigEndian: a.rawRepresentation)! * point).sec1Uncompressed()
        let shared = try a.sharedSecretFromKeyAgreement(with: b.publicKey).withUnsafeBytes { Array($0) }
        #expect(Array(product[1..<33]) == shared)
    }

    @Test func additionIsConsistentWithMultiplication() throws {
        let g = P256Point.generator
        let three = U256(3, 0, 0, 0)
        #expect(g + g + g == three * g)
        #expect(g + g == g * 2)
        #expect((g - g).isIdentity)
        #expect(g + .identity == g)
        let n = P256Point.order.modulus
        #expect((n * g).isIdentity)
    }

    @Test func compressedPointsDecompress() throws {
        let key = P256.Signing.PrivateKey().publicKey
        let point = try P256Point(sec1: key.compressedRepresentation)
        #expect(try point.sec1Uncompressed() == Array(key.x963Representation))
    }

    @Test func rejectsPointsOffTheCurve() {
        var bytes = Array(P256.Signing.PrivateKey().publicKey.x963Representation)
        bytes[64] ^= 1
        #expect(throws: P256Error.pointNotOnCurve) { try P256Point(sec1: bytes) }
        #expect(throws: P256Error.invalidPointEncoding) { try P256Point(sec1: [0x04] + [UInt8](repeating: 0xFF, count: 64)) }
    }

    @Test func reducesWideScalars() {
        // n + 5 reduces to 5.
        let n = P256Point.order.modulus.bigEndianBytes
        var bytes = [UInt8](repeating: 0, count: 8) + n
        bytes[39] &+= 5
        #expect(P256Scalar(reducing: bytes).value == U256(5, 0, 0, 0))
    }
}

extension P256Point {
    static func * (point: P256Point, scalar: UInt64) -> P256Point { U256(scalar, 0, 0, 0) * point }
}

extension P256Point: Equatable {}

struct SPAKE2PlusTests {
    /// draft-bar-cfrg-spake2plus-01's vectors, as matter.js tests them.
    let context = Array("SPAKE2+-P256-SHA256-HKDF draft-01".utf8)
    let w0 = hex("e6887cf9bdfb7579c69bf47928a84514b5e355ac034863f7ffaf4390e67d798c")
    let w1 = hex("24b5ae4abda868ec9336ffc3b78ee31c5755bef1759227ef5372ca139b94e512")
    let l = hex("0495645cfb74df6e58f9748bb83a86620bab7c82e107f57d6870da8cbcb2ff9f7063a14b6402c62f99afcb9706a4d1a143273259fe76f1c605a3639745a92154b9")
    let x = hex("5b478619804f4938d361fbba3a20648725222f0a54cc4c876139efe7d9a21786")
    let y = hex("766770dad8c8eecba936823c0aed044b8c3c4f7655e8beec44a15dcbcaf78e5e")

    @Test func matchesTheDraftVectors() throws {
        let prover = try SPAKE2Plus.Prover(context: context, w0: w0, w1: w1, random: x)
        let verifier = try SPAKE2Plus.VerifierSession(context: context, verifier: .init(w0: w0, l: l), random: y)
        #expect(prover.share == hex("04a6db23d001723fb01fcfc9d08746c3c2a0a3feff8635d29cad2853e7358623425cf39712e928054561ba71e2dc11f300f1760e71eb177021a8f85e78689071cd"))
        #expect(verifier.share == hex("04390d29bf185c3abf99f150ae7c13388c82b6be0c07b1b8d90d26853e84374bbdc82becdb978ca3792f472424106a2578012752c11938fcf60a41df75ff7cf947"))

        let expected = SPAKE2Plus.Keys(
            confirmationA: hex("71d9412779b6c45a2c615c9df3f1fd93dc0aaf63104da8ece4aa1b5a3a415fea"),
            confirmationB: hex("095dc0400355cc233fde7437811815b3c1524aae80fd4e6810cf531cf11d20e3"),
            sharedSecret: hex("ea3276d68334576097e04b19ee5a3a8b")
        )
        #expect(try prover.keys(verifierShare: verifier.share) == expected)
        #expect(try verifier.keys(proverShare: prover.share) == expected)
    }

    @Test func passcodeDerivedValuesAgree() throws {
        let salt = Array("SPAKE2P Key Salt".utf8)
        let (w0, w1) = SPAKE2Plus.proverValues(passcode: 20202021, salt: salt, iterations: 1000)
        let verifier = SPAKE2Plus.verifier(passcode: 20202021, salt: salt, iterations: 1000)
        #expect(verifier.w0 == w0)
        let prover = try SPAKE2Plus.Prover(context: context, w0: w0, w1: w1)
        let session = try SPAKE2Plus.VerifierSession(context: context, verifier: verifier)
        #expect(try prover.keys(verifierShare: session.share) == session.keys(proverShare: prover.share))

        let wrong = SPAKE2Plus.proverValues(passcode: 20202022, salt: salt, iterations: 1000)
        let impostor = try SPAKE2Plus.Prover(context: context, w0: wrong.w0, w1: wrong.w1)
        #expect(try impostor.keys(verifierShare: session.share).confirmationA != session.keys(proverShare: impostor.share).confirmationA)
    }

    @Test func hashesTheContextLikeConnectedhomeip() {
        // matter.js's capture from connectedhomeip.
        let request = hex("15300120b2901e92036f7bca007a3a1bf24bd71f18772105e83479c92b7a8af35e8182742502498d240300280435052501881325022c011818")
        let response = hex("15300120b2901e92036f7bca007a3a1bf24bd71f18772105e83479c92b7a8af35e81827430022008070f685f2077779b824adf91e4bab6253b9d1a3c0f6615c6d447780f0feef325039c8d35042501e803300220163f8501fbbc0e6a8f69a9b999d038ca388ecffccc18fe259c4253f26e494dda1835052501881325022c011818")
        #expect(MatterCrypto.hash(SPAKE2Plus.contextPrefix + request + response) == hex("c49718b0275b6f81fd6a081f6c34c5833382b75b3bd997895d13a51c71a02855"))
    }
}

struct AESCCMTests {
    /// RFC 3610, packet vector #1 (8-byte MIC).
    @Test func matchesRFC3610() throws {
        let ccm = try AESCCM(key: hex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"), tagLength: 8)
        let nonce = hex("00000003020100a0a1a2a3a4a5")
        let header = hex("0001020304050607")
        let payload = hex("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e")
        let sealed = try ccm.seal(payload, nonce: nonce, additionalData: header)
        #expect(sealed == hex("588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0"))
        #expect(try ccm.open(sealed, nonce: nonce, additionalData: header) == payload)
    }

    @Test func rejectsTampering() throws {
        let ccm = try AESCCM(key: MatterCrypto.random(16))
        let nonce = MatterCrypto.random(13)
        var sealed = try ccm.seal(Array("hello".utf8), nonce: nonce, additionalData: [1, 2, 3])
        #expect(sealed.count == 5 + 16)
        #expect(throws: AESCCMError.authenticationFailed) { try ccm.open(sealed, nonce: nonce, additionalData: [1, 2, 4]) }
        sealed[0] ^= 1
        #expect(throws: AESCCMError.authenticationFailed) { try ccm.open(sealed, nonce: nonce, additionalData: [1, 2, 3]) }
    }

    @Test func handlesEmptyAndLongInputs() throws {
        let ccm = try AESCCM(key: MatterCrypto.random(16))
        let nonce = MatterCrypto.random(13)
        for length in [0, 1, 15, 16, 17, 1200] {
            let plaintext = MatterCrypto.random(length)
            #expect(try ccm.open(ccm.seal(plaintext, nonce: nonce), nonce: nonce) == plaintext)
        }
    }
}

struct PBKDF2Tests {
    /// RFC 7914, section 11.
    @Test func matchesRFC7914() {
        #expect(PBKDF2.sha256(password: Array("passwd".utf8), salt: Array("salt".utf8), iterations: 1, length: 64) == hex(
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"))
    }
}
