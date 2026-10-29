import Crypto
import _CryptoExtras

/// Matter's cryptographic primitives (Core §3) over swift-crypto.
public enum MatterCrypto {
    /// Crypto_KDF: HKDF-SHA256 (Core §3.8).
    public static func kdf(key: [UInt8], salt: [UInt8], info: [UInt8], length: Int) -> [UInt8] {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: key), salt: salt, info: info, outputByteCount: length)
            .withUnsafeBytes { Array($0) }
    }

    /// Crypto_HMAC: HMAC-SHA256 (Core §3.4).
    public static func hmac(key: [UInt8], message: [UInt8]) -> [UInt8] {
        Array(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
    }

    /// Crypto_Hash: SHA-256 (Core §3.3).
    public static func hash(_ message: [UInt8]) -> [UInt8] {
        Array(SHA256.hash(data: message))
    }

    public static func random(_ count: Int) -> [UInt8] {
        var generator = SystemRandomNumberGenerator()
        return (0..<count).map { _ in UInt8.random(in: 0...255, using: &generator) }
    }

    /// Constant-time comparison of secrets.
    public static func equal(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        return zip(a, b).reduce(0) { $0 | ($1.0 ^ $1.1) } == 0
    }

    /// One AES-128 block encryption.
    static func aesBlock(_ block: inout [UInt8], key: SymmetricKey) {
        try! AES.permute(&block, key: key)
    }
}

/// PBKDF2 with HMAC-SHA256 (NIST SP 800-132), Matter's Crypto_PBKDF (Core §3.9).
public enum PBKDF2 {
    public static func sha256(password: [UInt8], salt: [UInt8], iterations: Int, length: Int) -> [UInt8] {
        let key = SymmetricKey(data: password)
        var output: [UInt8] = []
        var blockIndex: UInt32 = 1
        while output.count < length {
            var u = Array(HMAC<SHA256>.authenticationCode(for: salt + withUnsafeBytes(of: blockIndex.bigEndian, Array.init), using: key))
            var block = u
            if iterations > 1 {
                for _ in 1..<iterations {
                    u = Array(HMAC<SHA256>.authenticationCode(for: u, using: key))
                    for index in block.indices { block[index] ^= u[index] }
                }
            }
            output += block
            blockIndex += 1
        }
        return Array(output.prefix(length))
    }
}

public enum AESCCMError: Error, Equatable, Sendable {
    case invalidKey
    case invalidNonce
    case tooLong
    case authenticationFailed
}

/// AES-128-CCM (RFC 3610) with a 13-byte nonce; Matter uses a 16-byte MIC (Core §3.6).
public struct AESCCM: Sendable {
    public static let nonceLength = 13
    public static let micLength = 16

    private let key: SymmetricKey
    private let tagLength: Int

    public init(key: [UInt8], tagLength: Int = AESCCM.micLength) throws {
        guard key.count == 16 else { throw AESCCMError.invalidKey }
        self.key = SymmetricKey(data: key)
        self.tagLength = tagLength
    }

    /// The ciphertext followed by the MIC.
    public func seal(_ plaintext: [UInt8], nonce: [UInt8], additionalData: [UInt8] = []) throws -> [UInt8] {
        try checkInput(nonce: nonce, length: plaintext.count, additionalData: additionalData)
        let tag = mac(plaintext, nonce: nonce, additionalData: additionalData)
        var output = ctr(plaintext, nonce: nonce, startingAt: 1)
        output += zip(tag, ctr(Array(repeating: 0, count: tagLength), nonce: nonce, startingAt: 0)).map { $0 ^ $1 }
        return output
    }

    /// The plaintext of a ciphertext followed by its MIC.
    public func open(_ sealed: [UInt8], nonce: [UInt8], additionalData: [UInt8] = []) throws -> [UInt8] {
        guard sealed.count >= tagLength else { throw AESCCMError.authenticationFailed }
        let ciphertext = Array(sealed.dropLast(tagLength))
        try checkInput(nonce: nonce, length: ciphertext.count, additionalData: additionalData)
        let plaintext = ctr(ciphertext, nonce: nonce, startingAt: 1)
        let tag = zip(sealed.suffix(tagLength), ctr(Array(repeating: 0, count: tagLength), nonce: nonce, startingAt: 0)).map { $0 ^ $1 }
        guard MatterCrypto.equal(tag, mac(plaintext, nonce: nonce, additionalData: additionalData)) else {
            throw AESCCMError.authenticationFailed
        }
        return plaintext
    }

    private func checkInput(nonce: [UInt8], length: Int, additionalData: [UInt8]) throws {
        guard nonce.count == Self.nonceLength else { throw AESCCMError.invalidNonce }
        // L = 2: messages up to 2^16 - 1 bytes; additional data uses the two-byte length form only.
        guard length <= 0xFFFF, additionalData.count < 0xFF00 else { throw AESCCMError.tooLong }
    }

    private func mac(_ plaintext: [UInt8], nonce: [UInt8], additionalData: [UInt8]) -> [UInt8] {
        let flags = UInt8(additionalData.isEmpty ? 0 : 0x40) | UInt8((tagLength - 2) / 2) << 3 | 0x01
        var input: [UInt8] = [flags] + nonce
        input.appendBigEndian(UInt16(plaintext.count))
        if !additionalData.isEmpty {
            input.appendBigEndian(UInt16(additionalData.count))
            input += additionalData
            input += Array(repeating: 0, count: (16 - input.count % 16) % 16)
        }
        input += plaintext
        input += Array(repeating: 0, count: (16 - input.count % 16) % 16)

        var state = [UInt8](repeating: 0, count: 16)
        for start in stride(from: 0, to: input.count, by: 16) {
            for index in 0..<16 { state[index] ^= input[start + index] }
            MatterCrypto.aesBlock(&state, key: key)
        }
        return Array(state.prefix(tagLength))
    }

    private func ctr(_ input: [UInt8], nonce: [UInt8], startingAt counter: UInt16) -> [UInt8] {
        var output = input
        var counter = counter
        for start in stride(from: 0, to: input.count, by: 16) {
            var block: [UInt8] = [0x01] + nonce
            block.appendBigEndian(counter)
            MatterCrypto.aesBlock(&block, key: key)
            for index in start..<min(start + 16, input.count) { output[index] ^= block[index - start] }
            counter &+= 1
        }
        return output
    }
}
