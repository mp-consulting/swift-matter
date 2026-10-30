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
        guard count > 0 else { return [] }
        return SymmetricKey(size: SymmetricKeySize(bitCount: count * 8)).withUnsafeBytes { Array($0) }
    }

    /// PrivacyKey: the KDF of an encryption key with "PrivacyKey" (Core §4.9.1).
    public static func privacyKey(encryptionKey: [UInt8]) -> [UInt8] {
        kdf(key: encryptionKey, salt: [], info: Array("PrivacyKey".utf8), length: 16)
    }

    /// Constant-time comparison of secrets.
    public static func equal(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        return zip(a, b).reduce(0) { $0 | ($1.0 ^ $1.1) } == 0
    }
}

/// PBKDF2 with HMAC-SHA256 (NIST SP 800-132), Matter's Crypto_PBKDF (Core §3.9).
public enum PBKDF2 {
    /// Matter's iteration counts (1,000 to 100,000) are below the checked API's minimum, hence the unchecked rounds.
    public static let iterationRange = 1000...100_000

    /// Throws when the iteration count is outside Matter's range (a commissioner gets it from the peer).
    public static func sha256(password: [UInt8], salt: [UInt8], iterations: Int, length: Int) throws -> [UInt8] {
        guard iterationRange.contains(iterations) else { throw PBKDF2Error.invalidIterations }
        return try KDF.Insecure.PBKDF2.deriveKey(from: password, salt: salt, using: .sha256, outputByteCount: length,
                                                 unsafeUncheckedRounds: iterations).withUnsafeBytes { Array($0) }
    }

    /// Without Matter's iteration range, for test vectors.
    static func sha256Unchecked(password: [UInt8], salt: [UInt8], iterations: Int, length: Int) throws -> [UInt8] {
        try KDF.Insecure.PBKDF2.deriveKey(from: password, salt: salt, using: .sha256, outputByteCount: length,
                                          unsafeUncheckedRounds: iterations).withUnsafeBytes { Array($0) }
    }
}

public enum PBKDF2Error: Error, Equatable, Sendable {
    case invalidIterations
}

public enum AESCCMError: Error, Equatable, Sendable {
    case invalidKey
    case invalidTagLength
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
        guard (4...16).contains(tagLength), tagLength % 2 == 0 else { throw AESCCMError.invalidTagLength }
        self.key = SymmetricKey(data: key)
        self.tagLength = tagLength
    }

    /// The ciphertext followed by the MIC.
    public func seal(_ plaintext: [UInt8], nonce: [UInt8], additionalData: [UInt8] = []) throws -> [UInt8] {
        try checkInput(nonce: nonce, length: plaintext.count, additionalData: additionalData)
        let tag = mac(plaintext, nonce: nonce, additionalData: additionalData)
        return ctr(plaintext, nonce: nonce, startingAt: 1) + ctr(tag, nonce: nonce, startingAt: 0)
    }

    /// The plaintext of a ciphertext followed by its MIC.
    public func open(_ sealed: [UInt8], nonce: [UInt8], additionalData: [UInt8] = []) throws -> [UInt8] {
        guard sealed.count >= tagLength else { throw AESCCMError.authenticationFailed }
        let ciphertext = Array(sealed.dropLast(tagLength))
        try checkInput(nonce: nonce, length: ciphertext.count, additionalData: additionalData)
        let plaintext = ctr(ciphertext, nonce: nonce, startingAt: 1)
        let tag = ctr(Array(sealed.suffix(tagLength)), nonce: nonce, startingAt: 0)
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
        // CBC-MAC: the last block of AES-CBC with a zero IV.
        let chained = try! AES._CBC.encrypt(input, using: key, iv: AES._CBC.IV(ivBytes: [UInt8](repeating: 0, count: 16)), noPadding: true)
        return Array(chained.suffix(16).prefix(tagLength))
    }

    /// CTR mode from counter block A_i (flags with L - 1, the nonce, i); messages are short enough that the 16-bit
    /// counter never carries into the nonce.
    /// Crypto_Privacy_Encrypt and _Decrypt (Core §3.7): AES-CTR with NIST 800-38C's counters for q = 2, which are
    /// CCM's own from counter 1 (connectedhomeip computes it as CCM without its tag).
    func privacy(_ input: [UInt8], nonce: [UInt8]) -> [UInt8] {
        ctr(input, nonce: nonce, startingAt: 1)
    }

    private func ctr(_ input: [UInt8], nonce: [UInt8], startingAt counter: UInt16) -> [UInt8] {
        guard !input.isEmpty else { return [] }
        var block: [UInt8] = [0x01] + nonce
        block.appendBigEndian(counter)
        return Array(try! AES._CTR.encrypt(input, using: key, nonce: AES._CTR.Nonce(nonceBytes: block)))
    }
}
