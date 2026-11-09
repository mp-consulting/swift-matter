import Crypto
import Foundation

/// What a commissioner trusts to attest devices (Core §6.2.3.1): Product Attestation Authority certificates, at the
/// root of every Device Attestation Certificate chain, and the keys Certification Declarations are signed with.
public struct AttestationTrustStore: Sendable {
    /// PAA certificates, DER.
    public var paaCertificates: [[UInt8]]
    /// Certification Declaration signing certificates, DER, found by the declaration's signer key identifier.
    public var declarationSigners: [[UInt8]]
    /// Whether a declaration signed with the test key (`TestCredentials.cdSigningCertificate`) is taken, and then only for
    /// certification type 0, development and test, as connectedhomeip does.
    public var allowsTestDeclarations: Bool

    public init(paaCertificates: [[UInt8]], declarationSigners: [[UInt8]], allowsTestDeclarations: Bool = false) {
        self.paaCertificates = paaCertificates
        self.declarationSigners = declarationSigners
        self.allowsTestDeclarations = allowsTestDeclarations
    }

    /// The PAAs the Distributed Compliance Ledger approved (`Scripts/update-trust-store.py`) and the CSA's declaration
    /// signing keys: what production devices are attested with.
    public static let registry = AttestationTrustStore(
        paaCertificates: registryPAAs.compactMap(decode), declarationSigners: csaDeclarationSigners.compactMap(decode))

    /// connectedhomeip's test PAA and test declaration key: development devices, swift-matter's own node.
    public static let test = AttestationTrustStore(
        paaCertificates: [TestCredentials.paaCertificate], declarationSigners: [TestCredentials.cdSigningCertificate],
        allowsTestDeclarations: true)

    /// Both stores' roots and keys.
    public func adding(_ other: AttestationTrustStore) -> AttestationTrustStore {
        AttestationTrustStore(paaCertificates: paaCertificates + other.paaCertificates,
                              declarationSigners: declarationSigners + other.declarationSigners,
                              allowsTestDeclarations: allowsTestDeclarations || other.allowsTestDeclarations)
    }

    private static func decode(_ base64: String) -> [UInt8]? { Data(base64Encoded: base64).map(Array.init) }
}

/// Why a device's attestation was refused, in the order Core §6.2.3.1 checks it.
public enum AttestationFailure: Error, Equatable, Sendable, CustomStringConvertible {
    case malformedCertificate(String)
    case vendorMismatch
    case productMismatch
    /// No trusted PAA issued its PAI: not a certified device, or a PAA newer than this trust store.
    case untrustedRoot
    case invalidChain
    case attestationSignature
    case nonceMismatch
    case malformedElements
    case unknownDeclarationSigner
    case declarationSignature
    case malformedDeclaration
    /// The declaration does not cover the device's vendor or product (Basic Information's, or its certificates').
    case declarationVendor
    case declarationProduct
    case declarationPAA
    /// CSRResponse's signature with the DAC's key, and its nonce (Core §11.18.6.6).
    case csrSignature
    case csrNonce

    /// The device proved it holds its certificate's key, but its certification did not check out (a root or declaration
    /// key this commissioner does not have, a declaration that does not cover it): a commissioner MAY go on with the
    /// person's consent (Core §5.5, step 10). A wrong signature, nonce or chain never is: the device is not who it says.
    public var isCertificationFailure: Bool {
        switch self {
        case .untrustedRoot, .unknownDeclarationSigner, .malformedDeclaration, .declarationVendor, .declarationProduct, .declarationPAA:
            true
        default: false
        }
    }

    public var description: String {
        switch self {
        case .malformedCertificate(let which): "malformed \(which) certificate"
        case .vendorMismatch: "vendor ids of the certificates differ"
        case .productMismatch: "product ids of the certificates differ"
        case .untrustedRoot: "no trusted PAA issued its certificates"
        case .invalidChain: "certificate chain"
        case .attestationSignature: "attestation signature"
        case .nonceMismatch: "nonce"
        case .malformedElements: "attestation elements"
        case .unknownDeclarationSigner: "certification declaration signed by an unknown key"
        case .declarationSignature: "certification declaration signature"
        case .malformedDeclaration: "certification declaration"
        case .declarationVendor: "declaration does not cover the device's vendor"
        case .declarationProduct: "declaration does not cover the device's product"
        case .declarationPAA: "declaration does not authorize the device's PAA"
        case .csrSignature: "CSR signature"
        case .csrNonce: "CSR nonce"
        }
    }
}

/// A device's answers to AttestationRequest and CertificateChainRequest, with what the commissioner sent and read.
public struct AttestationInformation: Sendable {
    public var dac: [UInt8]
    public var pai: [UInt8]
    /// attestation_elements and attestation_signature (Core §11.18.4.7).
    public var elements: [UInt8]
    public var signature: [UInt8]
    /// The session's AttestationChallenge and the commissioner's AttestationNonce.
    public var challenge: [UInt8]
    public var nonce: [UInt8]
    /// Basic Information's VendorID and ProductID.
    public var vendorID: UInt16
    public var productID: UInt16

    public init(dac: [UInt8], pai: [UInt8], elements: [UInt8], signature: [UInt8], challenge: [UInt8], nonce: [UInt8],
                vendorID: UInt16, productID: UInt16) {
        self.dac = dac
        self.pai = pai
        self.elements = elements
        self.signature = signature
        self.challenge = challenge
        self.nonce = nonce
        self.vendorID = vendorID
        self.productID = productID
    }
}

/// Device attestation as a commissioner validates it (Core §6.2.3.1), as connectedhomeip's DefaultDACVerifier does.
/// Revocation (§6.2.4) is not checked: it needs the ledger's revocation distribution points at commissioning time.
public enum AttestationVerifier {
    /// The vendor and product ids the device's DAC carries, after every check of §6.2.3.1 passed.
    @discardableResult
    public static func verify(_ info: AttestationInformation, trusting store: AttestationTrustStore) throws(AttestationFailure)
        -> (vendorID: UInt16, productID: UInt16) {
        let dac = try parse(info.dac, "DAC"), pai = try parse(info.pai, "PAI")
        // The certificates' profiles (§6.2.2.3, §6.2.2.4): a DAC is no CA, a PAI a CA that issues only DACs.
        guard dac.isCA == false, dac.authorityKeyID != nil else { throw .malformedCertificate("DAC") }
        guard pai.isCA == true, pai.pathLength == 0, pai.authorityKeyID != nil, pai.subjectKeyID != nil else {
            throw .malformedCertificate("PAI")
        }
        guard let dacVendor = dac.vendorID, let dacProduct = dac.productID else { throw .malformedCertificate("DAC") }
        guard let paiVendor = pai.vendorID, paiVendor == dacVendor else { throw .vendorMismatch }
        if let paiProduct = pai.productID, paiProduct != dacProduct { throw .productMismatch }

        // The device's own signatures first: a reply signed for another session or nonce goes no further.
        try verifySignatures(info)

        // The PAA: the trusted root whose key identifier the PAI names, and that signed it.
        let paa = store.paaCertificates.lazy.compactMap { try? X509.parse($0) }.first {
            $0.subjectKeyID == pai.authorityKeyID && $0.isCA == true && $0.publicKey.isValidSignature(pai.signature, for: pai.tbs)
        }
        guard let paa, let paaKeyID = paa.subjectKeyID else { throw .untrustedRoot }
        if let paaVendor = paa.vendorID, paaVendor != paiVendor { throw .vendorMismatch }
        guard paa.productID == nil else { throw .malformedCertificate("PAA") }
        // DAC ← PAI ← PAA, each valid when the DAC was issued.
        guard pai.publicKey.isValidSignature(dac.signature, for: dac.tbs), dac.authorityKeyID == pai.subjectKeyID,
              [paa, pai, dac].allSatisfy({ $0.isValid(at: dac.notBefore) })
        else { throw .invalidChain }

        guard let cms = try? TLVStruct(decoding: info.elements).bytes(1) else { throw .malformedElements }

        // The Certification Declaration (§6.3.1): signed by a known key, covering this device.
        guard let signerID = try? CertificationDeclaration.signerKeyID(cms) else { throw .malformedDeclaration }
        let isTestKey = signerID == TestCredentials.cdSigningKeyIdentifier
        guard let signer = store.declarationSigners.lazy.compactMap({ try? X509.parse($0) }).first(where: { $0.subjectKeyID == signerID }),
              !isTestKey || store.allowsTestDeclarations
        else { throw .unknownDeclarationSigner }
        let content: [UInt8]
        do { content = try CertificationDeclaration.verify(cms, key: signer.publicKey) } catch { throw .declarationSignature }
        guard let declaration = try? TLVStruct(decoding: content), (try? declaration.uint(0)) == 1,
              let vendor = try? declaration.uint(1), let type = try? declaration.uint(8), type < 3,
              let products = try? declaration.elements(2)
        else { throw .malformedDeclaration }
        // The test key signs development declarations only.
        if isTestKey, type != 0 { throw .unknownDeclarationSigner }
        func covers(_ product: UInt16) -> Bool { products.contains { $0.value.uint == UInt64(product) } }
        guard vendor == UInt64(info.vendorID) else { throw .declarationVendor }
        guard covers(info.productID) else { throw .declarationProduct }
        switch (declaration[9]?.uint, declaration[10]?.uint) {
        case (let originVendor?, let originProduct?):
            guard originVendor == UInt64(dacVendor), originVendor == UInt64(paiVendor) else { throw .declarationVendor }
            guard originProduct == UInt64(dacProduct), pai.productID.map({ UInt64($0) == originProduct }) ?? true else {
                throw .declarationProduct
            }
        case (nil, nil):
            guard vendor == UInt64(dacVendor), vendor == UInt64(paiVendor) else { throw .declarationVendor }
            guard covers(dacProduct), pai.productID.map(covers) ?? true else { throw .declarationProduct }
        default:
            throw .malformedDeclaration
        }
        if let authorized = declaration[11] {
            guard let list = authorized.elements, list.contains(where: { $0.value.bytes == paaKeyID }) else { throw .declarationPAA }
        }
        return (dacVendor, dacProduct)
    }

    /// Only the device's own signatures: the attestation signature with its DAC's key, and the nonce. What a commissioner
    /// can check of a device whose PAA it does not have.
    public static func verifySignatures(_ info: AttestationInformation) throws(AttestationFailure) {
        let dac = try parse(info.dac, "DAC")
        guard verifySignature(info.signature, of: info.elements + info.challenge, key: dac.publicKey) else {
            throw .attestationSignature
        }
        guard let nonce = try? TLVStruct(decoding: info.elements).bytes(2) else { throw .malformedElements }
        guard MatterCrypto.equal(nonce, info.nonce) else { throw .nonceMismatch }
    }

    private static func parse(_ der: [UInt8], _ which: String) throws(AttestationFailure) -> X509.Parsed {
        do { return try X509.parse(der) } catch { throw .malformedCertificate(which) }
    }

    /// attestation_signature is a raw r‖s signature (Core §3.5.3).
    private static func verifySignature(_ signature: [UInt8], of message: [UInt8], key: P256.Signing.PublicKey) -> Bool {
        guard let parsed = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else { return false }
        return key.isValidSignature(parsed, for: message)
    }
}
