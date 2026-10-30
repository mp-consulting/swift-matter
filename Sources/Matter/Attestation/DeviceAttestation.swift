import Crypto
import Foundation

/// Device attestation (Core §6.2): the Device Attestation Certificate and its key, the Product Attestation Intermediate
/// that signed it, and the Certification Declaration, which a commissioner checks before commissioning.
public struct DeviceAttestation: Sendable {
    public var dacCertificate: [UInt8]
    public var paiCertificate: [UInt8]
    public var certificationDeclaration: [UInt8]
    /// The DAC's private key, raw.
    public var dacPrivateKey: [UInt8]

    public init(dacCertificate: [UInt8], paiCertificate: [UInt8], certificationDeclaration: [UInt8], dacPrivateKey: [UInt8]) {
        self.dacCertificate = dacCertificate
        self.paiCertificate = paiCertificate
        self.certificationDeclaration = certificationDeclaration
        self.dacPrivateKey = dacPrivateKey
    }

    var dacKey: P256.Signing.PrivateKey { get throws { try P256.Signing.PrivateKey(rawRepresentation: dacPrivateKey) } }

    /// Signs `message || attestationChallenge` with the DAC key (Core §11.18.4.7, §11.18.4.9).
    func sign(_ message: [UInt8], challenge: [UInt8]) throws -> [UInt8] {
        Array(try dacKey.signature(for: message + challenge).rawRepresentation)
    }

    /// A PAI and a DAC issued under connectedhomeip's test PAA, and a test Certification Declaration: what an
    /// uncertified product uses. Commissioners show it as uncertified, and some accept it only in developer mode.
    public static func test(vendorID: UInt16 = 0xFFF1, productID: UInt16 = 0x8000, deviceType: UInt32 = 0x000E) throws -> DeviceAttestation {
        let paaKey = try P256.Signing.PrivateKey(rawRepresentation: TestCredentials.paaPrivateKey)
        let paaKeyID = MatterCertificate.keyIdentifier(Array(paaKey.publicKey.x963Representation))
        let paaName = X509.name(commonName: "Matter Test PAA", vendorID: 0xFFF1)

        let paiKey = P256.Signing.PrivateKey()
        let paiName = X509.name(commonName: "Matter Test PAI", vendorID: vendorID)
        let pai = try X509.certificate(subject: paiName, issuer: paaName, publicKey: paiKey.publicKey, issuerKey: paaKey,
                                       authorityKeyID: paaKeyID, isCA: true, pathLength: 0)

        let dacKey = P256.Signing.PrivateKey()
        let dac = try X509.certificate(subject: X509.name(commonName: "Matter Test DAC", vendorID: vendorID, productID: productID),
                                       issuer: paiName, publicKey: dacKey.publicKey, issuerKey: paiKey,
                                       authorityKeyID: MatterCertificate.keyIdentifier(Array(paiKey.publicKey.x963Representation)),
                                       isCA: false, pathLength: nil)

        let declaration = try CertificationDeclaration(vendorID: vendorID, productIDs: [productID], deviceType: deviceType,
                                                       certificateID: "ZIG20142ZB330003-24", versionNumber: 0x2694,
                                                       certificationType: 0)
            .signed(with: P256.Signing.PrivateKey(rawRepresentation: TestCredentials.cdSigningPrivateKey),
                    keyIdentifier: TestCredentials.cdSigningKeyIdentifier)
        return DeviceAttestation(dacCertificate: dac, paiCertificate: pai, certificationDeclaration: declaration,
                                 dacPrivateKey: Array(dacKey.rawRepresentation))
    }
}

/// The Certification Declaration (Core §6.3.1): certification elements in TLV, wrapped in CMS SignedData.
public struct CertificationDeclaration: Hashable, Sendable {
    public var vendorID: UInt16
    public var productIDs: [UInt16]
    public var deviceType: UInt32
    public var certificateID: String
    public var securityLevel: UInt8 = 0
    public var securityInformation: UInt16 = 0
    public var versionNumber: UInt16
    /// 0: development and test, 1: provisional, 2: official.
    public var certificationType: UInt8

    public init(vendorID: UInt16, productIDs: [UInt16], deviceType: UInt32, certificateID: String, versionNumber: UInt16,
                certificationType: UInt8) {
        self.vendorID = vendorID
        self.productIDs = productIDs
        self.deviceType = deviceType
        self.certificateID = certificateID
        self.versionNumber = versionNumber
        self.certificationType = certificationType
    }

    /// cd_content: the certification elements TLV.
    public var content: [UInt8] {
        TLVEncoder.encode(.structure([
            .field(0, .unsigned(1)), .field(1, .unsigned(UInt64(vendorID))),
            .field(2, .array(productIDs.map { TLVElement(.unsigned(UInt64($0))) })), .field(3, .unsigned(UInt64(deviceType))),
            .field(4, .utf8(certificateID)), .field(5, .unsigned(UInt64(securityLevel))),
            .field(6, .unsigned(UInt64(securityInformation))), .field(7, .unsigned(UInt64(versionNumber))),
            .field(8, .unsigned(UInt64(certificationType))),
        ]))
    }

    /// The CMS SignedData (ContentInfo) as connectedhomeip encodes it (Core Appendix F.1).
    public func signed(with key: P256.Signing.PrivateKey, keyIdentifier: [UInt8]) throws -> [UInt8] {
        let content = self.content
        let signature = try key.signature(for: content).derRepresentation
        let sha256 = DER.sequence([.objectIdentifier(OID.sha256)])
        let signerInfo = DER.sequence([
            .integer([3]), .contextPrimitive(0, keyIdentifier), sha256, .sequence([.objectIdentifier(OID.ecdsaWithSHA256)]),
            .octetString(Array(signature)),
        ])
        let signedData = DER.sequence([
            .integer([3]), .set([sha256]),
            .sequence([.objectIdentifier(OID.data), .contextConstructed(0, [.octetString(content)])]),
            .set([signerInfo]),
        ])
        return DER.sequence([.objectIdentifier(OID.signedData), .contextConstructed(0, [signedData])]).encoded
    }

    /// The content and signature of a CMS-encoded declaration, after checking its signature with `key`.
    public static func verify(_ cms: [UInt8], key: P256.Signing.PublicKey) throws -> [UInt8] {
        guard let signedData = try DER.parse(cms)[1]?[0],
              case .octetString(let content)? = signedData[2]?[1]?[0],
              case .octetString(let signature)? = signedData[3]?[0]?[4]
        else { throw AttestationError.malformedDeclaration }
        guard key.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: signature), for: content) else {
            throw AttestationError.invalidSignature
        }
        return content
    }
}

public enum AttestationError: Error, Equatable, Sendable {
    case malformedDeclaration
    case malformedCertificate
    case invalidSignature
    case untrustedChain
}

/// X.509 certificates for attestation: DER built from scratch, signed with swift-crypto.
enum X509 {
    /// A name of a common name and Matter's vendor and product id attributes (Core §6.2.2.2), as uppercase hex.
    static func name(commonName: String, vendorID: UInt16? = nil, productID: UInt16? = nil) -> DER {
        var attributes: [DER] = [.set([.sequence([.objectIdentifier(OID.commonName), .utf8String(commonName)])])]
        if let vendorID {
            attributes.append(.set([.sequence([.objectIdentifier(OID.matterVendorID), .utf8String(zeroPadded(vendorID, width: 4, radix: 16))])]))
        }
        if let productID {
            attributes.append(.set([.sequence([.objectIdentifier(OID.matterProductID), .utf8String(zeroPadded(productID, width: 4, radix: 16))])]))
        }
        return .sequence(attributes)
    }

    /// A certificate valid from a day ago with no expiry (99991231235959Z, as Matter's attestation certificates use).
    static func certificate(subject: DER, issuer: DER, publicKey: P256.Signing.PublicKey, issuerKey: P256.Signing.PrivateKey,
                            authorityKeyID: [UInt8], isCA: Bool, pathLength: UInt8?) throws -> [UInt8] {
        let publicKeyBytes = Array(publicKey.x963Representation)
        func extensionDER(_ oid: DER.ObjectIdentifier, critical: Bool, _ value: DER) -> DER {
            .sequence([.objectIdentifier(oid)] + (critical ? [.boolean(true)] : []) + [.octetString(value.encoded)])
        }
        var constraints: [DER] = isCA ? [.boolean(true)] : []
        if let pathLength { constraints.append(.integer([pathLength])) }
        let usage = isCA ? MatterCertificate.namedBits(MatterCertificate.KeyUsage([.keyCertSign, .crlSign]).rawValue)
            : MatterCertificate.namedBits(MatterCertificate.KeyUsage.digitalSignature.rawValue)
        let notBefore = MatterCertificate.time(MatterCertificate.matterSeconds(Date().addingTimeInterval(-86_400)), isNotAfter: false)
        let tbs = DER.sequence([
            .contextConstructed(0, [.integer([2])]),
            .integer(MatterCrypto.random(8).enumerated().map { $0.offset == 0 ? $0.element & 0x7F : $0.element }),
            .sequence([.objectIdentifier(OID.ecdsaWithSHA256)]),
            issuer,
            .sequence([notBefore, .generalizedTime("99991231235959Z")]),
            subject,
            MatterCertificate.subjectPublicKeyInfo(publicKeyBytes),
            .contextConstructed(3, [.sequence([
                extensionDER(OID.basicConstraints, critical: true, .sequence(constraints)),
                extensionDER(OID.keyUsage, critical: true, usage),
                extensionDER(OID.subjectKeyIdentifier, critical: false, .octetString(MatterCertificate.keyIdentifier(publicKeyBytes))),
                extensionDER(OID.authorityKeyIdentifier, critical: false, .sequence([.contextPrimitive(0, authorityKeyID)])),
            ])]),
        ])
        return DER.signed(tbs, signature: Array(try issuerKey.signature(for: tbs.encoded).derRepresentation))
    }

    /// The parts of a certificate attestation checks need.
    struct Parsed {
        var tbs: [UInt8]
        var signature: P256.Signing.ECDSASignature
        var publicKey: P256.Signing.PublicKey
        var vendorID: UInt16?
        var productID: UInt16?
    }

    static func parse(_ der: [UInt8]) throws -> Parsed {
        var reader = DER.Reader(bytes: der)
        guard case .sequence(let parts) = try reader.next(depth: 0), parts.count == 3,
              case .bitString(let signatureBytes, _) = parts[2],
              case .sequence(let tbsFields) = parts[0],
              let subject = tbsFields.dropFirst(5).first, case .sequence(let keyInfo)? = tbsFields.dropFirst(6).first,
              keyInfo.count == 2, case .bitString(let keyBytes, _) = keyInfo[1]
        else { throw AttestationError.malformedCertificate }
        func attribute(_ oid: DER.ObjectIdentifier) -> UInt16? {
            for rdn in subject.members ?? [] {
                for pair in rdn.members ?? [] where pair[0]?.objectIdentifier == oid {
                    return pair[1]?.stringValue.flatMap { UInt16($0, radix: 16) }
                }
            }
            return nil
        }
        return Parsed(tbs: parts[0].encoded, signature: try P256.Signing.ECDSASignature(derRepresentation: signatureBytes),
                      publicKey: try P256.Signing.PublicKey(x963Representation: keyBytes),
                      vendorID: attribute(OID.matterVendorID), productID: attribute(OID.matterProductID))
    }

    /// Whether `certificate` was signed by `issuer`'s key.
    static func isSigned(_ certificate: [UInt8], by issuer: [UInt8]) -> Bool {
        guard let child = try? parse(certificate), let parent = try? parse(issuer) else { return false }
        return parent.publicKey.isValidSignature(child.signature, for: child.tbs)
    }
}

/// A PKCS#10 certification request (RFC 2986), as CSRRequest returns (Core §11.18.6.5).
enum CertificationRequest {
    static func create(key: P256.Signing.PrivateKey) throws -> [UInt8] {
        let info = DER.sequence([
            .integer([0]),
            .sequence([.set([.sequence([.objectIdentifier(OID.organizationName), .utf8String("CSR")])])]),
            MatterCertificate.subjectPublicKeyInfo(Array(key.publicKey.x963Representation)),
            .contextConstructed(0, []),
        ])
        return DER.signed(info, signature: Array(try key.signature(for: info.encoded).derRepresentation))
    }

    /// The requested public key, after checking the request's signature.
    static func publicKey(of csr: [UInt8]) throws -> P256.Signing.PublicKey {
        var reader = DER.Reader(bytes: csr)
        guard case .sequence(let parts) = try reader.next(depth: 0), parts.count == 3,
              case .sequence(let info) = parts[0], info.count >= 3, case .sequence(let keyInfo) = info[2], keyInfo.count == 2,
              case .bitString(let keyBytes, _) = keyInfo[1], case .bitString(let signature, _) = parts[2]
        else { throw AttestationError.malformedCertificate }
        let key = try P256.Signing.PublicKey(x963Representation: keyBytes)
        guard key.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: signature), for: parts[0].encoded) else {
            throw AttestationError.invalidSignature
        }
        return key
    }
}
