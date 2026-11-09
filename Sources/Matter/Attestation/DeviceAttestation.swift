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
    /// The vendor and product of the DAC when another vendor's PAI issued it (both or neither), and the PAAs allowed to
    /// root the device's chain, by subject key identifier (Core §6.3.1).
    public var dacOriginVendorID: UInt16?
    public var dacOriginProductID: UInt16?
    public var authorizedPAAs: [[UInt8]]?

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
        // Built a field at a time: one expression of it takes the compiler too long to type-check (Linux CI).
        let productList: [TLVElement] = productIDs.map { TLVElement(.unsigned(UInt64($0))) }
        var fields: [TLVElement] = [
            .field(0, .unsigned(1)), .field(1, .unsigned(UInt64(vendorID))),
            .field(2, .array(productList)), .field(3, .unsigned(UInt64(deviceType))),
            .field(4, .utf8(certificateID)), .field(5, .unsigned(UInt64(securityLevel))),
            .field(6, .unsigned(UInt64(securityInformation))), .field(7, .unsigned(UInt64(versionNumber))),
            .field(8, .unsigned(UInt64(certificationType))),
        ]
        if let vendor = dacOriginVendorID { fields.append(.field(9, .unsigned(UInt64(vendor)))) }
        if let product = dacOriginProductID { fields.append(.field(10, .unsigned(UInt64(product)))) }
        if let paas = authorizedPAAs {
            let keyIDs: [TLVElement] = paas.map { TLVElement(.bytes($0)) }
            fields.append(.field(11, .array(keyIDs)))
        }
        return TLVEncoder.encode(.structure(fields))
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

    /// The key identifier its SignerInfo names (subjectKeyIdentifier, Core Appendix F.1): which signing key to check it with.
    public static func signerKeyID(_ cms: [UInt8]) throws -> [UInt8] {
        guard case .contextPrimitive(0, let keyID)? = try DER.parse(cms)[1]?[0]?[3]?[0]?[1] else {
            throw AttestationError.malformedDeclaration
        }
        return keyID
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
        let notBefore = MatterCertificate.time(MatterCertificate.matterSeconds(Date().addingTimeInterval(-86_400)))
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
        var notBefore: Date
        var notAfter: Date
        /// Basic constraints: whether it is a CA (nil without the extension), and its path length.
        var isCA: Bool?
        var pathLength: Int?
        var subjectKeyID: [UInt8]?
        var authorityKeyID: [UInt8]?

        func isValid(at date: Date) -> Bool { notBefore <= date && date <= notAfter }
    }

    static func parse(_ der: [UInt8]) throws -> Parsed {
        var reader = DER.Reader(bytes: der)
        // TBSCertificate (RFC 5280 §4.1): version [0], serial, signature, issuer, validity, subject, key, extensions [3].
        guard case .sequence(let parts) = try reader.next(depth: 0), parts.count == 3,
              case .bitString(let signatureBytes, _) = parts[2],
              case .sequence(let tbsFields) = parts[0], tbsFields.count >= 7,
              case .contextConstructed(0, _) = tbsFields[0],
              case .sequence(let validity) = tbsFields[4], validity.count == 2,
              let notBefore = time(validity[0]), let notAfter = time(validity[1]),
              case .sequence(let keyInfo) = tbsFields[6], keyInfo.count == 2, case .bitString(let keyBytes, _) = keyInfo[1]
        else { throw AttestationError.malformedCertificate }
        let ids = try identifiers(tbsFields[5])
        var parsed = Parsed(tbs: parts[0].encoded, signature: try P256.Signing.ECDSASignature(derRepresentation: signatureBytes),
                            publicKey: try P256.Signing.PublicKey(x963Representation: keyBytes), vendorID: ids.vendorID,
                            productID: ids.productID, notBefore: notBefore, notAfter: notAfter)
        for case .contextConstructed(3, let wrapped) in tbsFields.dropFirst(7) {
            for item in wrapped.first?.members ?? [] {
                guard let oid = item[0]?.objectIdentifier, let value = item.members?.last?.octetStringBytes,
                      let inner = try? DER.parse(value) else { throw AttestationError.malformedCertificate }
                switch oid {
                case OID.basicConstraints:
                    parsed.isCA = false
                    for member in inner.members ?? [] {
                        if case .boolean(let ca) = member { parsed.isCA = ca }
                        if case .integer(let length) = member, length.count == 1 { parsed.pathLength = Int(length[0]) }
                    }
                case OID.subjectKeyIdentifier: parsed.subjectKeyID = inner.octetStringBytes
                case OID.authorityKeyIdentifier:
                    if case .contextPrimitive(0, let id)? = inner[0] { parsed.authorityKeyID = id }
                default: break
                }
            }
        }
        return parsed
    }

    /// A subject's vendor and product ids (Core §6.2.2.2): Matter's attributes, each exactly four uppercase hexadecimal
    /// digits (§6.1.1), or else `Mvid:XXXX` and `Mpid:XXXX` in the common name, the leftmost well-formed one counting.
    /// A prefix with no well-formed value, or both methods for one id, is a malformed certificate.
    static func identifiers(_ subject: DER) throws -> (vendorID: UInt16?, productID: UInt16?) {
        func hex4(_ text: Substring) -> UInt16? {
            guard text.count == 4, text.allSatisfy({ $0.isHexDigit && !$0.isLowercase }) else { return nil }
            return UInt16(text, radix: 16)
        }
        var attributes: [DER.ObjectIdentifier: String] = [:]
        for rdn in subject.members ?? [] {
            for pair in rdn.members ?? [] {
                if let oid = pair[0]?.objectIdentifier, let value = pair[1]?.stringValue { attributes[oid] = value }
            }
        }
        func id(_ oid: DER.ObjectIdentifier, prefix: String) throws -> UInt16? {
            let fallback: UInt16?
            if let commonName = attributes[OID.commonName], commonName.contains(prefix) {
                let candidates = commonName.ranges(of: prefix).map { commonName[$0.upperBound...].prefix(4) }
                guard let first = candidates.lazy.compactMap(hex4).first else { throw AttestationError.malformedCertificate }
                fallback = first
            } else {
                fallback = nil
            }
            guard let value = attributes[oid] else { return fallback }
            guard fallback == nil, let preferred = hex4(Substring(value)) else { throw AttestationError.malformedCertificate }
            return preferred
        }
        return (try id(OID.matterVendorID, prefix: "Mvid:"), try id(OID.matterProductID, prefix: "Mpid:"))
    }

    /// A UTCTime (years 1950-2049) or GeneralizedTime, in UTC (RFC 5280 §4.1.2.5).
    static func time(_ value: DER) -> Date? {
        let text: String, digits: Int
        switch value {
        case .utcTime(let string): (text, digits) = (string, 2)
        case .generalizedTime(let string): (text, digits) = (string, 4)
        default: return nil
        }
        let body = text.dropLast()
        guard text.count == digits + 11, text.hasSuffix("Z"), body.allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
        let n = body.compactMap(\.wholeNumberValue)
        func number(_ from: Int, _ count: Int) -> Int { n[from..<(from + count)].reduce(0) { $0 * 10 + $1 } }
        var year = number(0, digits)
        if digits == 2 { year += year < 50 ? 2000 : 1900 }
        var components = DateComponents(timeZone: TimeZone(identifier: "UTC"), year: year, month: number(digits, 2),
                                         day: number(digits + 2, 2), hour: number(digits + 4, 2), minute: number(digits + 6, 2),
                                         second: number(digits + 8, 2))
        components.calendar = Calendar(identifier: .gregorian)
        guard components.isValidDate, let date = components.date else { return nil }
        return date
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
