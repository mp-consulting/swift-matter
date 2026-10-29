import Crypto
import Foundation

/// A Matter operational certificate (RCAC, ICAC or NOC) in its TLV form, and its X.509 equivalent, whose DER encoding
/// is what the signature covers (Core §6.5).
public struct MatterCertificate: Hashable, Sendable {
    /// A distinguished name attribute (Core §6.5.6.1), by TLV tag.
    public struct Attribute: Hashable, Sendable {
        public var tag: UInt8
        public var value: Value

        public enum Value: Hashable, Sendable {
            case string(String)
            case id(UInt64)

            public var id: UInt64? { if case .id(let id) = self { id } else { nil } }
        }

        /// The Matter-specific attribute tags (Core §6.1.1, table 85).
        public static let nodeIDTag: UInt8 = 17
        public static let icacIDTag: UInt8 = 19
        public static let rcacIDTag: UInt8 = 20
        public static let fabricIDTag: UInt8 = 21
        public static let caseAuthenticatedTagTag: UInt8 = 22
        static let matterTags: ClosedRange<UInt8> = 17...23

        public init(tag: UInt8, value: Value) {
            self.tag = tag
            self.value = value
        }

        public static func nodeID(_ id: UInt64) -> Attribute { Attribute(tag: nodeIDTag, value: .id(id)) }
        public static func icacID(_ id: UInt64) -> Attribute { Attribute(tag: icacIDTag, value: .id(id)) }
        public static func rcacID(_ id: UInt64) -> Attribute { Attribute(tag: rcacIDTag, value: .id(id)) }
        public static func fabricID(_ id: UInt64) -> Attribute { Attribute(tag: fabricIDTag, value: .id(id)) }
        public static func caseAuthenticatedTag(_ tag: UInt32) -> Attribute { Attribute(tag: caseAuthenticatedTagTag, value: .id(UInt64(tag))) }
        public static func commonName(_ name: String) -> Attribute { Attribute(tag: 1, value: .string(name)) }
    }

    public struct BasicConstraints: Hashable, Sendable {
        public var isCA: Bool
        public var pathLength: UInt8?

        public init(isCA: Bool, pathLength: UInt8? = nil) {
            self.isCA = isCA
            self.pathLength = pathLength
        }
    }

    public struct KeyUsage: OptionSet, Hashable, Sendable {
        public let rawValue: UInt16
        public init(rawValue: UInt16) { self.rawValue = rawValue }

        public static let digitalSignature = Self(rawValue: 0x0001)
        public static let keyCertSign = Self(rawValue: 0x0020)
        public static let crlSign = Self(rawValue: 0x0040)
    }

    public var serialNumber: [UInt8]
    public var issuer: [Attribute]
    /// Seconds since 2000-01-01 00:00:00 UTC (Matter's epoch).
    public var notBefore: UInt32
    /// 0 means no expiry.
    public var notAfter: UInt32
    public var subject: [Attribute]
    /// The uncompressed P-256 public key.
    public var publicKey: [UInt8]
    public var basicConstraints: BasicConstraints?
    public var keyUsage: KeyUsage?
    public var extendedKeyUsage: [UInt8]?
    public var subjectKeyID: [UInt8]?
    public var authorityKeyID: [UInt8]?
    /// Other extensions, each the DER of the whole X.509 extension.
    public var futureExtensions: [[UInt8]]
    /// r || s, 64 bytes.
    public var signature: [UInt8]

    public init(serialNumber: [UInt8], issuer: [Attribute], notBefore: UInt32, notAfter: UInt32, subject: [Attribute],
                publicKey: [UInt8], basicConstraints: BasicConstraints? = nil, keyUsage: KeyUsage? = nil,
                extendedKeyUsage: [UInt8]? = nil, subjectKeyID: [UInt8]? = nil, authorityKeyID: [UInt8]? = nil,
                futureExtensions: [[UInt8]] = [], signature: [UInt8] = []) {
        self.serialNumber = serialNumber
        self.issuer = issuer
        self.notBefore = notBefore
        self.notAfter = notAfter
        self.subject = subject
        self.publicKey = publicKey
        self.basicConstraints = basicConstraints
        self.keyUsage = keyUsage
        self.extendedKeyUsage = extendedKeyUsage
        self.subjectKeyID = subjectKeyID
        self.authorityKeyID = authorityKeyID
        self.futureExtensions = futureExtensions
        self.signature = signature
    }

    // MARK: - Subject values

    private func subjectID(_ tag: UInt8) -> UInt64? { subject.first { $0.tag == tag }?.value.id }

    public var nodeID: UInt64? { subjectID(Attribute.nodeIDTag) }
    public var fabricID: UInt64? { subjectID(Attribute.fabricIDTag) }
    public var rcacID: UInt64? { subjectID(Attribute.rcacIDTag) }
    public var icacID: UInt64? { subjectID(Attribute.icacIDTag) }
    public var caseAuthenticatedTags: [UInt32] {
        subject.filter { $0.tag == Attribute.caseAuthenticatedTagTag }.compactMap { $0.value.id.map(UInt32.init(truncatingIfNeeded:)) }
    }

    public var notBeforeDate: Date { Date(timeIntervalSince1970: Self.epochOffset + TimeInterval(notBefore)) }
    /// Nil when the certificate does not expire.
    public var notAfterDate: Date? { notAfter == 0 ? nil : Date(timeIntervalSince1970: Self.epochOffset + TimeInterval(notAfter)) }

    public func isValid(at date: Date) -> Bool {
        date >= notBeforeDate && notAfterDate.map { date <= $0 } ?? true
    }

    /// The subject's public key, checked to be a P-256 point when the certificate was decoded.
    public var signingKey: P256.Signing.PublicKey { get throws { try P256.Signing.PublicKey(x963Representation: publicKey) } }

    // MARK: - TLV

    public var tlv: TLVValue {
        func dn(_ attributes: [Attribute]) -> TLVValue {
            .list(attributes.map { attribute in
                switch attribute.value {
                case .string(let string): .field(attribute.tag, .utf8(string))
                case .id(let id): .field(attribute.tag, .unsigned(id))
                }
            })
        }
        var extensions: [TLVElement] = []
        if let basicConstraints {
            var members: [TLVElement] = [.field(1, .bool(basicConstraints.isCA))]
            if let pathLength = basicConstraints.pathLength { members.append(.field(2, .unsigned(UInt64(pathLength)))) }
            extensions.append(.field(1, .structure(members)))
        }
        if let keyUsage { extensions.append(.field(2, .unsigned(UInt64(keyUsage.rawValue)))) }
        if let extendedKeyUsage { extensions.append(.field(3, .array(extendedKeyUsage.map { TLVElement(.unsigned(UInt64($0))) }))) }
        if let subjectKeyID { extensions.append(.field(4, .bytes(subjectKeyID))) }
        if let authorityKeyID { extensions.append(.field(5, .bytes(authorityKeyID))) }
        for future in futureExtensions { extensions.append(.field(6, .bytes(future))) }
        return .structure([
            .field(1, .bytes(serialNumber)), .field(2, .unsigned(1)), .field(3, dn(issuer)),
            .field(4, .unsigned(UInt64(notBefore))), .field(5, .unsigned(UInt64(notAfter))), .field(6, dn(subject)),
            .field(7, .unsigned(1)), .field(8, .unsigned(1)), .field(9, .bytes(publicKey)),
            .field(10, .list(extensions)), .field(11, .bytes(signature)),
        ])
    }

    public var tlvEncoded: [UInt8] { TLVEncoder.encode(tlv) }

    public init(tlv bytes: some Collection<UInt8>) throws {
        try self.init(tlv: TLVDecoder.decode(bytes).value)
    }

    public init(tlv value: TLVValue) throws {
        let fields = try TLVStruct(value)
        guard try fields.uint(2) == 1 else { throw CertificateError.unsupportedAlgorithm }
        guard try fields.uint(7) == 1, try fields.uint(8) == 1 else { throw CertificateError.unsupportedAlgorithm }

        func dn(_ tag: UInt8) throws -> [Attribute] {
            let elements = try fields.elements(tag)
            guard (1...5).contains(elements.count) else { throw CertificateError.invalidName }
            return try elements.map { element in
                guard case .context(let number) = element.tag else { throw CertificateError.invalidName }
                switch (number, element.value) {
                case (1...16, .utf8(let string)), (129...143, .utf8(let string)): return Attribute(tag: number, value: .string(string))
                case (Attribute.matterTags, .unsigned(let id)): return Attribute(tag: number, value: .id(id))
                default: throw CertificateError.invalidName
                }
            }
        }

        let serialNumber = try fields.bytes(1)
        guard serialNumber.count <= 20 else { throw CertificateError.invalidField }
        let publicKey = try fields.bytes(9)
        guard publicKey.count == 65, (try? P256.Signing.PublicKey(x963Representation: publicKey)) != nil else {
            throw CertificateError.invalidPublicKey
        }
        let signature = try fields.bytes(11)
        guard signature.count == 64 else { throw CertificateError.invalidSignature }

        self.init(serialNumber: serialNumber, issuer: try dn(3), notBefore: try fields.uint(4, as: UInt32.self),
                  notAfter: try fields.uint(5, as: UInt32.self), subject: try dn(6), publicKey: publicKey, signature: signature)

        var seen = Set<UInt8>()
        for element in try fields.elements(10) {
            guard case .context(let number) = element.tag else { throw CertificateError.invalidExtension }
            guard number == 6 || seen.insert(number).inserted else { throw CertificateError.invalidExtension }
            switch (number, element.value) {
            case (1, .structure):
                let constraints = try TLVStruct(element.value)
                let isCA = try constraints.bool(1)
                let pathLength = try constraints[2].map { value -> UInt8 in
                    guard let length = value.uint, let narrow = UInt8(exactly: length) else { throw CertificateError.invalidExtension }
                    return narrow
                }
                basicConstraints = BasicConstraints(isCA: isCA, pathLength: pathLength)
            case (2, .unsigned(let value)):
                guard let narrow = UInt16(exactly: value) else { throw CertificateError.invalidExtension }
                keyUsage = KeyUsage(rawValue: narrow)
            case (3, .array(let purposes)):
                extendedKeyUsage = try purposes.map {
                    guard let value = $0.value.uint, let purpose = UInt8(exactly: value), OID.keyPurposes[purpose] != nil
                    else { throw CertificateError.invalidExtension }
                    return purpose
                }
            case (4, .bytes(let id)) where id.count == 20: subjectKeyID = id
            case (5, .bytes(let id)) where id.count == 20: authorityKeyID = id
            case (6, .bytes(let raw)): futureExtensions.append(raw)
            default: throw CertificateError.invalidExtension
            }
        }
    }

    // MARK: - X.509

    /// The DER tbsCertificate, which the signature covers.
    public var tbsCertificate: DER {
        var extensions: [DER] = []
        func add(_ oid: DER.ObjectIdentifier, critical: Bool, _ value: DER) {
            extensions.append(.sequence([.objectIdentifier(oid)] + (critical ? [.boolean(true)] : []) + [.octetString(value.encoded)]))
        }
        if let basicConstraints {
            var members: [DER] = basicConstraints.isCA ? [.boolean(true)] : []
            if let pathLength = basicConstraints.pathLength { members.append(.integer([pathLength])) }
            add(OID.basicConstraints, critical: true, .sequence(members))
        }
        if let keyUsage { add(OID.keyUsage, critical: true, Self.namedBits(keyUsage.rawValue)) }
        if let extendedKeyUsage {
            add(OID.extendedKeyUsage, critical: true, .sequence(extendedKeyUsage.compactMap { OID.keyPurposes[$0].map(DER.objectIdentifier) }))
        }
        if let subjectKeyID { add(OID.subjectKeyIdentifier, critical: false, .octetString(subjectKeyID)) }
        if let authorityKeyID { add(OID.authorityKeyIdentifier, critical: false, .sequence([.contextPrimitive(0, authorityKeyID)])) }
        extensions += futureExtensions.map(DER.raw)

        return .sequence([
            .contextConstructed(0, [.integer([2])]),
            .integer(serialNumber),
            .sequence([.objectIdentifier(OID.ecdsaWithSHA256)]),
            Self.name(issuer),
            .sequence([Self.time(notBefore, isNotAfter: false), Self.time(notAfter, isNotAfter: true)]),
            Self.name(subject),
            Self.subjectPublicKeyInfo(publicKey),
            .contextConstructed(3, [.sequence(extensions)]),
        ])
    }

    /// The whole X.509 certificate in DER.
    public var x509: [UInt8] {
        get throws {
            let signature = try P256.Signing.ECDSASignature(rawRepresentation: signature)
            return DER.sequence([
                tbsCertificate, .sequence([.objectIdentifier(OID.ecdsaWithSHA256)]), .bitString(Array(signature.derRepresentation)),
            ]).encoded
        }
    }

    /// Signs the certificate with the issuer's key.
    public mutating func sign(with key: P256.Signing.PrivateKey) throws {
        signature = Array(try key.signature(for: tbsCertificate.encoded).rawRepresentation)
    }

    /// Whether the signature verifies with the issuer's public key.
    public func isSigned(by issuerKey: P256.Signing.PublicKey) -> Bool {
        guard let signature = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else { return false }
        return issuerKey.isValidSignature(signature, for: tbsCertificate.encoded)
    }

    /// Whether the signature verifies with the issuer certificate's key.
    public func isSigned(by issuer: MatterCertificate) -> Bool {
        guard let key = try? issuer.signingKey else { return false }
        return isSigned(by: key)
    }

    static func subjectPublicKeyInfo(_ publicKey: [UInt8]) -> DER {
        .sequence([.sequence([.objectIdentifier(OID.ecPublicKey), .objectIdentifier(OID.prime256v1)]), .bitString(publicKey)])
    }

    /// A key usage bit string: Matter's flag bit i is X.509's named bit i, trailing zero bits trimmed.
    static func namedBits(_ flags: UInt16) -> DER {
        var bytes: [UInt8] = [0, 0]
        for bit in 0..<16 where flags >> bit & 1 == 1 { bytes[bit / 8] |= 0x80 >> UInt8(bit % 8) }
        while bytes.count > 1, bytes.last == 0 { bytes.removeLast() }
        let last = bytes.last ?? 0
        return .bitString(bytes, unusedBits: last == 0 ? 0 : UInt8(last.trailingZeroBitCount))
    }

    static let standardAttributeOIDs: [UInt8: String] = [
        1: "2.5.4.3", 2: "2.5.4.4", 3: "2.5.4.5", 4: "2.5.4.6", 5: "2.5.4.7", 6: "2.5.4.8", 7: "2.5.4.10", 8: "2.5.4.11",
        9: "2.5.4.12", 10: "2.5.4.41", 11: "2.5.4.42", 12: "2.5.4.43", 13: "2.5.4.44", 14: "2.5.4.46", 15: "2.5.4.65",
        16: "0.9.2342.19200300.100.1.25",
    ]

    static func name(_ attributes: [Attribute]) -> DER {
        .sequence(attributes.map { attribute in
            let pair: [DER]
            switch attribute.value {
            case .id(let id):
                let width = attribute.tag == Attribute.caseAuthenticatedTagTag ? 8 : 16
                pair = [.objectIdentifier(.init("1.3.6.1.4.1.37244.1.\(attribute.tag - 16)")),
                        .utf8String(zeroPadded(id, width: width, radix: 16))]
            case .string(let string):
                let base = attribute.tag & 0x7F
                let oid = DER.ObjectIdentifier(standardAttributeOIDs[base] ?? "2.5.4.3")
                let value: DER = base == 16 ? .ia5String(string) : attribute.tag & 0x80 != 0 ? .printableString(string) : .utf8String(string)
                pair = [.objectIdentifier(oid), value]
            }
            return .set([.sequence(pair)])
        })
    }

    /// Matter's epoch, 2000-01-01T00:00:00Z, in Unix seconds.
    public static let epochOffset: TimeInterval = 946_684_800

    static func time(_ seconds: UInt32, isNotAfter: Bool) -> DER {
        if isNotAfter && seconds == 0 { return .generalizedTime("99991231235959Z") }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        let date = Date(timeIntervalSince1970: epochOffset + TimeInterval(seconds))
        let parts = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
        func two(_ value: Int?) -> String { String(format: "%02d", value ?? 0) }
        let rest = two(parts.month) + two(parts.day) + two(parts.hour) + two(parts.minute) + two(parts.second) + "Z"
        let year = parts.year ?? 2000
        return year < 2050 ? .utcTime(two(year % 100) + rest) : .generalizedTime(String(format: "%04d", year) + rest)
    }

    /// Seconds since Matter's epoch for a date, clamped to the 32-bit range.
    public static func matterSeconds(_ date: Date) -> UInt32 {
        UInt32(clamping: Int64(max(0, date.timeIntervalSince1970 - epochOffset)))
    }

    /// The key identifier of a public key: the SHA-1 of its bytes (RFC 5280, section 4.2.1.2).
    public static func keyIdentifier(_ publicKey: [UInt8]) -> [UInt8] {
        Array(Insecure.SHA1.hash(data: publicKey))
    }
}

public enum CertificateError: Error, Equatable, Sendable {
    case unsupportedAlgorithm
    case invalidName
    case invalidField
    case invalidPublicKey
    case invalidSignature
    case invalidExtension
}
