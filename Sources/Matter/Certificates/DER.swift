/// The subset of ASN.1 DER that X.509 certificates, PKCS#10 requests and PKCS#7 envelopes need.
public indirect enum DER: Equatable, Sendable {
    case boolean(Bool)
    /// A non-negative integer from its big-endian magnitude; leading zeros are trimmed and a zero byte added when the
    /// high bit is set.
    case integer([UInt8])
    case bitString([UInt8], unusedBits: UInt8 = 0)
    case octetString([UInt8])
    case null
    case objectIdentifier(ObjectIdentifier)
    case utf8String(String)
    case printableString(String)
    case ia5String(String)
    case utcTime(String)
    case generalizedTime(String)
    case sequence([DER])
    case set([DER])
    /// A context-specific constructed element: [number] EXPLICIT or IMPLICIT around constructed contents.
    case contextConstructed(UInt8, [DER])
    /// A context-specific primitive element: [number] IMPLICIT around raw bytes.
    case contextPrimitive(UInt8, [UInt8])
    /// Already encoded bytes, written as they are.
    case raw([UInt8])
    /// Any other element, as read.
    case other(tag: UInt8, contents: [UInt8])

    public struct ObjectIdentifier: Hashable, Sendable, CustomStringConvertible {
        public let components: [UInt64]

        public init(_ string: String) { components = string.split(separator: ".").map { UInt64($0)! } }
        public init(components: [UInt64]) { self.components = components }

        public var description: String { components.map(String.init).joined(separator: ".") }

        var encoded: [UInt8] {
            var out: [UInt8] = []
            func base128(_ value: UInt64) {
                var groups: [UInt8] = [UInt8(value & 0x7F)]
                var rest = value >> 7
                while rest > 0 { groups.append(UInt8(rest & 0x7F) | 0x80); rest >>= 7 }
                out += groups.reversed()
            }
            base128(components[0] * 40 + components[1])
            for component in components.dropFirst(2) { base128(component) }
            return out
        }

        init(encoded bytes: [UInt8]) throws {
            var values: [UInt64] = []
            var current: UInt64 = 0
            for byte in bytes {
                guard current >> 57 == 0 else { throw DERError.malformed }
                current = current << 7 | UInt64(byte & 0x7F)
                if byte & 0x80 == 0 { values.append(current); current = 0 }
            }
            guard let first = values.first, bytes.last.map({ $0 & 0x80 == 0 }) == true else { throw DERError.malformed }
            let head: [UInt64] = first < 80 ? [first / 40, first % 40] : [2, first - 80]
            components = head + values.dropFirst()
        }
    }

    public var encoded: [UInt8] {
        switch self {
        case .boolean(let value): return Self.element(0x01, [value ? 0xFF : 0x00])
        case .integer(let magnitude):
            var bytes = Array(magnitude.drop { $0 == 0 })
            if bytes.isEmpty || bytes[0] & 0x80 != 0 { bytes.insert(0, at: 0) }
            return Self.element(0x02, bytes)
        case .bitString(let bytes, let unusedBits): return Self.element(0x03, [unusedBits] + bytes)
        case .octetString(let bytes): return Self.element(0x04, bytes)
        case .null: return [0x05, 0x00]
        case .objectIdentifier(let oid): return Self.element(0x06, oid.encoded)
        case .utf8String(let string): return Self.element(0x0C, Array(string.utf8))
        case .printableString(let string): return Self.element(0x13, Array(string.utf8))
        case .ia5String(let string): return Self.element(0x16, Array(string.utf8))
        case .utcTime(let string): return Self.element(0x17, Array(string.utf8))
        case .generalizedTime(let string): return Self.element(0x18, Array(string.utf8))
        case .sequence(let members): return Self.element(0x30, members.flatMap(\.encoded))
        case .set(let members): return Self.element(0x31, members.flatMap(\.encoded))
        case .contextConstructed(let number, let members): return Self.element(0xA0 | number, members.flatMap(\.encoded))
        case .contextPrimitive(let number, let bytes): return Self.element(0x80 | number, bytes)
        case .raw(let bytes): return bytes
        case .other(let tag, let contents): return Self.element(tag, contents)
        }
    }

    static func element(_ tag: UInt8, _ contents: [UInt8]) -> [UInt8] {
        var out: [UInt8] = [tag]
        if contents.count < 0x80 {
            out.append(UInt8(contents.count))
        } else {
            var length = contents.count
            var lengthBytes: [UInt8] = []
            while length > 0 { lengthBytes.insert(UInt8(length & 0xFF), at: 0); length >>= 8 }
            out.append(0x80 | UInt8(lengthBytes.count))
            out += lengthBytes
        }
        return out + contents
    }

    // MARK: - Reading

    /// Parses one element spanning all of `bytes`.
    public static func parse(_ bytes: some Collection<UInt8>) throws -> DER {
        var reader = Reader(bytes: Array(bytes))
        let element = try reader.next(depth: 0)
        guard reader.atEnd else { throw DERError.trailingBytes }
        return element
    }

    struct Reader {
        let bytes: [UInt8]
        var offset = 0
        var atEnd: Bool { offset == bytes.count }

        /// The next element's tag and contents.
        mutating func nextElement() throws -> (tag: UInt8, contents: [UInt8]) {
            guard offset < bytes.count else { throw DERError.truncated }
            let tag = bytes[offset]
            guard tag & 0x1F != 0x1F else { throw DERError.unsupported }
            offset += 1
            guard offset < bytes.count else { throw DERError.truncated }
            var length = Int(bytes[offset])
            offset += 1
            if length & 0x80 != 0 {
                let count = length & 0x7F
                guard (1...4).contains(count), bytes.count - offset >= count else { throw DERError.malformed }
                length = 0
                for _ in 0..<count { length = length << 8 | Int(bytes[offset]); offset += 1 }
            }
            guard length <= bytes.count - offset else { throw DERError.truncated }
            let contents = Array(bytes[offset..<offset + length])
            offset += length
            return (tag, contents)
        }

        mutating func next(depth: Int) throws -> DER {
            guard depth < 16 else { throw DERError.malformed }
            let (tag, contents) = try nextElement()
            func members() throws -> [DER] {
                var reader = Reader(bytes: contents)
                var out: [DER] = []
                while !reader.atEnd { out.append(try reader.next(depth: depth + 1)) }
                return out
            }
            func string() throws -> String {
                let string = String(decoding: contents, as: UTF8.self)
                guard string.utf8.elementsEqual(contents) else { throw DERError.malformed }
                return string
            }
            switch tag {
            case 0x01:
                guard contents.count == 1 else { throw DERError.malformed }
                return .boolean(contents[0] != 0)
            case 0x02: return .integer(contents)
            case 0x03:
                guard let unused = contents.first, unused < 8 else { throw DERError.malformed }
                return .bitString(Array(contents.dropFirst()), unusedBits: unused)
            case 0x04: return .octetString(contents)
            case 0x05: return .null
            case 0x06: return .objectIdentifier(try ObjectIdentifier(encoded: contents))
            case 0x0C: return .utf8String(try string())
            case 0x13: return .printableString(try string())
            case 0x16: return .ia5String(try string())
            case 0x17: return .utcTime(try string())
            case 0x18: return .generalizedTime(try string())
            case 0x30: return .sequence(try members())
            case 0x31: return .set(try members())
            case 0xA0...0xBF: return .contextConstructed(tag & 0x1F, try members())
            case 0x80...0x9F: return .contextPrimitive(tag & 0x1F, contents)
            default: return .other(tag: tag, contents: contents)
            }
        }
    }

    // MARK: - Access

    public var members: [DER]? {
        switch self {
        case .sequence(let members), .set(let members), .contextConstructed(_, let members): members
        default: nil
        }
    }

    public subscript(index: Int) -> DER? {
        guard let members, members.indices.contains(index) else { return nil }
        return members[index]
    }

    public var objectIdentifier: ObjectIdentifier? { if case .objectIdentifier(let oid) = self { oid } else { nil } }

    public var stringValue: String? {
        switch self {
        case .utf8String(let string), .printableString(let string), .ia5String(let string): string
        default: nil
        }
    }

    public var bitStringBytes: [UInt8]? { if case .bitString(let bytes, _) = self { bytes } else { nil } }
    public var octetStringBytes: [UInt8]? { if case .octetString(let bytes) = self { bytes } else { nil } }
}

public enum DERError: Error, Equatable, Sendable {
    case truncated
    case malformed
    case unsupported
    case trailingBytes
}

/// The object identifiers Matter uses.
public enum OID {
    public static let ecdsaWithSHA256 = DER.ObjectIdentifier("1.2.840.10045.4.3.2")
    public static let ecPublicKey = DER.ObjectIdentifier("1.2.840.10045.2.1")
    public static let prime256v1 = DER.ObjectIdentifier("1.2.840.10045.3.1.7")
    public static let basicConstraints = DER.ObjectIdentifier("2.5.29.19")
    public static let keyUsage = DER.ObjectIdentifier("2.5.29.15")
    public static let extendedKeyUsage = DER.ObjectIdentifier("2.5.29.37")
    public static let subjectKeyIdentifier = DER.ObjectIdentifier("2.5.29.14")
    public static let authorityKeyIdentifier = DER.ObjectIdentifier("2.5.29.35")
    public static let signedData = DER.ObjectIdentifier("1.2.840.113549.1.7.2")
    public static let data = DER.ObjectIdentifier("1.2.840.113549.1.7.1")
    public static let sha256 = DER.ObjectIdentifier("2.16.840.1.101.3.4.2.1")
    /// Matter's vendor id and product id attributes in attestation certificates (Core §6.2.2.2).
    public static let matterVendorID = DER.ObjectIdentifier("1.3.6.1.4.1.37244.2.1")
    public static let matterProductID = DER.ObjectIdentifier("1.3.6.1.4.1.37244.2.2")
    public static let commonName = DER.ObjectIdentifier("2.5.4.3")
    public static let organizationName = DER.ObjectIdentifier("2.5.4.10")

    /// The key purposes of the extended key usage extension, by Matter's key-purpose-id (Core §6.5.11.3).
    static let keyPurposes: [UInt8: DER.ObjectIdentifier] = [
        1: .init("1.3.6.1.5.5.7.3.1"), 2: .init("1.3.6.1.5.5.7.3.2"), 3: .init("1.3.6.1.5.5.7.3.3"),
        4: .init("1.3.6.1.5.5.7.3.4"), 5: .init("1.3.6.1.5.5.7.3.8"), 6: .init("1.3.6.1.5.5.7.3.9"),
    ]
}
