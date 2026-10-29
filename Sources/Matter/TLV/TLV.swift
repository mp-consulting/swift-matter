/// Matter's tag-length-value encoding (Core specification, Appendix A).

/// An element's tag (Appendix A.7).
public enum TLVTag: Hashable, Sendable {
    case anonymous
    case context(UInt8)
    case commonProfile(UInt32)
    case implicitProfile(UInt32)
    case fullyQualified(vendor: UInt16, profile: UInt16, tag: UInt32)
}

/// An element's value (Appendix A.6).
public indirect enum TLVValue: Hashable, Sendable {
    case signed(Int64)
    case unsigned(UInt64)
    case bool(Bool)
    case float(Float)
    case double(Double)
    case utf8(String)
    case bytes([UInt8])
    case null
    case structure([TLVElement])
    case array([TLVElement])
    case list([TLVElement])
}

/// A tagged value.
public struct TLVElement: Hashable, Sendable {
    public var tag: TLVTag
    public var value: TLVValue

    public init(_ tag: TLVTag, _ value: TLVValue) {
        self.tag = tag
        self.value = value
    }

    /// An anonymous element.
    public init(_ value: TLVValue) {
        self.init(.anonymous, value)
    }

    /// A context-tagged member of a structure.
    public static func field(_ tag: UInt8, _ value: TLVValue) -> TLVElement {
        TLVElement(.context(tag), value)
    }
}

public enum TLVError: Error, Equatable, Sendable {
    case truncated
    case reservedElementType(UInt8)
    case unexpectedEndOfContainer
    case missingEndOfContainer
    case invalidUTF8
    case tooDeep
    case trailingBytes
    /// A schema check: the field is missing or has another type.
    case field(UInt8)
    case unexpectedType
}

extension TLVValue {
    public var uint: UInt64? {
        switch self {
        case .unsigned(let value): value
        case .signed(let value) where value >= 0: UInt64(value)
        default: nil
        }
    }

    public var int: Int64? {
        switch self {
        case .signed(let value): value
        case .unsigned(let value) where value <= UInt64(Int64.max): Int64(value)
        default: nil
        }
    }

    public var bool: Bool? { if case .bool(let value) = self { value } else { nil } }
    public var bytes: [UInt8]? { if case .bytes(let value) = self { value } else { nil } }
    public var string: String? { if case .utf8(let value) = self { value } else { nil } }
    public var isNull: Bool { self == .null }

    public var floatingPoint: Double? {
        switch self {
        case .float(let value): Double(value)
        case .double(let value): value
        default: nil
        }
    }

    /// The members of a structure, an array or a list.
    public var elements: [TLVElement]? {
        switch self {
        case .structure(let elements), .array(let elements), .list(let elements): elements
        default: nil
        }
    }

    /// A structure's or a list's member by context tag.
    public subscript(tag: UInt8) -> TLVValue? {
        switch self {
        case .structure(let elements), .list(let elements): elements.first { $0.tag == .context(tag) }?.value
        default: nil
        }
    }
}

/// Typed access to a structure's fields that throws `TLVError.field` when one is missing or mistyped.
public struct TLVStruct: Sendable {
    public let value: TLVValue

    public init(_ value: TLVValue) throws {
        guard case .structure = value else { throw TLVError.unexpectedType }
        self.value = value
    }

    public init(decoding bytes: some Collection<UInt8>) throws {
        try self.init(TLVDecoder.decode(bytes).value)
    }

    public subscript(tag: UInt8) -> TLVValue? { value[tag] }

    private func field<T>(_ tag: UInt8, _ read: (TLVValue) -> T?) throws -> T {
        guard let value = value[tag].flatMap(read) else { throw TLVError.field(tag) }
        return value
    }

    public func uint(_ tag: UInt8) throws -> UInt64 { try field(tag, \.uint) }
    public func int(_ tag: UInt8) throws -> Int64 { try field(tag, \.int) }
    public func bytes(_ tag: UInt8) throws -> [UInt8] { try field(tag, \.bytes) }
    public func string(_ tag: UInt8) throws -> String { try field(tag, \.string) }
    public func bool(_ tag: UInt8) throws -> Bool { try field(tag, \.bool) }
    public func elements(_ tag: UInt8) throws -> [TLVElement] { try field(tag, \.elements) }

    public func uint<T: FixedWidthInteger & UnsignedInteger>(_ tag: UInt8, as type: T.Type) throws -> T {
        try field(tag) { $0.uint.flatMap { T(exactly: $0) } }
    }

    public func structure(_ tag: UInt8) throws -> TLVStruct {
        guard let value = value[tag] else { throw TLVError.field(tag) }
        return try TLVStruct(value)
    }
}
