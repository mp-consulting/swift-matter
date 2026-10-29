/// Writes elements in their shortest form: integers and lengths take the fewest bytes that hold them.
public enum TLVEncoder {
    public static func encode(_ element: TLVElement) -> [UInt8] {
        var out: [UInt8] = []
        encode(element, into: &out)
        return out
    }

    /// An anonymous element.
    public static func encode(_ value: TLVValue) -> [UInt8] {
        encode(TLVElement(.anonymous, value))
    }

    public static func encode(_ element: TLVElement, into out: inout [UInt8]) {
        let (tagControl, tagBytes) = tagEncoding(element.tag)
        func control(_ type: UInt8) { out.append(tagControl << 5 | type); out.append(contentsOf: tagBytes) }

        switch element.value {
        case .signed(let value):
            switch value {
            case Int64(Int8.min)...Int64(Int8.max): control(0x00); out.appendLittleEndian(Int8(value))
            case Int64(Int16.min)...Int64(Int16.max): control(0x01); out.appendLittleEndian(Int16(value))
            case Int64(Int32.min)...Int64(Int32.max): control(0x02); out.appendLittleEndian(Int32(value))
            default: control(0x03); out.appendLittleEndian(value)
            }
        case .unsigned(let value):
            switch value {
            case 0...UInt64(UInt8.max): control(0x04); out.append(UInt8(value))
            case 0...UInt64(UInt16.max): control(0x05); out.appendLittleEndian(UInt16(value))
            case 0...UInt64(UInt32.max): control(0x06); out.appendLittleEndian(UInt32(value))
            default: control(0x07); out.appendLittleEndian(value)
            }
        case .bool(let value):
            control(value ? 0x09 : 0x08)
        case .float(let value):
            control(0x0A); out.appendLittleEndian(value.bitPattern)
        case .double(let value):
            control(0x0B); out.appendLittleEndian(value.bitPattern)
        case .utf8(let string):
            let bytes = Array(string.utf8)
            control(0x0C | lengthWidth(bytes.count)); appendLength(bytes.count, into: &out); out.append(contentsOf: bytes)
        case .bytes(let bytes):
            control(0x10 | lengthWidth(bytes.count)); appendLength(bytes.count, into: &out); out.append(contentsOf: bytes)
        case .null:
            control(0x14)
        case .structure(let elements), .array(let elements), .list(let elements):
            control(containerType(element.value))
            for member in elements { encode(member, into: &out) }
            out.append(0x18)
        }
    }

    private static func containerType(_ value: TLVValue) -> UInt8 {
        switch value {
        case .structure: 0x15
        case .array: 0x16
        default: 0x17
        }
    }

    private static func lengthWidth(_ count: Int) -> UInt8 {
        switch count {
        case 0...0xFF: 0
        case 0...0xFFFF: 1
        default: 2
        }
    }

    private static func appendLength(_ count: Int, into out: inout [UInt8]) {
        switch lengthWidth(count) {
        case 0: out.append(UInt8(count))
        case 1: out.appendLittleEndian(UInt16(count))
        default: out.appendLittleEndian(UInt32(count))
        }
    }

    private static func tagEncoding(_ tag: TLVTag) -> (UInt8, [UInt8]) {
        var bytes: [UInt8] = []
        switch tag {
        case .anonymous:
            return (0, [])
        case .context(let number):
            return (1, [number])
        case .commonProfile(let number) where number <= UInt16.max:
            bytes.appendLittleEndian(UInt16(number)); return (2, bytes)
        case .commonProfile(let number):
            bytes.appendLittleEndian(number); return (3, bytes)
        case .implicitProfile(let number) where number <= UInt16.max:
            bytes.appendLittleEndian(UInt16(number)); return (4, bytes)
        case .implicitProfile(let number):
            bytes.appendLittleEndian(number); return (5, bytes)
        case .fullyQualified(let vendor, let profile, let number):
            bytes.appendLittleEndian(vendor)
            bytes.appendLittleEndian(profile)
            if number <= UInt16.max {
                bytes.appendLittleEndian(UInt16(number)); return (6, bytes)
            }
            bytes.appendLittleEndian(number); return (7, bytes)
        }
    }
}

/// Reads elements, rejecting truncated input, reserved types and containers nested deeper than `maxDepth`.
public struct TLVDecoder {
    public static let maxDepth = 32

    private var reader: ByteReader

    /// Decodes exactly one element that spans all of `bytes`.
    public static func decode(_ bytes: some Collection<UInt8>) throws -> TLVElement {
        let (element, length) = try decodePrefix(bytes)
        guard length == bytes.count else { throw TLVError.trailingBytes }
        return element
    }

    /// Decodes one element at the start of `bytes`, returning it and how many bytes it took.
    public static func decodePrefix(_ bytes: some Collection<UInt8>) throws -> (TLVElement, Int) {
        var decoder = TLVDecoder(bytes: Array(bytes))
        let element = try decoder.next(depth: 0)
        return (element, decoder.reader.offset)
    }

    private init(bytes: [UInt8]) { reader = ByteReader(bytes, truncated: TLVError.truncated) }

    private mutating func take(_ count: Int) throws -> ArraySlice<UInt8> { try reader.take(count) }
    private mutating func read<T: FixedWidthInteger>(_ type: T.Type) throws -> T { try reader.read(type) }

    /// Returns nil on an end-of-container marker.
    private mutating func nextOrEnd(depth: Int) throws -> TLVElement? {
        let control = try read(UInt8.self)
        if control == 0x18 { return nil }
        let type = control & 0x1F
        let tag: TLVTag
        switch control >> 5 {
        case 0: tag = .anonymous
        case 1: tag = .context(try read(UInt8.self))
        case 2: tag = .commonProfile(UInt32(try read(UInt16.self)))
        case 3: tag = .commonProfile(try read(UInt32.self))
        case 4: tag = .implicitProfile(UInt32(try read(UInt16.self)))
        case 5: tag = .implicitProfile(try read(UInt32.self))
        case 6:
            tag = .fullyQualified(vendor: try read(UInt16.self), profile: try read(UInt16.self), tag: UInt32(try read(UInt16.self)))
        default:
            tag = .fullyQualified(vendor: try read(UInt16.self), profile: try read(UInt16.self), tag: try read(UInt32.self))
        }

        let value: TLVValue
        switch type {
        case 0x00: value = .signed(Int64(try read(Int8.self)))
        case 0x01: value = .signed(Int64(try read(Int16.self)))
        case 0x02: value = .signed(Int64(try read(Int32.self)))
        case 0x03: value = .signed(try read(Int64.self))
        case 0x04: value = .unsigned(UInt64(try read(UInt8.self)))
        case 0x05: value = .unsigned(UInt64(try read(UInt16.self)))
        case 0x06: value = .unsigned(UInt64(try read(UInt32.self)))
        case 0x07: value = .unsigned(try read(UInt64.self))
        case 0x08: value = .bool(false)
        case 0x09: value = .bool(true)
        case 0x0A: value = .float(Float(bitPattern: try read(UInt32.self)))
        case 0x0B: value = .double(Double(bitPattern: try read(UInt64.self)))
        case 0x0C...0x0F:
            let raw = Array(try take(try length(width: type & 0x03)))
            // Decoding repairs invalid sequences, so a round trip that changes the bytes means they were invalid.
            let string = String(decoding: raw, as: UTF8.self)
            guard string.utf8.elementsEqual(raw) else { throw TLVError.invalidUTF8 }
            value = .utf8(string)
        case 0x10...0x13:
            value = .bytes(Array(try take(try length(width: type & 0x03))))
        case 0x14:
            value = .null
        case 0x15, 0x16, 0x17:
            guard depth < Self.maxDepth else { throw TLVError.tooDeep }
            var members: [TLVElement] = []
            while true {
                guard reader.remaining > 0 else { throw TLVError.missingEndOfContainer }
                guard let member = try nextOrEnd(depth: depth + 1) else { break }
                members.append(member)
            }
            value = type == 0x15 ? .structure(members) : type == 0x16 ? .array(members) : .list(members)
        default:
            throw TLVError.reservedElementType(type)
        }
        return TLVElement(tag, value)
    }

    private mutating func next(depth: Int) throws -> TLVElement {
        guard let element = try nextOrEnd(depth: depth) else { throw TLVError.unexpectedEndOfContainer }
        return element
    }

    private mutating func length(width: UInt8) throws -> Int {
        let length: UInt64 = switch width {
        case 0: UInt64(try read(UInt8.self))
        case 1: UInt64(try read(UInt16.self))
        case 2: UInt64(try read(UInt32.self))
        default: try read(UInt64.self)
        }
        guard length <= UInt64(reader.remaining) else { throw TLVError.truncated }
        return Int(length)
    }
}
