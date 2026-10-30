extension Array where Element == UInt8 {
    mutating func appendLittleEndian<T: FixedWidthInteger>(_ value: T) {
        Swift.withUnsafeBytes(of: value.littleEndian) { append(contentsOf: $0) }
    }

    mutating func appendBigEndian<T: FixedWidthInteger>(_ value: T) {
        Swift.withUnsafeBytes(of: value.bigEndian) { append(contentsOf: $0) }
    }
}

/// Bytes from hexadecimal digits; for constants and tests.
func hex(_ string: String) -> [UInt8] {
    var bytes: [UInt8] = []
    var iterator = string.makeIterator()
    while let high = iterator.next(), let low = iterator.next() {
        bytes.append(UInt8(String([high, low]), radix: 16)!)
    }
    return bytes
}

/// Bytes as uppercase hexadecimal digits.
func hexString(_ bytes: some Sequence<UInt8>) -> String {
    bytes.map { zeroPadded($0, width: 2, radix: 16) }.joined()
}

/// A non-negative integer in decimal or uppercase hexadecimal, left-padded with zeros to `width` characters.
func zeroPadded(_ value: some BinaryInteger, width: Int, radix: Int = 10) -> String {
    let digits = String(value, radix: radix, uppercase: true)
    return String(repeating: "0", count: max(0, width - digits.count)) + digits
}

/// Bounds-checked little-endian reading over bytes; running out throws the reader's error.
struct ByteReader {
    let bytes: [UInt8]
    private(set) var offset = 0
    let truncated: any Error

    init(_ bytes: [UInt8], truncated: any Error) {
        self.bytes = bytes
        self.truncated = truncated
    }

    var remaining: Int { bytes.count - offset }

    mutating func take(_ count: Int) throws -> ArraySlice<UInt8> {
        guard count >= 0, remaining >= count else { throw truncated }
        defer { offset += count }
        return bytes[offset..<offset + count]
    }

    mutating func read<T: FixedWidthInteger>(_ type: T.Type) throws -> T {
        try take(MemoryLayout<T>.size).reversed().reduce(T.zero) { $0 << 8 | T(truncatingIfNeeded: $1) }
    }
}

extension String {
    /// The longest prefix of whole characters that fits in `bytes` bytes of UTF-8: Matter limits strings by bytes.
    func utf8Prefix(_ bytes: Int) -> String {
        var count = 0
        var end = startIndex
        for character in self {
            count += character.utf8.count
            guard count <= bytes else { break }
            end = index(after: end)
        }
        return String(self[..<end])
    }
}

extension Array {
    /// The array in consecutive slices of `size` elements, the last one shorter.
    func chunks(of size: Int) -> [ArraySlice<Element>] {
        stride(from: 0, to: count, by: size).map { self[$0..<Swift.min($0 + size, count)] }
    }
}
