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

/// A non-negative integer in decimal or uppercase hexadecimal, left-padded with zeros to `width` characters.
func zeroPadded(_ value: some BinaryInteger, width: Int, radix: Int = 10) -> String {
    let digits = String(value, radix: radix, uppercase: true)
    return String(repeating: "0", count: max(0, width - digits.count)) + digits
}
