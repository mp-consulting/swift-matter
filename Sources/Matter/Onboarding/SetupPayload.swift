/// The onboarding payload a commissioner reads from a QR code or a manual pairing code (Core §5.1).
public struct SetupPayload: Hashable, Sendable {
    /// How the device enters commissioning mode (Core §5.1.1.3).
    public enum CommissioningFlow: UInt8, Sendable {
        case standard = 0
        case userIntent = 1
        case custom = 2
    }

    /// Discovery capabilities (Core §5.1.1.4).
    public struct DiscoveryCapabilities: OptionSet, Hashable, Sendable {
        public let rawValue: UInt8
        public init(rawValue: UInt8) { self.rawValue = rawValue }

        public static let softAP = Self(rawValue: 1 << 0)
        public static let ble = Self(rawValue: 1 << 1)
        public static let onNetwork = Self(rawValue: 1 << 2)
        public static let wifiPAF = Self(rawValue: 1 << 3)
        public static let nfc = Self(rawValue: 1 << 4)
    }

    public var vendorID: UInt16
    public var productID: UInt16
    public var flow: CommissioningFlow
    public var capabilities: DiscoveryCapabilities
    /// The 12-bit discriminator.
    public var discriminator: UInt16
    /// The 27-bit passcode (an 8-digit number).
    public var passcode: UInt32

    public init(vendorID: UInt16, productID: UInt16, flow: CommissioningFlow = .standard,
                capabilities: DiscoveryCapabilities = .onNetwork, discriminator: UInt16, passcode: UInt32) {
        self.vendorID = vendorID
        self.productID = productID
        self.flow = flow
        self.capabilities = capabilities
        self.discriminator = discriminator & 0x0FFF
        self.passcode = passcode
    }

    /// The upper four bits of the discriminator, which the manual code carries.
    public var shortDiscriminator: UInt8 { UInt8(discriminator >> 8) }

    // MARK: - Passcodes

    /// Passcodes a device SHALL NOT use (Core §5.1.7.1).
    static let invalidPasscodes: Set<UInt32> = [
        0, 11111111, 22222222, 33333333, 44444444, 55555555, 66666666, 77777777, 88888888, 99999999, 12345678, 87654321,
    ]

    public static func isValid(passcode: UInt32) -> Bool {
        (1...99_999_998).contains(passcode) && !invalidPasscodes.contains(passcode)
    }

    public static func randomPasscode() -> UInt32 {
        while true {
            let candidate = UInt32.random(in: 1...99_999_998)
            if isValid(passcode: candidate) { return candidate }
        }
    }

    public static func randomDiscriminator() -> UInt16 { UInt16.random(in: 0...0x0FFF) }

    // MARK: - QR code

    /// The QR code's text: `MT:` and the Base38 packed payload (Core §5.1.3).
    public var qrCode: String {
        var bits = BitWriter()
        bits.write(0, width: 3)
        bits.write(UInt64(vendorID), width: 16)
        bits.write(UInt64(productID), width: 16)
        bits.write(UInt64(flow.rawValue), width: 2)
        bits.write(UInt64(capabilities.rawValue), width: 8)
        bits.write(UInt64(discriminator), width: 12)
        bits.write(UInt64(passcode), width: 27)
        bits.write(0, width: 4)
        return "MT:" + Base38.encode(bits.bytes)
    }

    public init(qrCode: String) throws {
        guard qrCode.hasPrefix("MT:") else { throw SetupPayloadError.invalidPrefix }
        // Concatenated payloads are separated by '*'; the first one is read.
        let encoded = qrCode.dropFirst(3).split(separator: "*", omittingEmptySubsequences: false).first ?? ""
        let bytes = try Base38.decode(String(encoded))
        guard bytes.count >= 11 else { throw SetupPayloadError.tooShort }
        var bits = BitReader(bytes: bytes)
        guard bits.read(3) == 0 else { throw SetupPayloadError.unsupportedVersion }
        let vendorID = UInt16(bits.read(16)), productID = UInt16(bits.read(16))
        guard let flow = CommissioningFlow(rawValue: UInt8(bits.read(2))) else { throw SetupPayloadError.invalidFlow }
        let capabilities = DiscoveryCapabilities(rawValue: UInt8(bits.read(8)))
        let discriminator = UInt16(bits.read(12)), passcode = UInt32(bits.read(27))
        guard Self.isValid(passcode: passcode) else { throw SetupPayloadError.invalidPasscode }
        self.init(vendorID: vendorID, productID: productID, flow: flow, capabilities: capabilities,
                  discriminator: discriminator, passcode: passcode)
    }

    // MARK: - Manual pairing code

    /// The 11-digit manual pairing code, or 21 digits with the vendor and product ids when the flow is not standard (Core §5.1.4).
    public var manualCode: String {
        let includesIDs = flow != .standard
        let first = (includesIDs ? 1 << 2 : 0) | UInt32(discriminator >> 10)
        let second = UInt32(discriminator & 0x300) << 6 | passcode & 0x3FFF
        let third = passcode >> 14
        var digits = String(first) + padded(second, 5) + padded(third, 4)
        if includesIDs { digits += padded(UInt32(vendorID), 5) + padded(UInt32(productID), 5) }
        return digits + String(Verhoeff.checkDigit(digits))
    }

    /// The values a manual code carries: the short discriminator and the passcode.
    public static func parse(manualCode: String) throws -> (shortDiscriminator: UInt8, passcode: UInt32) {
        let digits = manualCode.filter(\.isNumber)
        guard digits.count == 11 || digits.count == 21 else { throw SetupPayloadError.invalidLength }
        guard Verhoeff.checkDigit(String(digits.dropLast())) == digits.last!.wholeNumberValue! else {
            throw SetupPayloadError.invalidCheckDigit
        }
        let numbers = Array(digits).map { UInt32($0.wholeNumberValue!) }
        func value(_ range: Range<Int>) -> UInt32 { numbers[range].reduce(0) { $0 * 10 + $1 } }
        let first = value(0..<1), second = value(1..<6), third = value(6..<10)
        guard first <= 7, second <= 0xFFFF, third <= 0x1FFF else { throw SetupPayloadError.invalidDigits }
        let passcode = third << 14 | second & 0x3FFF
        guard isValid(passcode: passcode) else { throw SetupPayloadError.invalidPasscode }
        // The short discriminator's two upper bits are in the first digit, the next two in the second group.
        let shortDiscriminator = UInt8((first & 0x3) << 2 | second >> 14)
        return (shortDiscriminator, passcode)
    }

    private func padded(_ value: UInt32, _ width: Int) -> String {
        let string = String(value)
        return String(repeating: "0", count: max(0, width - string.count)) + string
    }
}

public enum SetupPayloadError: Error, Equatable, Sendable {
    case invalidPrefix
    case invalidCharacter
    case tooShort
    case unsupportedVersion
    case invalidFlow
    case invalidPasscode
    case invalidLength
    case invalidCheckDigit
    case invalidDigits
}

/// Base-38 (Core §5.1.3.1): 3 bytes become 5 characters, 2 bytes 4, 1 byte 2, least significant first.
enum Base38 {
    static let alphabet = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-.")

    static func encode(_ bytes: [UInt8]) -> String {
        var output = ""
        for start in stride(from: 0, to: bytes.count, by: 3) {
            let chunk = bytes[start..<min(start + 3, bytes.count)]
            var value = chunk.reversed().reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
            for _ in 0..<[0, 2, 4, 5][chunk.count] {
                output.append(alphabet[Int(value % 38)])
                value /= 38
            }
        }
        return output
    }

    static func decode(_ string: String) throws -> [UInt8] {
        let characters = Array(string)
        var output: [UInt8] = []
        var start = 0
        while start < characters.count {
            let length = min(5, characters.count - start)
            let byteCount: Int
            switch length {
            case 5: byteCount = 3
            case 4: byteCount = 2
            case 2: byteCount = 1
            default: throw SetupPayloadError.invalidCharacter
            }
            var value: UInt32 = 0
            for character in characters[start..<start + length].reversed() {
                guard let digit = alphabet.firstIndex(of: character) else { throw SetupPayloadError.invalidCharacter }
                value = value * 38 + UInt32(digit)
            }
            guard value < 1 << (8 * byteCount) else { throw SetupPayloadError.invalidCharacter }
            for index in 0..<byteCount { output.append(UInt8(truncatingIfNeeded: value >> (8 * index))) }
            start += length
        }
        return output
    }
}

/// The Verhoeff check digit.
enum Verhoeff {
    private static let multiplication: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ]
    private static let permutation: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ]
    private static let inverse = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]

    static func checkDigit(_ digits: String) -> Int {
        var check = 0
        for (index, character) in digits.reversed().enumerated() {
            check = multiplication[check][permutation[(index + 1) % 8][character.wholeNumberValue ?? 0]]
        }
        return inverse[check]
    }
}

/// Packs values least significant bit first.
struct BitWriter {
    private(set) var bytes: [UInt8] = []
    private var bitCount = 0

    mutating func write(_ value: UInt64, width: Int) {
        for bit in 0..<width {
            if bitCount % 8 == 0 { bytes.append(0) }
            if value >> UInt64(bit) & 1 == 1 { bytes[bitCount / 8] |= 1 << UInt8(bitCount % 8) }
            bitCount += 1
        }
    }
}

struct BitReader {
    let bytes: [UInt8]
    private var bitCount = 0

    init(bytes: [UInt8]) { self.bytes = bytes }

    mutating func read(_ width: Int) -> UInt64 {
        var value: UInt64 = 0
        for bit in 0..<width {
            let byte = bitCount / 8 < bytes.count ? bytes[bitCount / 8] : 0
            if byte >> UInt8(bitCount % 8) & 1 == 1 { value |= 1 << UInt64(bit) }
            bitCount += 1
        }
        return value
    }
}
