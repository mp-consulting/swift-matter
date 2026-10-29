/// Secure Channel opcodes (Core §4.11, table 18).
public enum SecureChannelOpcode: UInt8, Sendable {
    case messageCounterSyncRequest = 0x00
    case messageCounterSyncResponse = 0x01
    case standaloneAck = 0x10
    case pbkdfParamRequest = 0x20
    case pbkdfParamResponse = 0x21
    case pake1 = 0x22
    case pake2 = 0x23
    case pake3 = 0x24
    case sigma1 = 0x30
    case sigma2 = 0x31
    case sigma3 = 0x32
    case sigma2Resume = 0x33
    case statusReport = 0x40
    case icdCheckIn = 0x50
}

/// A Status Report (Core Appendix D).
public struct StatusReport: Hashable, Sendable, Error {
    /// General status codes (Appendix D.3.1).
    public enum GeneralCode: UInt16, Sendable {
        case success = 0
        case failure = 1
        case badPrecondition = 2
        case outOfRange = 3
        case badRequest = 4
        case unsupported = 5
        case unexpected = 6
        case resourceExhausted = 7
        case busy = 8
        case timeout = 9
        case `continue` = 10
        case aborted = 11
        case invalidArgument = 12
        case notFound = 13
        case alreadyExists = 14
        case permissionDenied = 15
        case dataLoss = 16
    }

    /// Secure Channel protocol codes (Core §4.11.1.4).
    public enum SecureChannelCode: UInt16, Sendable {
        case sessionEstablishmentSuccess = 0
        case noSharedTrustRoots = 1
        case invalidParameter = 2
        case closeSession = 3
        case busy = 4
    }

    public var generalCode: GeneralCode
    public var protocolID: ProtocolID
    public var vendorID: UInt16
    public var protocolCode: UInt16
    public var data: [UInt8]

    public init(generalCode: GeneralCode, protocolID: ProtocolID, vendorID: UInt16 = 0, protocolCode: UInt16, data: [UInt8] = []) {
        self.generalCode = generalCode
        self.protocolID = protocolID
        self.vendorID = vendorID
        self.protocolCode = protocolCode
        self.data = data
    }

    public static func secureChannel(_ general: GeneralCode, _ code: SecureChannelCode, data: [UInt8] = []) -> StatusReport {
        StatusReport(generalCode: general, protocolID: .secureChannel, protocolCode: code.rawValue, data: data)
    }

    public static let sessionEstablished = secureChannel(.success, .sessionEstablishmentSuccess)
    public static let invalidParameter = secureChannel(.failure, .invalidParameter)
    public static let noSharedTrustRoots = secureChannel(.failure, .noSharedTrustRoots)
    public static let closeSession = secureChannel(.success, .closeSession)

    public var isSuccess: Bool { generalCode == .success }

    public var encoded: [UInt8] {
        var out: [UInt8] = []
        out.appendLittleEndian(generalCode.rawValue)
        out.appendLittleEndian(protocolID.rawValue)
        out.appendLittleEndian(vendorID)
        out.appendLittleEndian(protocolCode)
        return out + data
    }

    public init(decoding bytes: [UInt8]) throws {
        var reader = ByteReader(bytes)
        guard let general = GeneralCode(rawValue: try reader.read(UInt16.self)) else { throw MessageError.truncated }
        let protocolID = ProtocolID(rawValue: try reader.read(UInt16.self))
        let vendorID = try reader.read(UInt16.self)
        let code = try reader.read(UInt16.self)
        self.init(generalCode: general, protocolID: protocolID, vendorID: vendorID, protocolCode: code,
                  data: Array(try reader.take(reader.remaining)))
    }
}
