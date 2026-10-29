/// Matter message frames (Core §4.4).

/// Protocol identifiers (Core §2.5.6).
public struct ProtocolID: RawRepresentable, Hashable, Sendable, CustomStringConvertible {
    public let rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }

    public static let secureChannel = ProtocolID(rawValue: 0x0000)
    public static let interactionModel = ProtocolID(rawValue: 0x0001)
    public static let bdx = ProtocolID(rawValue: 0x0002)
    public static let userDirectedCommissioning = ProtocolID(rawValue: 0x0003)

    public var description: String { "0x" + zeroPadded(rawValue, width: 4, radix: 16) }
}

public enum MessageError: Error, Equatable, Sendable {
    case truncated
    case unsupportedVersion
    case invalidDestination
    case invalidSessionType
    case authenticationFailed
    case unknownSession(UInt16)
    case privacyUnsupported
    case unknownStatus(UInt16)
}

/// The unencrypted message header (Core §4.4.1); it is the additional data of the AEAD.
public struct MessageHeader: Hashable, Sendable {
    public enum Destination: Hashable, Sendable {
        case none
        case node(UInt64)
        case group(UInt16)
    }

    public enum SessionType: UInt8, Sendable {
        case unicast = 0
        case group = 1
    }

    public var sessionID: UInt16
    public var sessionType: SessionType
    /// The C flag: a control message, counted with the control counter.
    public var isControl: Bool
    public var privacy: Bool
    public var counter: UInt32
    public var source: UInt64?
    public var destination: Destination

    public init(sessionID: UInt16, sessionType: SessionType = .unicast, isControl: Bool = false, privacy: Bool = false,
                counter: UInt32, source: UInt64? = nil, destination: Destination = .none) {
        self.sessionID = sessionID
        self.sessionType = sessionType
        self.isControl = isControl
        self.privacy = privacy
        self.counter = counter
        self.source = source
        self.destination = destination
    }

    /// Unsecured messages use session 0 of the unicast type.
    public var isUnsecured: Bool { sessionID == 0 && sessionType == .unicast }

    public var securityFlags: UInt8 {
        (privacy ? 0x80 : 0) | (isControl ? 0x40 : 0) | sessionType.rawValue
    }

    public var encoded: [UInt8] {
        var out: [UInt8] = []
        let destinationSize: UInt8 = switch destination {
        case .none: 0
        case .node: 1
        case .group: 2
        }
        out.append((source != nil ? 0x04 : 0) | destinationSize)
        out.appendLittleEndian(sessionID)
        out.append(securityFlags)
        out.appendLittleEndian(counter)
        if let source { out.appendLittleEndian(source) }
        switch destination {
        case .none: break
        case .node(let node): out.appendLittleEndian(node)
        case .group(let group): out.appendLittleEndian(group)
        }
        return out
    }

    /// Decodes the header at the start of `bytes`, returning it and its length (extensions included).
    public static func decode(_ bytes: [UInt8]) throws -> (MessageHeader, Int) {
        var reader = ByteReader(bytes, truncated: MessageError.truncated)
        let flags = try reader.read(UInt8.self)
        guard flags >> 4 == 0 else { throw MessageError.unsupportedVersion }
        let sessionID = try reader.read(UInt16.self)
        let security = try reader.read(UInt8.self)
        guard let sessionType = SessionType(rawValue: security & 0x03) else { throw MessageError.invalidSessionType }
        let counter = try reader.read(UInt32.self)
        let source = flags & 0x04 != 0 ? try reader.read(UInt64.self) : nil
        let destination: Destination
        switch flags & 0x03 {
        case 0: destination = .none
        case 1: destination = .node(try reader.read(UInt64.self))
        case 2: destination = .group(try reader.read(UInt16.self))
        default: throw MessageError.invalidDestination
        }
        if security & 0x20 != 0 {
            // Message extensions: skipped by version 1.0 nodes.
            let length = Int(try reader.read(UInt16.self))
            _ = try reader.take(length)
        }
        let header = MessageHeader(sessionID: sessionID, sessionType: sessionType, isControl: security & 0x40 != 0,
                                   privacy: security & 0x80 != 0, counter: counter, source: source, destination: destination)
        return (header, reader.offset)
    }

    /// The AEAD nonce (Core §4.8.1.1): security flags, counter and the source node id, little-endian.
    func nonce(sourceNodeID: UInt64) -> [UInt8] {
        var nonce: [UInt8] = [securityFlags]
        nonce.appendLittleEndian(counter)
        nonce.appendLittleEndian(sourceNodeID)
        return nonce
    }
}

/// The protocol header (Core §4.4.3), encrypted in secure sessions.
public struct PayloadHeader: Hashable, Sendable {
    public var isInitiator: Bool
    public var needsAck: Bool
    public var ackedCounter: UInt32?
    public var opcode: UInt8
    public var exchangeID: UInt16
    public var protocolID: ProtocolID
    public var vendorID: UInt16?

    public init(isInitiator: Bool, needsAck: Bool, ackedCounter: UInt32? = nil, opcode: UInt8, exchangeID: UInt16,
                protocolID: ProtocolID, vendorID: UInt16? = nil) {
        self.isInitiator = isInitiator
        self.needsAck = needsAck
        self.ackedCounter = ackedCounter
        self.opcode = opcode
        self.exchangeID = exchangeID
        self.protocolID = protocolID
        self.vendorID = vendorID
    }

    public var encoded: [UInt8] {
        var out: [UInt8] = [
            (isInitiator ? 0x01 : 0) | (ackedCounter != nil ? 0x02 : 0) | (needsAck ? 0x04 : 0) | (vendorID != nil ? 0x10 : 0),
            opcode,
        ]
        out.appendLittleEndian(exchangeID)
        if let vendorID { out.appendLittleEndian(vendorID) }
        out.appendLittleEndian(protocolID.rawValue)
        if let ackedCounter { out.appendLittleEndian(ackedCounter) }
        return out
    }

    public static func decode(_ bytes: [UInt8]) throws -> (PayloadHeader, Int) {
        var reader = ByteReader(bytes, truncated: MessageError.truncated)
        let flags = try reader.read(UInt8.self)
        let opcode = try reader.read(UInt8.self)
        let exchangeID = try reader.read(UInt16.self)
        let vendorID = flags & 0x10 != 0 ? try reader.read(UInt16.self) : nil
        let protocolID = ProtocolID(rawValue: try reader.read(UInt16.self))
        let ackedCounter = flags & 0x02 != 0 ? try reader.read(UInt32.self) : nil
        if flags & 0x08 != 0 {
            // Secured extensions: skipped by version 1.0 nodes.
            let length = Int(try reader.read(UInt16.self))
            _ = try reader.take(length)
        }
        let header = PayloadHeader(isInitiator: flags & 0x01 != 0, needsAck: flags & 0x04 != 0, ackedCounter: ackedCounter,
                                   opcode: opcode, exchangeID: exchangeID, protocolID: protocolID, vendorID: vendorID)
        return (header, reader.offset)
    }
}

/// A decoded message: its headers and application payload.
public struct Message: Sendable {
    public var header: MessageHeader
    public var payloadHeader: PayloadHeader
    public var payload: [UInt8]

    public init(header: MessageHeader, payloadHeader: PayloadHeader, payload: [UInt8]) {
        self.header = header
        self.payloadHeader = payloadHeader
        self.payload = payload
    }

    /// The frame of an unsecured message.
    public var unsecuredFrame: [UInt8] { header.encoded + payloadHeader.encoded + payload }

    /// The frame encrypted with a session key: the header in clear as additional data, the rest sealed.
    public func sealedFrame(key: AESCCM, nonceSourceNodeID: UInt64) throws -> [UInt8] {
        let aad = header.encoded
        return aad + (try key.seal(payloadHeader.encoded + payload, nonce: header.nonce(sourceNodeID: nonceSourceNodeID), additionalData: aad))
    }

    /// Decodes the protocol header and payload of an unsecured message's remaining bytes.
    public init(header: MessageHeader, plaintext: [UInt8]) throws {
        let (payloadHeader, length) = try PayloadHeader.decode(plaintext)
        self.init(header: header, payloadHeader: payloadHeader, payload: Array(plaintext[length...]))
    }

    /// Opens a secure frame whose header has been decoded.
    public static func open(frame: [UInt8], header: MessageHeader, headerLength: Int, key: AESCCM, nonceSourceNodeID: UInt64) throws -> Message {
        let plaintext: [UInt8]
        do {
            plaintext = try key.open(Array(frame[headerLength...]), nonce: header.nonce(sourceNodeID: nonceSourceNodeID),
                                     additionalData: Array(frame[..<headerLength]))
        } catch {
            throw MessageError.authenticationFailed
        }
        return try Message(header: header, plaintext: plaintext)
    }
}
