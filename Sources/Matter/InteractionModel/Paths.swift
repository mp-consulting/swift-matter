/// Interaction Model paths and information blocks (Core §10.6).

/// Interaction Model opcodes (Core §10.2.1).
public enum IMOpcode: UInt8, Sendable {
    case statusResponse = 0x01
    case readRequest = 0x02
    case subscribeRequest = 0x03
    case subscribeResponse = 0x04
    case reportData = 0x05
    case writeRequest = 0x06
    case writeResponse = 0x07
    case invokeRequest = 0x08
    case invokeResponse = 0x09
    case timedRequest = 0x0A
}

/// The InteractionModelRevision field every action carries (tag 0xFF).
let interactionModelRevisionTag: UInt8 = 0xFF

/// An attribute path; nil fields are wildcards (AttributePathIB, Core §10.6.2).
public struct AttributePath: Hashable, Sendable, CustomStringConvertible {
    public enum ListIndex: Hashable, Sendable {
        /// Append to the list (a null ListIndex).
        case append
    }

    public var endpoint: EndpointNumber?
    public var cluster: ClusterID?
    public var attribute: AttributeID?
    public var listIndex: ListIndex?

    public init(endpoint: EndpointNumber? = nil, cluster: ClusterID? = nil, attribute: AttributeID? = nil, listIndex: ListIndex? = nil) {
        self.endpoint = endpoint
        self.cluster = cluster
        self.attribute = attribute
        self.listIndex = listIndex
    }

    public var isConcrete: Bool { endpoint != nil && cluster != nil && attribute != nil }

    public var description: String {
        func part<T: BinaryInteger>(_ value: T?) -> String { value.map { "0x" + String($0, radix: 16) } ?? "*" }
        return "\(part(endpoint))/\(part(cluster))/\(part(attribute))" + (listIndex == .append ? "[+]" : "")
    }

    public func matches(endpoint: EndpointNumber, cluster: ClusterID, attribute: AttributeID) -> Bool {
        (self.endpoint ?? endpoint) == endpoint && (self.cluster ?? cluster) == cluster && (self.attribute ?? attribute) == attribute
    }

    var tlv: TLVValue {
        var fields: [TLVElement] = []
        if let endpoint { fields.append(.field(2, .unsigned(UInt64(endpoint)))) }
        if let cluster { fields.append(.field(3, .unsigned(UInt64(cluster)))) }
        if let attribute { fields.append(.field(4, .unsigned(UInt64(attribute)))) }
        if listIndex == .append { fields.append(.field(5, .null)) }
        return .list(fields)
    }

    init(tlv value: TLVValue) throws {
        guard case .list(let elements) = value else { throw StatusError(.invalidAction) }
        func field(_ tag: UInt8) -> TLVValue? { elements.first { $0.tag == .context(tag) }?.value }
        // A node id (tag 1) other than this node's is not supported; wildcard paths carry none.
        endpoint = try field(2).map { try narrow($0) }
        cluster = try field(3).map { try narrow($0) }
        attribute = try field(4).map { try narrow($0) }
        switch field(5) {
        case nil: listIndex = nil
        case .null: listIndex = .append
        default: throw StatusError(.invalidAction) // Indexed list access is not supported (Core §8.9.2.4).
        }
        // Tag compression and wildcard path flags (tags 0, 6, 7) only change encoding and filtering hints.
    }
}

/// A command path (CommandPathIB, Core §10.6.11).
public struct CommandPath: Hashable, Sendable {
    public var endpoint: EndpointNumber?
    public var cluster: ClusterID
    public var command: CommandID

    public init(endpoint: EndpointNumber?, cluster: ClusterID, command: CommandID) {
        self.endpoint = endpoint
        self.cluster = cluster
        self.command = command
    }

    var tlv: TLVValue {
        var fields: [TLVElement] = []
        if let endpoint { fields.append(.field(0, .unsigned(UInt64(endpoint)))) }
        fields.append(.field(1, .unsigned(UInt64(cluster))))
        fields.append(.field(2, .unsigned(UInt64(command))))
        return .list(fields)
    }

    init(tlv value: TLVValue) throws {
        guard case .list(let elements) = value else { throw StatusError(.invalidAction) }
        func field(_ tag: UInt8) -> TLVValue? { elements.first { $0.tag == .context(tag) }?.value }
        endpoint = try field(0).map { try narrow($0) }
        guard let cluster = field(1), let command = field(2) else { throw StatusError(.invalidAction) }
        self.cluster = try narrow(cluster)
        self.command = try narrow(command)
    }
}

/// An event path; nil fields are wildcards (EventPathIB, Core §10.6.8).
public struct EventPath: Hashable, Sendable {
    public var endpoint: EndpointNumber?
    public var cluster: ClusterID?
    public var event: EventID?
    public var isUrgent: Bool

    public init(endpoint: EndpointNumber? = nil, cluster: ClusterID? = nil, event: EventID? = nil, isUrgent: Bool = false) {
        self.endpoint = endpoint
        self.cluster = cluster
        self.event = event
        self.isUrgent = isUrgent
    }

    public func matches(_ record: EventRecord) -> Bool {
        (endpoint ?? record.endpoint) == record.endpoint && (cluster ?? record.cluster) == record.cluster
            && (event ?? record.event) == record.event
    }

    var tlv: TLVValue {
        var fields: [TLVElement] = []
        if let endpoint { fields.append(.field(1, .unsigned(UInt64(endpoint)))) }
        if let cluster { fields.append(.field(2, .unsigned(UInt64(cluster)))) }
        if let event { fields.append(.field(3, .unsigned(UInt64(event)))) }
        if isUrgent { fields.append(.field(4, .bool(true))) }
        return .list(fields)
    }

    init(tlv value: TLVValue) throws {
        guard case .list(let elements) = value else { throw StatusError(.invalidAction) }
        func field(_ tag: UInt8) -> TLVValue? { elements.first { $0.tag == .context(tag) }?.value }
        endpoint = try field(1).map { try narrow($0) }
        cluster = try field(2).map { try narrow($0) }
        event = try field(3).map { try narrow($0) }
        isUrgent = field(4)?.bool ?? false
    }

    static func concrete(_ record: EventRecord) -> EventPath {
        EventPath(endpoint: record.endpoint, cluster: record.cluster, event: record.event)
    }
}

/// A data version filter (DataVersionFilterIB, Core §10.6.3).
public struct DataVersionFilter: Hashable, Sendable {
    public var endpoint: EndpointNumber
    public var cluster: ClusterID
    public var version: UInt32

    init(tlv value: TLVValue) throws {
        let fields = try TLVStruct(value)
        guard case .list(let path) = fields[0] ?? .null else { throw StatusError(.invalidAction) }
        func field(_ tag: UInt8) -> TLVValue? { path.first { $0.tag == .context(tag) }?.value }
        guard let endpoint = field(1), let cluster = field(2) else { throw StatusError(.invalidAction) }
        self.endpoint = try narrow(endpoint)
        self.cluster = try narrow(cluster)
        version = try fields.uint(1, as: UInt32.self)
    }

    public init(endpoint: EndpointNumber, cluster: ClusterID, version: UInt32) {
        self.endpoint = endpoint
        self.cluster = cluster
        self.version = version
    }

    var tlv: TLVValue {
        .structure([
            .field(0, .list([.field(1, .unsigned(UInt64(endpoint))), .field(2, .unsigned(UInt64(cluster)))])),
            .field(1, .unsigned(UInt64(version))),
        ])
    }
}

/// An attribute's value or status in a report (AttributeReportIB, Core §10.6.5).
public enum AttributeReport: Sendable {
    case data(path: AttributePath, dataVersion: UInt32, value: TLVValue)
    case status(path: AttributePath, StatusError)

    var tlv: TLVValue {
        switch self {
        case .data(let path, let version, let value):
            .structure([.field(1, .structure([
                .field(0, .unsigned(UInt64(version))), .field(1, path.tlv), TLVElement(.context(2), value),
            ]))])
        case .status(let path, let status):
            .structure([.field(0, .structure([.field(0, path.tlv), .field(1, status.tlv)]))])
        }
    }

    init(tlv value: TLVValue) throws {
        let fields = try TLVStruct(value)
        if let data = fields[1] {
            let data = try TLVStruct(data)
            guard let path = data[1], let value = data[2] else { throw TLVError.field(1) }
            self = .data(path: try AttributePath(tlv: path), dataVersion: UInt32(truncatingIfNeeded: (try? data.uint(0)) ?? 0), value: value)
        } else {
            let status = try fields.structure(0)
            guard let path = status[0], let statusValue = status[1] else { throw TLVError.field(0) }
            self = .status(path: try AttributePath(tlv: path), try StatusError(tlv: statusValue))
        }
    }
}

/// An event in a report (EventReportIB, Core §10.6.10).
public enum EventReport: Sendable {
    case data(EventRecord)
    case status(path: EventPath, StatusError)

    var tlv: TLVValue {
        switch self {
        case .data(let record):
            .structure([.field(1, .structure([
                .field(0, EventPath.concrete(record).tlv), .field(1, .unsigned(record.number)),
                .field(2, .unsigned(UInt64(record.priority.rawValue))), .field(3, .unsigned(record.timestamp)),
                TLVElement(.context(7), record.data),
            ]))])
        case .status(let path, let status):
            .structure([.field(0, .structure([.field(0, path.tlv), .field(1, status.tlv)]))])
        }
    }

    init(tlv value: TLVValue) throws {
        let fields = try TLVStruct(value)
        if let data = fields[1] {
            let data = try TLVStruct(data)
            guard let pathValue = data[0] else { throw TLVError.field(0) }
            let path = try EventPath(tlv: pathValue)
            self = .data(EventRecord(
                number: try data.uint(1), endpoint: path.endpoint ?? 0, cluster: path.cluster ?? 0, event: path.event ?? 0,
                priority: EventDefinition.Priority(rawValue: UInt8(truncatingIfNeeded: try data.uint(2))) ?? .info,
                timestamp: (try? data.uint(3)) ?? 0, data: data[7] ?? .null, fabricIndex: nil))
        } else {
            let status = try fields.structure(0)
            guard let path = status[0], let statusValue = status[1] else { throw TLVError.field(0) }
            self = .status(path: try EventPath(tlv: path), try StatusError(tlv: statusValue))
        }
    }
}

/// Narrows an unsigned TLV value, rejecting the path when it does not fit.
func narrow<T: FixedWidthInteger & UnsignedInteger>(_ value: TLVValue) throws -> T {
    guard let raw = value.uint, let narrowed = T(exactly: raw) else { throw StatusError(.invalidAction) }
    return narrowed
}
