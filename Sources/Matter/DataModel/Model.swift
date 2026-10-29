/// The data model's identifiers and metadata (Core §7).

public typealias ClusterID = UInt32
public typealias AttributeID = UInt32
public typealias CommandID = UInt32
public typealias EventID = UInt32
public typealias EndpointNumber = UInt16
public typealias FabricIndex = UInt8
public typealias NodeID = UInt64

/// Access privileges, from least to most (Core §6.6.2.1).
public enum Privilege: UInt8, Comparable, Sendable {
    case view = 1
    case proxyView = 2
    case operate = 3
    case manage = 4
    case administer = 5

    public static func < (lhs: Privilege, rhs: Privilege) -> Bool { lhs.rawValue < rhs.rawValue }

    /// Whether holding this privilege grants `required` (Administer grants everything, Manage grants Operate...).
    public func grants(_ required: Privilege) -> Bool {
        // ProxyView is granted only by itself and Administer (Core §6.6.2.1).
        if required == .proxyView { return self == .proxyView || self == .administer }
        if self == .proxyView { return required == .view }
        return self >= required
    }
}

/// Interaction Model status codes (Core §8.10).
public enum IMStatus: UInt8, Sendable, Error {
    case success = 0x00
    case failure = 0x01
    case invalidSubscription = 0x7D
    case unsupportedAccess = 0x7E
    case unsupportedEndpoint = 0x7F
    case invalidAction = 0x80
    case unsupportedCommand = 0x81
    case invalidCommand = 0x85
    case unsupportedAttribute = 0x86
    case constraintError = 0x87
    case unsupportedWrite = 0x88
    case resourceExhausted = 0x89
    case notFound = 0x8B
    case unreportableAttribute = 0x8C
    case invalidDataType = 0x8D
    case unsupportedRead = 0x8F
    case dataVersionMismatch = 0x92
    case timeout = 0x94
    case unsupportedNode = 0x9B
    case busy = 0x9C
    case accessRestricted = 0x9D
    case unsupportedCluster = 0xC3
    case noUpstreamSubscription = 0xC5
    case needsTimedInteraction = 0xC6
    case unsupportedEvent = 0xC7
    case pathsExhausted = 0xC8
    case timedRequestMismatch = 0xC9
    case failsafeRequired = 0xCA
    case invalidInState = 0xCB
    case noCommandResponse = 0xCC
    case termsAndConditionsChanged = 0xCD
    case maintenanceRequired = 0xCE
    case dynamicConstraintError = 0xCF
    case alreadyExists = 0xD0
    case invalidTransportType = 0xD1
}

/// A status with an optional cluster-specific code (StatusIB, Core §10.6.17).
public struct StatusError: Error, Hashable, Sendable {
    public var status: IMStatus
    public var clusterStatus: UInt8?

    public init(_ status: IMStatus, clusterStatus: UInt8? = nil) {
        self.status = status
        self.clusterStatus = clusterStatus
    }

    var tlv: TLVValue {
        var fields: [TLVElement] = [.field(0, .unsigned(UInt64(status.rawValue)))]
        if let clusterStatus { fields.append(.field(1, .unsigned(UInt64(clusterStatus)))) }
        return .structure(fields)
    }

    init(tlv value: TLVValue) throws {
        let fields = try TLVStruct(value)
        guard let status = IMStatus(rawValue: try fields.uint(0, as: UInt8.self)) else { throw TLVError.field(0) }
        self.init(status, clusterStatus: try? fields.uint(1, as: UInt8.self))
    }
}

/// What the specification says about an attribute.
public struct AttributeDefinition: Sendable {
    public struct Flags: OptionSet, Sendable {
        public let rawValue: UInt16
        public init(rawValue: UInt16) { self.rawValue = rawValue }

        public static let list = Flags(rawValue: 1 << 0)
        /// Entries carry a FabricIndex (field 254) and are filtered per fabric.
        public static let fabricScoped = Flags(rawValue: 1 << 1)
        public static let fabricSensitive = Flags(rawValue: 1 << 2)
        public static let timedWrite = Flags(rawValue: 1 << 3)
        public static let nullable = Flags(rawValue: 1 << 4)
        public static let fixed = Flags(rawValue: 1 << 5)
        public static let changesOmitted = Flags(rawValue: 1 << 6)
        public static let nonVolatile = Flags(rawValue: 1 << 7)
    }

    public var id: AttributeID
    public var name: String
    public var type: String
    public var read: Privilege
    /// Nil when the attribute is read-only.
    public var write: Privilege?
    public var flags: Flags

    public init(id: AttributeID, name: String, type: String, read: Privilege, write: Privilege? = nil, flags: Flags) {
        self.id = id
        self.name = name
        self.type = type
        self.read = read
        self.write = write
        self.flags = flags
    }
}

public struct CommandDefinition: Sendable {
    public var id: CommandID
    public var name: String
    public var invoke: Privilege
    public var timed: Bool
    public var fabricScoped: Bool
    /// The response command's id, or nil when the response is a status.
    public var response: CommandID?
}

public struct EventDefinition: Sendable {
    public enum Priority: UInt8, Sendable {
        case debug = 0
        case info = 1
        case critical = 2
    }

    public var id: EventID
    public var name: String
    public var priority: Priority
    public var read: Privilege
    public var fabricSensitive: Bool
}

public struct ClusterDefinition: Sendable {
    public let id: ClusterID
    public let name: String
    public let revision: UInt16
    public let attributes: [AttributeDefinition]
    public let commands: [CommandDefinition]
    public let events: [EventDefinition]
    private let attributeIndex: [AttributeID: AttributeDefinition]
    private let commandIndex: [CommandID: CommandDefinition]

    public init(id: ClusterID, name: String, revision: UInt16, attributes: [AttributeDefinition], commands: [CommandDefinition],
                events: [EventDefinition]) {
        self.id = id
        self.name = name
        self.revision = revision
        self.attributes = attributes
        self.commands = commands
        self.events = events
        attributeIndex = Dictionary(attributes.map { ($0.id, $0) }) { first, _ in first }
        commandIndex = Dictionary(commands.map { ($0.id, $0) }) { first, _ in first }
    }

    public func attribute(_ id: AttributeID) -> AttributeDefinition? { attributeIndex[id] }
    public func command(_ id: CommandID) -> CommandDefinition? { commandIndex[id] }
    public func event(_ id: EventID) -> EventDefinition? { events.first { $0.id == id } }
}

public struct DeviceType: Hashable, Sendable {
    public var id: UInt32
    public var revision: UInt16
    public var name: String
    public var requiredServerClusters: [ClusterID]

    public init(id: UInt32, revision: UInt16, name: String, requiredServerClusters: [ClusterID] = []) {
        self.id = id
        self.revision = revision
        self.name = name
        self.requiredServerClusters = requiredServerClusters
    }
}

/// The global attributes every cluster has (Core §7.13).
public enum GlobalAttribute {
    public static let generatedCommandList: AttributeID = 0xFFF8
    public static let acceptedCommandList: AttributeID = 0xFFF9
    public static let attributeList: AttributeID = 0xFFFB
    public static let featureMap: AttributeID = 0xFFFC
    public static let clusterRevision: AttributeID = 0xFFFD

    static let all: [AttributeID] = [generatedCommandList, acceptedCommandList, attributeList, featureMap, clusterRevision]
}

/// The FabricIndex field of fabric-scoped structs (Core §7.13.6).
public let fabricIndexFieldTag: UInt8 = 0xFE
