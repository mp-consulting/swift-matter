/// Cluster instances on endpoints, as the Interaction Model sees them.

/// Who is accessing the data model, and how.
public struct AccessContext: Sendable {
    public var session: SessionInfo
    /// Fabric-filtered reads see only the accessing fabric's entries of fabric-scoped lists.
    public var isFabricFiltered: Bool
    /// Set when the write or invoke came after a Timed Request.
    public var isTimed: Bool
    /// The exchange, for clusters that need to know the peer (commissioning).
    public var exchange: Exchange?

    public init(session: SessionInfo, isFabricFiltered: Bool = true, isTimed: Bool = false, exchange: Exchange? = nil) {
        self.session = session
        self.isFabricFiltered = isFabricFiltered
        self.isTimed = isTimed
        self.exchange = exchange
    }

    public var fabricIndex: FabricIndex? { session.fabricIndex }
}

/// The result of a command: a status, or a response command with its fields.
public enum InvokeResult: Sendable {
    case status(StatusError)
    case response(CommandID, TLVValue)

    public static let success = InvokeResult.status(StatusError(.success))
}

/// Reports attribute changes to subscriptions; installed on a cluster when it is added to an endpoint.
public struct ChangeReporter: Sendable {
    let report: @Sendable (_ endpoint: EndpointNumber, _ cluster: ClusterID, _ attributes: [AttributeID]) -> Void

    public init(report: @escaping @Sendable (EndpointNumber, ClusterID, [AttributeID]) -> Void) { self.report = report }

    public static let none = ChangeReporter { _, _, _ in }
}

/// A server cluster on an endpoint. `AttributeCluster` implements it for clusters that are mostly stored data;
/// clusters with their own logic implement it directly.
public protocol ClusterHandler: Sendable {
    var definition: ClusterDefinition { get }
    var featureMap: UInt32 { get async }
    /// The attributes this instance supports (global attributes excluded).
    var attributeIDs: [AttributeID] { get async }
    var acceptedCommands: [CommandID] { get async }
    var generatedCommands: [CommandID] { get async }
    var dataVersion: UInt32 { get async }

    /// Called once when the cluster is placed on an endpoint.
    func attach(endpoint: EndpointNumber, reporter: ChangeReporter) async
    func read(_ attribute: AttributeID, context: AccessContext) async throws -> TLVValue
    func write(_ attribute: AttributeID, value: TLVValue, context: AccessContext) async throws
    func invoke(_ command: CommandID, fields: TLVValue, context: AccessContext) async throws -> InvokeResult
}

extension ClusterHandler {
    public var id: ClusterID { definition.id }

    /// A global attribute's value (Core §7.13).
    func readGlobal(_ attribute: AttributeID) async -> TLVValue? {
        func ids(_ values: [UInt32]) -> TLVValue { .array(values.map { TLVElement(.unsigned(UInt64($0))) }) }
        switch attribute {
        case GlobalAttribute.clusterRevision: return .unsigned(UInt64(definition.revision))
        case GlobalAttribute.featureMap: return .unsigned(UInt64(await featureMap))
        case GlobalAttribute.attributeList: return ids(await attributeIDs + GlobalAttribute.all)
        case GlobalAttribute.acceptedCommandList: return ids(await acceptedCommands)
        case GlobalAttribute.generatedCommandList: return ids(await generatedCommands)
        default: return nil
        }
    }
}

/// A cluster backed by stored attribute values, with hooks for writes and closures for commands.
public actor AttributeCluster: ClusterHandler {
    public typealias CommandHandler = @Sendable (_ cluster: AttributeCluster, _ fields: TLVValue, _ context: AccessContext) async throws -> InvokeResult
    public typealias WriteHook = @Sendable (_ cluster: AttributeCluster, _ attribute: AttributeID, _ value: TLVValue, _ context: AccessContext) async throws -> Void

    public nonisolated let definition: ClusterDefinition
    public private(set) var featureMap: UInt32
    private var values: [AttributeID: TLVValue]
    private var readers: [AttributeID: @Sendable (AccessContext) async throws -> TLVValue] = [:]
    private var commands: [CommandID: CommandHandler] = [:]
    private var writeHook: WriteHook?
    public private(set) var dataVersion = UInt32.random(in: 0...UInt32.max)
    private var endpoint: EndpointNumber = 0
    private var reporter = ChangeReporter.none

    /// A cluster with initial attribute values; attributes without a value are unsupported.
    public init(_ definition: ClusterDefinition, featureMap: UInt32 = 0, attributes: [AttributeID: TLVValue] = [:]) {
        self.definition = definition
        self.featureMap = featureMap
        values = attributes
    }

    public var attributeIDs: [AttributeID] { (Array(values.keys) + Array(readers.keys)).sorted() }
    public var acceptedCommands: [CommandID] { commands.keys.sorted() }
    public var generatedCommands: [CommandID] {
        Set(commands.keys.compactMap { definition.command($0)?.response }).sorted()
    }

    public func attach(endpoint: EndpointNumber, reporter: ChangeReporter) {
        self.endpoint = endpoint
        self.reporter = reporter
    }

    // MARK: - Configuration

    public func handle(_ command: CommandID, _ handler: @escaping CommandHandler) { commands[command] = handler }

    /// Called before a write is stored; throw to reject it, or store something else with `set`.
    public func onWrite(_ hook: @escaping WriteHook) { writeHook = hook }

    /// An attribute computed on each read.
    public func provide(_ attribute: AttributeID, _ reader: @escaping @Sendable (AccessContext) async throws -> TLVValue) {
        readers[attribute] = reader
    }

    public func setFeatureMap(_ featureMap: UInt32) { self.featureMap = featureMap }

    // MARK: - Values

    public func value(_ attribute: AttributeID) -> TLVValue? { values[attribute] }

    /// Stores attribute values, reporting them (and bumping the data version) when they change.
    public func set(_ updates: [AttributeID: TLVValue]) {
        let changed = updates.filter { values[$0.key] != $0.value }
        guard !changed.isEmpty else { return }
        values.merge(changed) { $1 }
        dataVersion &+= 1
        reporter.report(endpoint, definition.id, Array(changed.keys))
    }

    public func set(_ attribute: AttributeID, _ value: TLVValue) { set([attribute: value]) }

    /// Reports a computed attribute as changed.
    public func changed(_ attributes: [AttributeID]) {
        dataVersion &+= 1
        reporter.report(endpoint, definition.id, attributes)
    }

    // MARK: - ClusterHandler

    public func read(_ attribute: AttributeID, context: AccessContext) async throws -> TLVValue {
        if let global = await readGlobal(attribute) { return global }
        if let reader = readers[attribute] { return try await reader(context) }
        guard let value = values[attribute] else { throw StatusError(.unsupportedAttribute) }
        if definition.attribute(attribute)?.flags.contains(.fabricScoped) == true, context.isFabricFiltered,
           case .array(let entries) = value {
            return .array(entries.filter { $0.value[fabricIndexFieldTag]?.uint == context.fabricIndex.map(UInt64.init) })
        }
        return value
    }

    public func write(_ attribute: AttributeID, value: TLVValue, context: AccessContext) async throws {
        guard values[attribute] != nil || readers[attribute] != nil else { throw StatusError(.unsupportedAttribute) }
        var value = value
        if definition.attribute(attribute)?.flags.contains(.fabricScoped) == true {
            // A fabric-scoped list write replaces only the accessing fabric's entries (Core §7.13.6).
            guard let fabric = context.fabricIndex, case .array(let written) = value else { throw StatusError(.unsupportedAccess) }
            let stamped = written.map { entry -> TLVElement in
                guard case .structure(var fields) = entry.value else { return entry }
                fields.removeAll { $0.tag == .context(fabricIndexFieldTag) }
                fields.append(.field(fabricIndexFieldTag, .unsigned(UInt64(fabric))))
                return TLVElement(entry.tag, .structure(fields))
            }
            let others = (values[attribute]?.elements ?? []).filter { $0.value[fabricIndexFieldTag]?.uint != UInt64(fabric) }
            value = .array(others + stamped)
        }
        if let writeHook { try await writeHook(self, attribute, value, context) }
        if readers[attribute] == nil { set(attribute, value) }
    }

    public func invoke(_ command: CommandID, fields: TLVValue, context: AccessContext) async throws -> InvokeResult {
        guard let handler = commands[command] else { throw StatusError(.unsupportedCommand) }
        return try await handler(self, fields, context)
    }
}
