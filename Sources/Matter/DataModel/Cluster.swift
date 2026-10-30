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
    /// The node's groups, for the Groups cluster.
    public var groups: Groups?

    public init(session: SessionInfo, isFabricFiltered: Bool = true, isTimed: Bool = false, exchange: Exchange? = nil, groups: Groups? = nil) {
        self.session = session
        self.isFabricFiltered = isFabricFiltered
        self.isTimed = isTimed
        self.exchange = exchange
        self.groups = groups
    }

    public var fabricIndex: FabricIndex? { session.fabricIndex }
}

/// The result of a command: a status, or a response command with its fields.
public enum InvokeResult: Sendable {
    case status(StatusError)
    case response(CommandID, TLVValue)

    public static let success = InvokeResult.status(StatusError(.success))
}

/// Reports attribute changes and records events; installed on a cluster when it is added to an endpoint.
public struct ChangeReporter: Sendable {
    let report: @Sendable (_ endpoint: EndpointNumber, _ cluster: ClusterID, _ attributes: [AttributeID]) -> Void
    let emit: @Sendable (_ endpoint: EndpointNumber, _ cluster: ClusterID, _ event: EventID, _ priority: EventDefinition.Priority,
                         _ data: TLVValue) async -> Void

    public init(report: @escaping @Sendable (EndpointNumber, ClusterID, [AttributeID]) -> Void,
                emit: @escaping @Sendable (EndpointNumber, ClusterID, EventID, EventDefinition.Priority, TLVValue) async -> Void = { _, _, _, _, _ in }) {
        self.report = report
        self.emit = emit
    }

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

/// Fabric-scoped lists (Core §7.13.6): each entry carries the FabricIndex of the fabric that wrote it.
public enum FabricScopedList {
    /// What a read returns: the accessing fabric's entries, and with filtering off the others' too, reduced to their
    /// FabricIndex so no fabric-sensitive field leaks (Core §8.4.3.2).
    public static func read(_ stored: TLVValue, context: AccessContext) -> TLVValue {
        guard case .array(let entries) = stored else { return stored }
        let own = context.fabricIndex.map(UInt64.init)
        return .array(entries.compactMap { entry in
            if entry.value[fabricIndexFieldTag]?.uint == own { return entry }
            guard !context.isFabricFiltered, let index = entry.value[fabricIndexFieldTag] else { return nil }
            return TLVElement(entry.tag, .structure([.field(fabricIndexFieldTag, index)]))
        })
    }

    /// The stored list after a write: the accessing fabric's entries replaced by the written ones, stamped with its
    /// FabricIndex whatever the writer put there.
    public static func merge(_ written: TLVValue, into stored: TLVValue, context: AccessContext) throws -> TLVValue {
        guard let fabric = context.fabricIndex, case .array(let entries) = written else { throw StatusError(.unsupportedAccess) }
        let stamped = try entries.map { entry -> TLVElement in
            guard case .structure(var fields) = entry.value else { throw StatusError(.constraintError) }
            fields.removeAll { $0.tag == .context(fabricIndexFieldTag) }
            fields.append(.field(fabricIndexFieldTag, .unsigned(UInt64(fabric))))
            return TLVElement(entry.tag, .structure(fields))
        }
        let others = (stored.elements ?? []).filter { $0.value[fabricIndexFieldTag]?.uint != UInt64(fabric) }
        return .array(others + stamped)
    }

    /// The entries of one fabric.
    public static func entries(_ stored: TLVValue, fabric: FabricIndex) -> [TLVElement] {
        (stored.elements ?? []).filter { $0.value[fabricIndexFieldTag]?.uint == UInt64(fabric) }
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
    /// The endpoint the cluster is on.
    public private(set) var endpoint: EndpointNumber = 0
    private var reporter = ChangeReporter.none

    /// A cluster with initial attribute values; attributes without a value are unsupported.
    public init(_ definition: ClusterDefinition, featureMap: UInt32 = 0, attributes: [AttributeID: TLVValue] = [:]) {
        self.definition = definition
        self.featureMap = featureMap
        values = attributes
        attributeIDs = attributes.keys.sorted()
    }

    /// Kept sorted as attributes are added.
    public private(set) var attributeIDs: [AttributeID] = []

    private func noteAttribute(_ id: AttributeID) {
        guard !attributeIDs.contains(id) else { return }
        attributeIDs.append(id)
        attributeIDs.sort()
    }
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

    /// Several command handlers at once.
    public func handle(_ handlers: [CommandID: CommandHandler]) { commands.merge(handlers) { $1 } }

    /// Called before a write is stored; throw to reject it, or store something else with `set`.
    public func onWrite(_ hook: @escaping WriteHook) { writeHook = hook }

    /// An attribute computed on each read.
    public func provide(_ attribute: AttributeID, _ reader: @escaping @Sendable (AccessContext) async throws -> TLVValue) {
        readers[attribute] = reader
        noteAttribute(attribute)
    }

    public func setFeatureMap(_ featureMap: UInt32) { self.featureMap = featureMap }

    // MARK: - Values

    public func value(_ attribute: AttributeID) -> TLVValue? { values[attribute] }

    /// Stores attribute values, reporting them (and bumping the data version) when they change.
    public func set(_ updates: [AttributeID: TLVValue]) {
        let changed = updates.filter { values[$0.key] != $0.value }
        guard !changed.isEmpty else { return }
        values.merge(changed) { $1 }
        for id in changed.keys { noteAttribute(id) }
        dataVersion &+= 1
        reporter.report(endpoint, definition.id, Array(changed.keys))
    }

    public func set(_ attribute: AttributeID, _ value: TLVValue) { set([attribute: value]) }

    /// Records one of the cluster's events (Core §7.14), at the priority its definition gives unless told otherwise.
    public func emit(_ event: EventID, data: TLVValue, priority: EventDefinition.Priority? = nil) async {
        await reporter.emit(endpoint, definition.id, event, priority ?? definition.event(event)?.priority ?? .info, data)
    }

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
        if definition.attribute(attribute)?.flags.contains(.fabricScoped) == true {
            return FabricScopedList.read(value, context: context)
        }
        return value
    }

    public func write(_ attribute: AttributeID, value: TLVValue, context: AccessContext) async throws {
        guard values[attribute] != nil || readers[attribute] != nil else { throw StatusError(.unsupportedAttribute) }
        var value = value
        if definition.attribute(attribute)?.flags.contains(.fabricScoped) == true {
            value = try FabricScopedList.merge(value, into: values[attribute] ?? .array([]), context: context)
        }
        if let writeHook { try await writeHook(self, attribute, value, context) }
        if readers[attribute] == nil { set(attribute, value) }
    }

    public func invoke(_ command: CommandID, fields: TLVValue, context: AccessContext) async throws -> InvokeResult {
        guard let handler = commands[command] else { throw StatusError(.unsupportedCommand) }
        return try await handler(self, fields, context)
    }
}
