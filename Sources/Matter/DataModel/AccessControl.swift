/// Access control (Core §6.6): which privilege a session holds on an endpoint's cluster.

/// An Access Control List entry (AccessControlEntryStruct, Core §9.10.5.4).
public struct AccessControlEntry: Hashable, Sendable {
    public enum AuthMode: UInt8, Sendable {
        case pase = 1
        case `case` = 2
        case group = 3
    }

    public struct Target: Hashable, Sendable {
        public var cluster: ClusterID?
        public var endpoint: EndpointNumber?
        public var deviceType: UInt32?

        public init(cluster: ClusterID? = nil, endpoint: EndpointNumber? = nil, deviceType: UInt32? = nil) {
            self.cluster = cluster
            self.endpoint = endpoint
            self.deviceType = deviceType
        }
    }

    public var fabricIndex: FabricIndex
    public var privilege: Privilege
    public var authMode: AuthMode
    /// Node ids or CASE Authenticated Tags; nil grants any subject of the auth mode.
    public var subjects: [UInt64]?
    /// Nil grants every target.
    public var targets: [Target]?
    /// Why an AuxiliaryACL entry exists; nil in the ACL (Core §9.10.5.5).
    public var auxiliaryType: AuxiliaryType?

    public enum AuxiliaryType: UInt8, Sendable {
        case system = 0
        case groupcast = 1
    }

    /// TargetsPerAccessControlEntry: how many targets an entry holds.
    public static let targetsPerEntry = 3

    public init(fabricIndex: FabricIndex, privilege: Privilege, authMode: AuthMode, subjects: [UInt64]?, targets: [Target]? = nil,
                auxiliaryType: AuxiliaryType? = nil) {
        self.fabricIndex = fabricIndex
        self.privilege = privilege
        self.authMode = authMode
        self.subjects = subjects
        self.targets = targets
        self.auxiliaryType = auxiliaryType
    }

    /// The TLV of the ACL attribute's entries.
    public var tlv: TLVValue {
        var fields: [TLVElement] = [
            .field(1, .unsigned(UInt64(privilege.rawValue))), .field(2, .unsigned(UInt64(authMode.rawValue))),
            .field(3, subjects.map { .array($0.map { TLVElement(.unsigned($0)) }) } ?? .null),
            .field(4, targets.map { targets in
                .array(targets.map { target in
                    TLVElement(.structure([
                        .field(0, target.cluster.map { .unsigned(UInt64($0)) } ?? .null),
                        .field(1, target.endpoint.map { .unsigned(UInt64($0)) } ?? .null),
                        .field(2, target.deviceType.map { .unsigned(UInt64($0)) } ?? .null),
                    ]))
                })
            } ?? .null),
        ]
        if let auxiliaryType { fields.append(.field(5, .unsigned(UInt64(auxiliaryType.rawValue)))) }
        fields.append(.field(fabricIndexFieldTag, .unsigned(UInt64(fabricIndex))))
        return .structure(fields)
    }

    /// From a written entry; throws CONSTRAINT_ERROR for invalid ones (Core §9.10.5.4).
    public init(tlv value: TLVValue) throws {
        do {
            let fields = try TLVStruct(value)
            guard let privilege = Privilege(rawValue: try fields.uint(1, as: UInt8.self)),
                  let authMode = AuthMode(rawValue: try fields.uint(2, as: UInt8.self)),
                  authMode != .pase
            else { throw StatusError(.constraintError) }
            self.privilege = privilege
            self.authMode = authMode
            fabricIndex = try fields.uint(fabricIndexFieldTag, as: UInt8.self)
            switch fields[3] {
            case nil, .null?: subjects = nil
            case .array(let entries)?: subjects = try entries.map { guard let value = $0.value.uint else { throw StatusError(.constraintError) }; return value }
            default: throw StatusError(.constraintError)
            }
            switch fields[4] {
            case nil, .null?: targets = nil
            case .array(let entries)?:
                targets = try entries.map { entry in
                    let target = try TLVStruct(entry.value)
                    func optional<T: FixedWidthInteger & UnsignedInteger>(_ tag: UInt8) throws -> T? {
                        guard let value = target[tag], value != .null else { return nil }
                        return try narrow(value)
                    }
                    let result = Target(cluster: try optional(0), endpoint: try optional(1), deviceType: try optional(2))
                    // A target names a cluster, an endpoint or a device type, and not both an endpoint and a device type.
                    guard result.cluster != nil || result.endpoint != nil || result.deviceType != nil,
                          result.endpoint == nil || result.deviceType == nil
                    else { throw StatusError(.constraintError) }
                    return result
                }
            default: throw StatusError(.constraintError)
            }
            // A group-mode entry may not grant Administer, and the subjects are 16-bit group ids then.
            if authMode == .group, privilege == .administer { throw StatusError(.constraintError) }
        } catch let error as StatusError {
            throw error
        } catch {
            throw StatusError(.constraintError)
        }
    }

    /// Whether the entry grants its privilege to a session for a target (Core §6.6.5.2).
    func grants(_ session: SessionInfo, endpoint: EndpointNumber, cluster: ClusterID, deviceTypes: [UInt32]) -> Bool {
        guard session.fabricIndex == fabricIndex else { return false }
        switch (session.kind, authMode) {
        case (.case, .case):
            if let subjects, !subjects.contains(where: { Self.subject($0, matches: session) }) { return false }
        case (.group, .group):
            // A group entry's subjects are group ids (Core §6.6.2.1.2).
            guard let group = session.groupID else { return false }
            if let subjects, !subjects.contains(UInt64(group)) { return false }
        default:
            return false
        }
        if let targets {
            return targets.contains { target in
                (target.cluster ?? cluster) == cluster && (target.endpoint ?? endpoint) == endpoint
                    && (target.deviceType.map { deviceTypes.contains($0) } ?? true)
            }
        }
        return true
    }

    /// A subject is the peer's node id, or a CAT whose identifier matches one of the peer's with a version at least
    /// as high (Core §6.6.2.1.2).
    static func subject(_ subject: UInt64, matches session: SessionInfo) -> Bool {
        if subject >> 32 == 0xFFFF_FFFD {
            let identifier = UInt32(truncatingIfNeeded: subject) >> 16
            let version = UInt16(truncatingIfNeeded: subject)
            return session.caseAuthenticatedTags.contains { $0 >> 16 == identifier && UInt16(truncatingIfNeeded: $0) >= version }
        }
        return subject == session.peerNodeID
    }
}

/// Decides access for the Interaction Model.
public protocol AccessController: Sendable {
    /// The highest privilege the session holds on the target, or nil for none.
    func privilege(of session: SessionInfo, endpoint: EndpointNumber, cluster: ClusterID, deviceTypes: [UInt32]) async -> Privilege?
}

/// The ACL entries of every fabric, persisted; the AccessControl cluster reads and writes them per fabric.
public actor AccessControlEntries: AccessController {
    private var entries: [AccessControlEntry] = []
    private let storage: any MatterStorage
    /// The AuxiliaryACL's entries (Groupcast's), which grant as the ACL's do (Core §9.10.6.10).
    private var auxiliary: (@Sendable () async -> [AccessControlEntry])?
    private var observers: [@Sendable () -> Void] = []

    public init(storage: any MatterStorage) async {
        self.storage = storage
        if let data = await storage.value(for: StorageKey.accessControl), let list = try? TLVDecoder.decode(data).value.elements {
            entries = list.compactMap { try? AccessControlEntry(tlv: $0.value) }
        }
    }

    public var all: [AccessControlEntry] { entries }

    func onChange(_ observer: @escaping @Sendable () -> Void) { observers.append(observer) }

    public func entries(fabric: FabricIndex) -> [AccessControlEntry] { entries.filter { $0.fabricIndex == fabric } }

    public func replace(fabric: FabricIndex, with newEntries: [AccessControlEntry]) async {
        if newEntries.isEmpty, !entries.contains(where: { $0.fabricIndex == fabric }) { return }
        entries = entries.filter { $0.fabricIndex != fabric } + newEntries.map { entry in
            var stamped = entry
            stamped.fabricIndex = fabric
            return stamped
        }
        await save()
    }

    public func removeFabric(_ fabric: FabricIndex) async { await replace(fabric: fabric, with: []) }

    public func useAuxiliary(_ provider: @escaping @Sendable () async -> [AccessControlEntry]) { auxiliary = provider }

    public func privilege(of session: SessionInfo, endpoint: EndpointNumber, cluster: ClusterID, deviceTypes: [UInt32]) async -> Privilege? {
        // A PASE session commissions the node: it holds Administer implicitly (Core §6.6.2.9).
        if session.kind == .pase { return .administer }
        // The AuxiliaryACL grants only to groups: other sessions need not ask for it.
        let all = session.kind == .group ? entries + (await auxiliary?() ?? []) : entries
        return all.filter { $0.grants(session, endpoint: endpoint, cluster: cluster, deviceTypes: deviceTypes) }.map(\.privilege).max()
    }

    private func save() async {
        try? await storage.setValue(TLVEncoder.encode(.array(entries.map { TLVElement($0.tlv) })), for: StorageKey.accessControl)
        for observer in observers { observer() }
    }
}
