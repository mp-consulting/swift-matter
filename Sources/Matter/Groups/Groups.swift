import Foundation
import NIOCore

public typealias GroupID = UInt16

/// Group communication's state on a node (Core §4.16, §4.17): each fabric's group key sets (their operational keys,
/// never the epoch keys), the GroupKeyMap from groups to key sets, which endpoints are in which group (the Groups
/// cluster), and the trust-first message counters of the peers that sent group messages. Persisted, except the
/// counters (Core §4.18.2 lets them go at reboot).
public actor Groups {
    /// Groups per fabric, and key sets per fabric besides the IPK (Core §2.11.1.2 asks at least 4 and 3).
    public static let maxGroupsPerFabric = 16
    public static let maxKeySetsPerFabric = 3

    struct OperationalKey: Hashable {
        let key: [UInt8]
        let startTime: UInt64
        /// Derived from the key (Core §4.17.3.6): where a received message's session id points.
        let sessionID: UInt16
    }

    struct KeySet {
        let id: UInt16
        let policy: UInt8
        let keys: [OperationalKey]
    }

    struct Membership: Equatable {
        var name: String
        var endpoints: Set<EndpointNumber>
    }

    struct FabricGroups {
        var keySets: [UInt16: KeySet] = [:]
        /// GroupKeyMap: group to key set, in the order written.
        var keyMap: [(group: GroupID, keySet: UInt16)] = []
        var memberships: [GroupID: Membership] = [:]
        var isEmpty: Bool { keySets.isEmpty && keyMap.isEmpty && memberships.isEmpty }
    }

    /// A key that may have encrypted a received group message.
    struct Candidate {
        let fabric: FabricIndex
        let key: AESCCM
        let privacy: AESCCM
        /// The groups mapped to the key's set: a decrypted message's group must be one of them.
        let groups: Set<GroupID>
    }

    private struct PeerKey: Hashable {
        let fabric: FabricIndex
        let source: NodeID
        let control: Bool
    }

    private var fabrics: [FabricIndex: FabricGroups] = [:]
    private var peers: [PeerKey: MessageReceptionState] = [:]
    private let storage: any MatterStorage
    private let fabricTable: FabricTable
    private var observers: [@Sendable ([SocketAddress]) async -> Void] = []

    public init(storage: any MatterStorage, fabrics: FabricTable) async {
        self.storage = storage
        fabricTable = fabrics
        if let data = await storage.value(for: StorageKey.groups), let decoded = try? Self.decode(data) { self.fabrics = decoded }
    }

    /// Called with the multicast addresses to listen on whenever memberships change.
    public func onMulticastChange(_ observer: @escaping @Sendable ([SocketAddress]) async -> Void) {
        observers.append(observer)
    }

    // MARK: - Key sets (Group Key Management, Core §11.2.7)

    /// Installs or replaces a key set from a KeySetWrite's GroupKeySetStruct, after its checks (Core §11.2.7.1).
    func writeKeySet(_ value: TLVValue, fabric: FabricIndex) async throws {
        typealias S = GroupKeyManagementCluster.GroupKeySetStruct
        let fields = try TLVStruct(value)
        let id = try fields.uint(S.groupKeySetId, as: UInt16.self)
        let policy = try fields.uint(S.groupKeySecurityPolicy, as: UInt8.self)
        // Only trust-first: CacheAndSync is not in the FeatureMap (Core §11.2.5.4).
        guard id != 0, policy == 0 else { throw StatusError(.invalidCommand) }
        var epochs: [(key: [UInt8], start: UInt64)] = []
        for (keyTag, startTag) in [(S.epochKey0, S.epochStartTime0), (S.epochKey1, S.epochStartTime1), (S.epochKey2, S.epochStartTime2)] {
            let key = fields[keyTag].flatMap { $0 == .null ? nil : $0 }, start = fields[startTag].flatMap { $0 == .null ? nil : $0 }
            if key == nil, start == nil { break }
            guard let key = key?.bytes, let start = start?.uint else { throw StatusError(.invalidCommand) }
            guard key.count == 16 else { throw StatusError(.constraintError) }
            // A later slot starts later; the first never at 0 from a client.
            guard start > (epochs.last?.start ?? 0) else { throw StatusError(.invalidCommand) }
            epochs.append((key, start))
        }
        guard !epochs.isEmpty else { throw StatusError(.invalidCommand) }
        // A slot after an empty one is malformed too.
        let filled = [S.epochKey0, S.epochKey1, S.epochKey2].filter { fields[$0].map { $0 != .null } ?? false }.count
        guard filled == epochs.count else { throw StatusError(.invalidCommand) }
        guard let compressed = await fabricTable.fabric(fabric)?.compressedFabricID else { throw StatusError(.unsupportedAccess) }

        var state = fabrics[fabric] ?? FabricGroups()
        guard state.keySets[id] != nil || state.keySets.count < Self.maxKeySetsPerFabric else { throw StatusError(.resourceExhausted) }
        state.keySets[id] = KeySet(id: id, policy: policy, keys: epochs.map { epoch in
            Self.operationalKey(Fabric.operationalGroupKey(epochKey: epoch.key, compressedFabricID: compressed), startTime: epoch.start)
        })
        fabrics[fabric] = state
        try await save()
    }

    /// A key set as KeySetReadResponse gives it: the keys left out (Core §11.2.7.2).
    func keySetResponse(_ id: UInt16, fabric: FabricIndex) -> TLVValue? {
        typealias S = GroupKeyManagementCluster.GroupKeySetStruct
        guard let set = fabrics[fabric]?.keySets[id] else { return nil }
        let starts = [S.epochStartTime0, S.epochStartTime1, S.epochStartTime2]
        var fields: [TLVElement] = [.field(S.groupKeySetId, .unsigned(UInt64(id))), .field(S.groupKeySecurityPolicy, .unsigned(UInt64(set.policy)))]
        for (slot, (keyTag, startTag)) in zip([S.epochKey0, S.epochKey1, S.epochKey2], starts).enumerated() {
            fields.append(.field(keyTag, .null))
            fields.append(.field(startTag, set.keys.indices.contains(slot) ? .unsigned(set.keys[slot].startTime) : .null))
        }
        return .structure(fields)
    }

    /// Removes a key set and the GroupKeyMap entries that use it (Core §11.2.7.4).
    func removeKeySet(_ id: UInt16, fabric: FabricIndex) async throws {
        guard id != 0 else { throw StatusError(.invalidCommand) }
        guard fabrics[fabric]?.keySets.removeValue(forKey: id) != nil else { throw StatusError(.notFound) }
        fabrics[fabric]?.keyMap.removeAll { $0.keySet == id }
        try await save()
    }

    func keySetIDs(fabric: FabricIndex) -> [UInt16] { (fabrics[fabric]?.keySets.keys).map { $0.sorted() } ?? [] }

    // MARK: - GroupKeyMap and GroupTable (Core §11.2.6)

    /// GroupKeyMap: every fabric's entries; the cluster filters them.
    var keyMap: TLVValue {
        typealias S = GroupKeyManagementCluster.GroupKeyMapStruct
        return .array(fabrics.keys.sorted().flatMap { fabric in
            fabrics[fabric]!.keyMap.map { entry in
                TLVElement(.structure([.field(S.groupId, .unsigned(UInt64(entry.group))), .field(S.groupKeySetId, .unsigned(UInt64(entry.keySet))),
                                       .field(fabricIndexFieldTag, .unsigned(UInt64(fabric)))]))
            }
        })
    }

    /// Replaces a fabric's GroupKeyMap entries: one per group, never the IPK's set (Core §11.2.5.3).
    func setKeyMap(_ entries: [TLVElement], fabric: FabricIndex) async throws {
        typealias S = GroupKeyManagementCluster.GroupKeyMapStruct
        var map: [(group: GroupID, keySet: UInt16)] = []
        for entry in entries {
            let fields = try TLVStruct(entry.value)
            let group = try fields.uint(S.groupId, as: UInt16.self), keySet = try fields.uint(S.groupKeySetId, as: UInt16.self)
            guard group != 0, keySet != 0 else { throw StatusError(.constraintError) }
            guard !map.contains(where: { $0.group == group }) else { throw StatusError(.constraintError) }
            map.append((group, keySet))
        }
        guard map.count <= Self.maxGroupsPerFabric else { throw StatusError(.resourceExhausted) }
        fabrics[fabric, default: FabricGroups()].keyMap = map
        try await save()
    }

    /// GroupTable: each fabric's groups with their endpoints and names (Core §11.2.6.2).
    var groupTable: TLVValue {
        typealias S = GroupKeyManagementCluster.GroupInfoMapStruct
        return .array(fabrics.keys.sorted().flatMap { fabric in
            fabrics[fabric]!.memberships.sorted { $0.key < $1.key }.compactMap { group, membership -> TLVElement? in
                guard !membership.endpoints.isEmpty else { return nil }
                return TLVElement(.structure([
                    .field(S.groupId, .unsigned(UInt64(group))),
                    .field(S.endpoints, .array(membership.endpoints.sorted().map { TLVElement(.unsigned(UInt64($0))) })),
                    .field(S.groupName, .utf8(membership.name)),
                    .field(fabricIndexFieldTag, .unsigned(UInt64(fabric))),
                ]))
            }
        })
    }

    // MARK: - Membership (the Groups cluster, Application Clusters §1.3)

    /// AddGroup: the group needs key material, and room (Application Clusters §1.3.7.1).
    func add(_ group: GroupID, name: String, endpoint: EndpointNumber, fabric: FabricIndex) async -> IMStatus {
        guard group != 0, name.utf8.count <= 16 else { return .constraintError }
        guard let entry = fabrics[fabric]?.keyMap.first(where: { $0.group == group }), fabrics[fabric]?.keySets[entry.keySet] != nil
        else { return .unsupportedAccess }
        var state = fabrics[fabric] ?? FabricGroups()
        if state.memberships[group] == nil, state.memberships.count >= Self.maxGroupsPerFabric { return .resourceExhausted }
        state.memberships[group, default: Membership(name: name, endpoints: [])].endpoints.insert(endpoint)
        state.memberships[group]?.name = name
        fabrics[fabric] = state
        return await membershipChanged()
    }

    func name(of group: GroupID, endpoint: EndpointNumber, fabric: FabricIndex) -> String? {
        guard let membership = fabrics[fabric]?.memberships[group], membership.endpoints.contains(endpoint) else { return nil }
        return membership.name
    }

    func groups(of endpoint: EndpointNumber, fabric: FabricIndex) -> [GroupID] {
        (fabrics[fabric]?.memberships.filter { $0.value.endpoints.contains(endpoint) }.keys).map { $0.sorted() } ?? []
    }

    var remainingCapacity: Int {
        get async {
            fabrics.values.map { Self.maxGroupsPerFabric - $0.memberships.count }.min() ?? Self.maxGroupsPerFabric
        }
    }

    func remove(_ group: GroupID, endpoint: EndpointNumber, fabric: FabricIndex) async -> IMStatus {
        guard group != 0 else { return .constraintError }
        guard fabrics[fabric]?.memberships[group]?.endpoints.remove(endpoint) != nil else { return .notFound }
        if fabrics[fabric]?.memberships[group]?.endpoints.isEmpty == true { fabrics[fabric]?.memberships[group] = nil }
        return await membershipChanged()
    }

    func removeAll(endpoint: EndpointNumber, fabric: FabricIndex) async {
        guard var state = fabrics[fabric] else { return }
        for group in state.memberships.keys {
            state.memberships[group]?.endpoints.remove(endpoint)
            if state.memberships[group]?.endpoints.isEmpty == true { state.memberships[group] = nil }
        }
        fabrics[fabric] = state
        _ = await membershipChanged()
    }

    /// The endpoints a group message is for.
    public func endpoints(of group: GroupID, fabric: FabricIndex) -> [EndpointNumber] {
        fabrics[fabric]?.memberships[group]?.endpoints.sorted() ?? []
    }

    /// Forgets a removed fabric's groups, keys and peers.
    public func removeFabric(_ fabric: FabricIndex) async {
        peers = peers.filter { $0.key.fabric != fabric }
        guard fabrics.removeValue(forKey: fabric) != nil else { return }
        _ = await membershipChanged()
    }

    /// The node leaves an endpoint: its memberships go (a bridged device removed).
    public func removeEndpoint(_ endpoint: EndpointNumber) async {
        for fabric in fabrics.keys { await removeAll(endpoint: endpoint, fabric: fabric) }
    }

    private func membershipChanged() async -> IMStatus {
        do { try await save() } catch { return .failure }
        let addresses = await multicastAddresses
        for observer in observers { await observer(addresses) }
        return .success
    }

    /// The multicast addresses of the groups an endpoint is in, by their fabric's id (Core §2.5.6.2).
    public var multicastAddresses: [SocketAddress] {
        get async {
            var addresses: [SocketAddress] = []
            for (fabric, state) in fabrics where !state.memberships.isEmpty {
                guard let fabricID = await fabricTable.fabric(fabric)?.fabricID else { continue }
                for group in state.memberships.keys.sorted() {
                    if let address = try? Self.multicastAddress(fabricID: fabricID, group: group) { addresses.append(address) }
                }
            }
            return addresses
        }
    }

    // MARK: - Receiving (Core §4.16.3)

    /// The operational keys a message's group session id may point to, with their privacy keys.
    func candidates(sessionID: UInt16) -> [Candidate] {
        fabrics.flatMap { fabric, state in
            state.keySets.values.flatMap { set -> [Candidate] in
                let groups = Set(state.keyMap.filter { $0.keySet == set.id }.map(\.group))
                guard !groups.isEmpty else { return [] }
                return set.keys.filter { $0.sessionID == sessionID }.compactMap { key in
                    guard let encryption = try? AESCCM(key: key.key),
                          let privacy = try? AESCCM(key: MatterCrypto.privacyKey(encryptionKey: key.key)) else { return nil }
                    return Candidate(fabric: fabric, key: encryption, privacy: privacy, groups: groups)
                }
            }
        }
    }

    /// Trust-first counters per peer and counter type (Core §4.18.1.1): the first authenticated counter is trusted.
    func accept(_ counter: UInt32, fabric: FabricIndex, source: NodeID, control: Bool) -> Bool {
        let key = PeerKey(fabric: fabric, source: source, control: control)
        var state = peers[key] ?? MessageReceptionState(policy: .rolling)
        defer { peers[key] = state }
        return state.accept(counter)
    }

    // MARK: - Derivations

    static func operationalKey(_ key: [UInt8], startTime: UInt64) -> OperationalKey {
        OperationalKey(key: key, startTime: startTime, sessionID: groupSessionID(operationalKey: key))
    }

    /// GroupSessionId: the KDF of the operational key with "GroupKeyHash", big-endian (Core §4.17.3.6).
    public static func groupSessionID(operationalKey: [UInt8]) -> UInt16 {
        let hash = MatterCrypto.kdf(key: operationalKey, salt: [], info: Array("GroupKeyHash".utf8), length: 2)
        return UInt16(hash[0]) << 8 | UInt16(hash[1])
    }

    /// FF35:0040:FD<fabric id>00:<group id> (Core §2.5.6.2), on Matter's multicast port 5540 (§2.5.6.3).
    public static func multicastAddress(fabricID: UInt64, group: GroupID, port: Int = 5540) throws -> SocketAddress {
        var bytes: [UInt8] = [0xFF, 0x35, 0x00, 0x40, 0xFD]
        bytes.appendBigEndian(fabricID)
        bytes.append(0x00)
        bytes.appendBigEndian(group)
        let text = stride(from: 0, to: 16, by: 2).map { hexString(bytes[$0..<$0 + 2]) }.joined(separator: ":")
        return try SocketAddress(ipAddress: text, port: port)
    }

    /// The Group Node Id of a group (Core §2.5.5): 0xFFFF_FFFF_FFFF_xxxx.
    public static func nodeID(of group: GroupID) -> NodeID { 0xFFFF_FFFF_FFFF_0000 | NodeID(group) }

    // MARK: - Storage

    private func save() async throws {
        try await storage.setValue(TLVEncoder.encode(Self.encode(fabrics)), for: StorageKey.groups)
    }

    static func encode(_ fabrics: [FabricIndex: FabricGroups]) -> TLVValue {
        .array(fabrics.sorted { $0.key < $1.key }.filter { !$0.value.isEmpty }.map { fabric, state in
            TLVElement(.structure([
                .field(1, .unsigned(UInt64(fabric))),
                .field(2, .array(state.keySets.values.sorted { $0.id < $1.id }.map { set in
                    TLVElement(.structure([
                        .field(1, .unsigned(UInt64(set.id))), .field(2, .unsigned(UInt64(set.policy))),
                        .field(3, .array(set.keys.map { TLVElement(.structure([.field(1, .bytes($0.key)), .field(2, .unsigned($0.startTime))])) })),
                    ]))
                })),
                .field(3, .array(state.keyMap.map { TLVElement(.structure([.field(1, .unsigned(UInt64($0.group))), .field(2, .unsigned(UInt64($0.keySet)))])) })),
                .field(4, .array(state.memberships.sorted { $0.key < $1.key }.map { group, membership in
                    TLVElement(.structure([
                        .field(1, .unsigned(UInt64(group))), .field(2, .utf8(membership.name)),
                        .field(3, .array(membership.endpoints.sorted().map { TLVElement(.unsigned(UInt64($0))) })),
                    ]))
                })),
            ]))
        })
    }

    static func decode(_ data: [UInt8]) throws -> [FabricIndex: FabricGroups] {
        var fabrics: [FabricIndex: FabricGroups] = [:]
        for element in try TLVDecoder.decode(data).value.elements ?? [] {
            let fields = try TLVStruct(element.value)
            var state = FabricGroups()
            for set in try fields.elements(2) {
                let setFields = try TLVStruct(set.value)
                let keys = try setFields.elements(3).map { entry -> OperationalKey in
                    let keyFields = try TLVStruct(entry.value)
                    return operationalKey(try keyFields.bytes(1), startTime: try keyFields.uint(2))
                }
                let id = try setFields.uint(1, as: UInt16.self)
                state.keySets[id] = KeySet(id: id, policy: try setFields.uint(2, as: UInt8.self), keys: keys)
            }
            state.keyMap = try fields.elements(3).map { entry in
                let entryFields = try TLVStruct(entry.value)
                return (try entryFields.uint(1, as: UInt16.self), try entryFields.uint(2, as: UInt16.self))
            }
            for membership in try fields.elements(4) {
                let membershipFields = try TLVStruct(membership.value)
                state.memberships[try membershipFields.uint(1, as: UInt16.self)] = Membership(
                    name: try membershipFields.string(2),
                    endpoints: Set(try membershipFields.elements(3).compactMap { $0.value.uint.flatMap(UInt16.init(exactly:)) }))
            }
            fabrics[try fields.uint(1, as: UInt8.self)] = state
        }
        return fabrics
    }
}
