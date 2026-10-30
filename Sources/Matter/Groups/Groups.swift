import Foundation
import NIOConcurrencyHelpers
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

    /// An operational group key with what receiving needs, prepared once rather than per message.
    struct OperationalKey {
        let key: [UInt8]
        let startTime: UInt64
        /// Derived from the key (Core §4.17.3.6): where a received message's session id points.
        let sessionID: UInt16
        let encryption: AESCCM
        let privacy: AESCCM
    }

    /// A key set's operational keys and its counter policy: trust-first, or cache-and-sync (MCSP, Core §4.18).
    struct KeySet {
        let keys: [OperationalKey]
        var cacheAndSync = false
    }

    struct Membership: Equatable {
        var name: String
        var endpoints: Set<EndpointNumber>
        /// Its senders hold Operate on its endpoints through the AuxiliaryACL (Groupcast, Core §11.27.10).
        var auxiliaryACL = false
        /// On the group's own address (FF35:…), as legacy groups are; else on the IANA one, FF05::FA (Core §2.5.6.2).
        var perGroupAddress = true
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
        /// The operational key itself, to answer or ask for counter synchronization with it.
        let operationalKey: [UInt8]
        let cacheAndSync: Bool
    }

    /// What a group message's counter says (Core §4.18.4).
    enum CounterCheck {
        case new
        case duplicate
        /// From a peer whose data counter is not known yet, under a cache-and-sync key: synchronize first.
        case unsynchronized
    }

    private struct PeerKey: Hashable {
        let fabric: FabricIndex
        let source: NodeID
        let control: Bool
    }

    var fabrics: [FabricIndex: FabricGroups] = [:]
    private var peers: [PeerKey: MessageReceptionState] = [:]
    private let storage: any MatterStorage
    private let fabricTable: FabricTable
    private var observers: [@Sendable ([SocketAddress]) async -> Void] = []
    /// Told when the AuxiliaryACL entries change, with the administrator that changed them if known, and the fabrics
    /// whose entries changed.
    var auxiliaryObservers: [@Sendable (NodeID?, [FabricIndex]) async -> Void] = []
    /// The fabric under Groupcast testing and until when: read without a hop by every group message.
    nonisolated let testing = NIOLockedValueBox<Testing?>(nil)
    var testReporters: [@Sendable (TLVValue) async -> Void] = []
    /// The AuxiliaryACL entries last announced: a change of them, whatever caused it, is announced once.
    private var announcedAuxiliary: [AccessControlEntry] = []
    /// The Global Group Encrypted Data and Control Message Counters (Core §4.6.1): kept across restarts. Control
    /// counters are reserved in blocks: storage holds the end of the block, where a restart picks up.
    private var counters: (data: UInt32, control: UInt32)
    private var reservedControl: UInt32
    static let counterBlock: UInt32 = 1000

    public init(storage: any MatterStorage, fabrics: FabricTable) async {
        self.storage = storage
        fabricTable = fabrics
        if let data = await storage.value(for: StorageKey.groups), let decoded = try? Self.decode(data) { self.fabrics = decoded }
        if let data = await storage.value(for: StorageKey.groupCounters), let fields = try? TLVStruct(decoding: data),
           let dataCounter = try? fields.uint(1, as: UInt32.self), let control = try? fields.uint(2, as: UInt32.self) {
            counters = (dataCounter, control)
        } else {
            counters = (MessageCounter.initialValue(), MessageCounter.initialValue())
        }
        reservedControl = counters.control
        announcedAuxiliary = auxiliaryEntries
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
        typealias Policy = GroupKeyManagementCluster.GroupKeySecurityPolicyEnum
        let cacheAndSync = UInt64(policy) == Policy.cacheAndSync
        guard id != 0, UInt64(policy) == Policy.trustFirst || cacheAndSync else { throw StatusError(.invalidCommand) }
        // The three slots, key and start time each, null or absent alike; empty slots may only trail.
        func present(_ tag: UInt8) -> TLVValue? { fields[tag].flatMap { $0 == .null ? nil : $0 } }
        var slots = [(S.epochKey0, S.epochStartTime0), (S.epochKey1, S.epochStartTime1), (S.epochKey2, S.epochStartTime2)]
            .map { (key: present($0.0), start: present($0.1)) }
        while let last = slots.last, last.key == nil, last.start == nil { slots.removeLast() }
        guard !slots.isEmpty else { throw StatusError(.invalidCommand) }
        var epochs: [(key: [UInt8], start: UInt64)] = []
        for slot in slots {
            guard let key = slot.key?.bytes, let start = slot.start?.uint else { throw StatusError(.invalidCommand) }
            guard key.count == 16 else { throw StatusError(.constraintError) }
            // A later slot starts later; the first never at 0 from a client.
            guard start > (epochs.last?.start ?? 0) else { throw StatusError(.invalidCommand) }
            epochs.append((key, start))
        }
        guard let compressed = await fabricTable.fabric(fabric)?.compressedFabricID else { throw StatusError(.unsupportedAccess) }

        var state = fabrics[fabric] ?? FabricGroups()
        guard state.keySets[id] != nil || state.keySets.count < Self.maxKeySetsPerFabric else { throw StatusError(.resourceExhausted) }
        state.keySets[id] = KeySet(keys: try epochs.map { epoch in
            try Self.operationalKey(Fabric.operationalGroupKey(epochKey: epoch.key, compressedFabricID: compressed), startTime: epoch.start)
        }, cacheAndSync: cacheAndSync)
        fabrics[fabric] = state
        try await save()
    }

    /// A key set as KeySetReadResponse gives it: the keys left out (Core §11.2.7.2).
    func keySetResponse(_ id: UInt16, fabric: FabricIndex) -> TLVValue? {
        typealias S = GroupKeyManagementCluster.GroupKeySetStruct
        guard let set = fabrics[fabric]?.keySets[id] else { return nil }
        let starts = [S.epochStartTime0, S.epochStartTime1, S.epochStartTime2]
        var fields: [TLVElement] = [.field(S.groupKeySetId, .unsigned(UInt64(id))),
                                    .field(S.groupKeySecurityPolicy, .unsigned(set.cacheAndSync
                                        ? GroupKeyManagementCluster.GroupKeySecurityPolicyEnum.cacheAndSync
                                        : GroupKeyManagementCluster.GroupKeySecurityPolicyEnum.trustFirst))]
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
            // Empty memberships are never kept, so every group listed has endpoints.
            fabrics[fabric]!.memberships.sorted { $0.key < $1.key }.map { group, membership in
                TLVElement(.structure([
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
        guard var state = fabrics[fabric], let entry = state.keyMap.first(where: { $0.group == group }), state.keySets[entry.keySet] != nil
        else { return .unsupportedAccess }
        if state.memberships[group] == nil, state.memberships.count >= Self.maxGroupsPerFabric { return .resourceExhausted }
        var membership = state.memberships[group] ?? Membership(name: name, endpoints: [])
        membership.name = name
        membership.endpoints.insert(endpoint)
        state.memberships[group] = membership
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
        fabrics.values.map { Self.maxGroupsPerFabric - $0.memberships.count }.min() ?? Self.maxGroupsPerFabric
    }

    func remove(_ group: GroupID, endpoint: EndpointNumber, fabric: FabricIndex) async -> IMStatus {
        guard group != 0 else { return .constraintError }
        guard fabrics[fabric]?.memberships[group]?.endpoints.remove(endpoint) != nil else { return .notFound }
        if fabrics[fabric]?.memberships[group]?.endpoints.isEmpty == true { fabrics[fabric]?.memberships[group] = nil }
        return await membershipChanged()
    }

    func removeAll(endpoint: EndpointNumber, fabric: FabricIndex) async {
        if leave(endpoint, fabric: fabric) { _ = await membershipChanged() }
    }

    /// Takes an endpoint out of a fabric's groups, dropping groups left empty; says whether anything changed.
    private func leave(_ endpoint: EndpointNumber, fabric: FabricIndex) -> Bool {
        guard let memberships = fabrics[fabric]?.memberships else { return false }
        let remaining = memberships.compactMapValues { membership -> Membership? in
            var membership = membership
            membership.endpoints.remove(endpoint)
            return membership.endpoints.isEmpty ? nil : membership
        }
        guard remaining != memberships else { return false }
        fabrics[fabric]?.memberships = remaining
        return true
    }

    /// The endpoints a group message is for.
    public func endpoints(of group: GroupID, fabric: FabricIndex) -> [EndpointNumber] {
        fabrics[fabric]?.memberships[group]?.endpoints.sorted() ?? []
    }

    /// Forgets a removed fabric's groups, keys and peers.
    public func removeFabric(_ fabric: FabricIndex) async {
        peers = peers.filter { $0.key.fabric != fabric }
        guard fabrics.removeValue(forKey: fabric) != nil else { return }
        // Leaving a fabric is not announced as an AuxiliaryACL change (Core §9.10.9.4).
        announcedAuxiliary = auxiliaryEntries
        _ = await membershipChanged()
    }

    /// The node leaves an endpoint: its memberships go (a bridged device removed).
    public func removeEndpoint(_ endpoint: EndpointNumber) async {
        let changed = fabrics.keys.map { leave(endpoint, fabric: $0) }.contains(true)
        if changed { _ = await membershipChanged() }
    }

    func membershipChanged(by admin: NodeID? = nil) async -> IMStatus {
        do { try await save() } catch { return .failure }
        let addresses = await multicastAddresses
        for observer in observers { await observer(addresses) }
        let auxiliary = auxiliaryEntries
        if auxiliary != announcedAuxiliary {
            let now = Dictionary(grouping: auxiliary, by: \.fabricIndex), before = Dictionary(grouping: announcedAuxiliary, by: \.fabricIndex)
            let changed = Set(now.keys).union(before.keys).filter { now[$0] != before[$0] }.sorted()
            announcedAuxiliary = auxiliary
            for observer in auxiliaryObservers { await observer(admin, changed) }
        }
        return .success
    }

    /// The multicast addresses of the groups an endpoint is in: a group's own, by its fabric's id, or the IANA one
    /// that groups share (Core §2.5.6.2).
    public var multicastAddresses: [SocketAddress] {
        get async {
            var addresses: [SocketAddress] = []
            var shared = false
            for (fabric, state) in fabrics.sorted(by: { $0.key < $1.key }) where !state.memberships.isEmpty {
                guard let fabricID = await fabricTable.fabric(fabric)?.fabricID else { continue }
                for (group, membership) in state.memberships.sorted(by: { $0.key < $1.key }) {
                    guard membership.perGroupAddress else {
                        shared = true
                        continue
                    }
                    if let address = try? Self.multicastAddress(fabricID: fabricID, group: group) { addresses.append(address) }
                }
            }
            if shared, let address = try? SocketAddress(ipAddress: Self.ianaAddress, port: 5540) { addresses.insert(address, at: 0) }
            return addresses
        }
    }

    /// The site-scoped multicast address IANA assigned to Matter, which Groupcast groups share (Core §2.5.6.2).
    public static let ianaAddress = "ff05::fa"

    // MARK: - Receiving (Core §4.16.3)

    /// The operational keys a message's group session id may point to, with their privacy keys.
    func candidates(sessionID: UInt16) -> [Candidate] {
        fabrics.flatMap { fabric, state in
            state.keySets.flatMap { id, set -> [Candidate] in
                let keys = set.keys.filter { $0.sessionID == sessionID }
                guard !keys.isEmpty else { return [] }
                let groups = Set(state.keyMap.filter { $0.keySet == id }.map(\.group))
                guard !groups.isEmpty else { return [] }
                return keys.map {
                    Candidate(fabric: fabric, key: $0.encryption, privacy: $0.privacy, groups: groups, operationalKey: $0.key,
                              cacheAndSync: set.cacheAndSync)
                }
            }
        }
    }

    /// A peer's counter, per counter type (Core §4.18.4): control messages and trust-first keys trust the first
    /// authenticated counter; a cache-and-sync key waits for MCSP to learn it.
    func check(_ counter: UInt32, fabric: FabricIndex, source: NodeID, control: Bool, cacheAndSync: Bool = false) -> CounterCheck {
        let key = PeerKey(fabric: fabric, source: source, control: control)
        if peers[key] == nil, cacheAndSync, !control { return .unsynchronized }
        // Trust-first: a first counter is accepted, and received.
        var state = peers[key] ?? MessageReceptionState(policy: .group)
        defer { peers[key] = state }
        return state.accept(counter) ? .new : .duplicate
    }

    /// The peer's data counter, learnt from a MsgCounterSyncRsp.
    func synchronize(fabric: FabricIndex, source: NodeID, counter: UInt32) {
        peers[PeerKey(fabric: fabric, source: source, control: false)] = MessageReceptionState(policy: .group, learnt: counter)
    }

    /// The node's id on a fabric: the source of its MCSP messages.
    func nodeID(fabric: FabricIndex) async -> NodeID? { await fabricTable.fabric(fabric)?.nodeID }

    /// The next Global Group Encrypted Control Message Counter: from a block reserved in storage before its first use,
    /// so a restart never reuses one and storage is written once per block.
    func nextControlCounter() async -> UInt32 {
        if counters.control == reservedControl {
            reservedControl = counters.control &+ Self.counterBlock
            try? await storage.setValue(TLVEncoder.encode(.structure([.field(1, .unsigned(UInt64(counters.data))),
                                                                      .field(2, .unsigned(UInt64(reservedControl)))])),
                                        for: StorageKey.groupCounters)
        }
        defer { counters.control &+= 1 }
        return counters.control
    }

    /// The Global Group Encrypted Data Message Counter, for a MsgCounterSyncRsp: this node sends no group data.
    var dataCounter: UInt32 { counters.data }

    // MARK: - Derivations

    static func operationalKey(_ key: [UInt8], startTime: UInt64) throws -> OperationalKey {
        OperationalKey(key: key, startTime: startTime, sessionID: groupSessionID(operationalKey: key), encryption: try AESCCM(key: key),
                       privacy: try AESCCM(key: MatterCrypto.privacyKey(encryptionKey: key)))
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
                .field(2, .array(state.keySets.sorted { $0.key < $1.key }.map { id, set in
                    TLVElement(.structure([
                        .field(1, .unsigned(UInt64(id))), .field(2, .bool(set.cacheAndSync)),
                        .field(3, .array(set.keys.map { TLVElement(.structure([.field(1, .bytes($0.key)), .field(2, .unsigned($0.startTime))])) })),
                    ]))
                })),
                .field(3, .array(state.keyMap.map { TLVElement(.structure([.field(1, .unsigned(UInt64($0.group))), .field(2, .unsigned(UInt64($0.keySet)))])) })),
                .field(4, .array(state.memberships.sorted { $0.key < $1.key }.map { group, membership in
                    TLVElement(.structure([
                        .field(1, .unsigned(UInt64(group))), .field(2, .utf8(membership.name)),
                        .field(3, .array(membership.endpoints.sorted().map { TLVElement(.unsigned(UInt64($0))) })),
                        .field(4, .bool(membership.auxiliaryACL)), .field(5, .bool(membership.perGroupAddress)),
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
                    return try operationalKey(try keyFields.bytes(1), startTime: try keyFields.uint(2))
                }
                state.keySets[try setFields.uint(1, as: UInt16.self)] = KeySet(keys: keys, cacheAndSync: setFields[2]?.bool ?? false)
            }
            state.keyMap = try fields.elements(3).map { entry in
                let entryFields = try TLVStruct(entry.value)
                return (try entryFields.uint(1, as: UInt16.self), try entryFields.uint(2, as: UInt16.self))
            }
            for membership in try fields.elements(4) {
                let membershipFields = try TLVStruct(membership.value)
                // Groups kept before Groupcast are legacy ones: no AuxiliaryACL, their own address (Core §2.12.2).
                state.memberships[try membershipFields.uint(1, as: UInt16.self)] = Membership(
                    name: try membershipFields.string(2),
                    endpoints: Set(try membershipFields.elements(3).compactMap { $0.value.uint.flatMap(UInt16.init(exactly:)) }),
                    auxiliaryACL: membershipFields[4]?.bool ?? false, perGroupAddress: membershipFields[5]?.bool ?? true)
            }
            fabrics[try fields.uint(1, as: UInt8.self)] = state
        }
        return fabrics
    }
}
