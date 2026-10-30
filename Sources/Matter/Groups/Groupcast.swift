import NIOConcurrencyHelpers

/// Groupcast (Core §11.27) on the node's groups: a group joined in one command with its endpoints and key, on the IANA
/// address or its own, and the AuxiliaryACL entries that let its senders operate its endpoints.
extension Groups {
    /// Groups across all fabrics (MaxMembershipCount); a fabric may use half (§11.27.6.1), which is `maxGroupsPerFabric`.
    public static let maxMembershipCount = 2 * maxGroupsPerFabric
    /// A JoinGroup's endpoints at most (§11.27.7.1.2), and a Membership entry's (§11.27.6.1).
    static let endpointsPerJoin = 20
    static let endpointsPerMembershipEntry = 255

    /// JoinGroup's effect (§11.27.7.1.7). `endpoints` are checked by the caller; `key` needs Administer, as
    /// `useAuxiliaryACL` does (`administer`).
    func join(_ group: GroupID, endpoints: [EndpointNumber], keySet: UInt16, key: [UInt8]?, useAuxiliaryACL: Bool?, replace: Bool,
              perGroupAddress: Bool, fabric: FabricIndex, administer: Bool, admin: NodeID?) async throws {
        guard group != 0, keySet != 0 else { throw StatusError(.constraintError) }
        var state = fabrics[fabric] ?? FabricGroups()
        guard state.memberships[group] != nil || state.memberships.count < Self.maxGroupsPerFabric else { throw StatusError(.resourceExhausted) }
        // Listener only: a membership has endpoints, none of them the root's.
        guard !endpoints.isEmpty, endpoints.count <= Self.endpointsPerJoin else { throw StatusError(.constraintError) }
        guard !endpoints.contains(0) else { throw StatusError(.unsupportedEndpoint) }
        if useAuxiliaryACL != nil, !administer { throw StatusError(.unsupportedAccess) }
        state = try await bind(group, to: keySet, key: key, fabric: fabric, administer: administer)
        var membership = state.memberships[group] ?? Membership(name: "", endpoints: [])
        membership.endpoints = replace ? Set(endpoints) : membership.endpoints.union(endpoints)
        membership.perGroupAddress = perGroupAddress
        if let useAuxiliaryACL { membership.auxiliaryACL = useAuxiliaryACL }
        state.memberships[group] = membership
        fabrics[fabric] = state
        try await groupcastChanged(by: admin)
    }

    /// LeaveGroup's effect (§11.27.7.2): the endpoints removed. Group 0 is every group of the fabric.
    func leave(_ group: GroupID, endpoints: [EndpointNumber]?, fabric: FabricIndex, admin: NodeID?) async throws -> [EndpointNumber] {
        guard var state = fabrics[fabric] else { throw StatusError(.notFound) }
        let targets = group == 0 ? state.memberships.keys.sorted() : [group]
        guard !targets.isEmpty, targets.allSatisfy({ state.memberships[$0] != nil }) else { throw StatusError(.notFound) }
        var removed: [EndpointNumber] = []
        for target in targets {
            guard var membership = state.memberships[target] else { continue }
            if let endpoints {
                let leaving = membership.endpoints.intersection(endpoints)
                removed += leaving.sorted()
                membership.endpoints.subtract(leaving)
            } else {
                removed += membership.endpoints.sorted()
                membership.endpoints = []
            }
            if membership.endpoints.isEmpty {
                // The group goes with its keys, unless another group uses them (§11.27.7.2.4).
                state.memberships[target] = nil
                let keySet = state.keyMap.first { $0.group == target }?.keySet
                state.keyMap.removeAll { $0.group == target }
                if let keySet, !state.keyMap.contains(where: { $0.keySet == keySet }) { state.keySets[keySet] = nil }
            } else {
                state.memberships[target] = membership
            }
        }
        fabrics[fabric] = state
        try await groupcastChanged(by: admin)
        // Ambiguous over several groups, and limited to 20 (§11.27.7.3).
        return group == 0 || removed.count > Self.endpointsPerJoin ? [] : removed
    }

    /// UpdateGroupKey's effect (§11.27.7.4).
    func updateKey(_ group: GroupID, keySet: UInt16, key: [UInt8]?, fabric: FabricIndex, administer: Bool, admin: NodeID?) async throws {
        guard fabrics[fabric]?.memberships[group] != nil else { throw StatusError(.notFound) }
        fabrics[fabric] = try await bind(group, to: keySet, key: key, fabric: fabric, administer: administer)
        try await groupcastChanged(by: admin)
    }

    /// ConfigureAuxiliaryACL's effect (§11.27.7.5).
    func configureAuxiliaryACL(_ group: GroupID, use: Bool, fabric: FabricIndex, admin: NodeID?) async throws {
        guard fabrics[fabric]?.memberships[group] != nil else { throw StatusError(.notFound) }
        fabrics[fabric]?.memberships[group]?.auxiliaryACL = use
        try await groupcastChanged(by: admin)
    }

    /// Maps a group to a key set: a new one from `key` (Administer only, and never over an existing set), else one the
    /// fabric has (§11.27.7.1.7 steps 4-6). The fabric's groups after it.
    private func bind(_ group: GroupID, to keySet: UInt16, key: [UInt8]?, fabric: FabricIndex, administer: Bool) async throws -> FabricGroups {
        if let key {
            guard administer else { throw StatusError(.unsupportedAccess) }
            guard fabrics[fabric]?.keySets[keySet] == nil else { throw StatusError(.alreadyExists) }
            try await addKeySet(keySet, key: key, fabric: fabric)
        } else {
            guard fabrics[fabric]?.keySets[keySet] != nil else { throw StatusError(.notFound) }
        }
        var state = fabrics[fabric] ?? FabricGroups()
        state.keyMap.removeAll { $0.group == group }
        state.keyMap.append((group, keySet))
        return state
    }

    /// A key set from a Groupcast key: trust-first, the key as its only epoch key, from time 1 (§11.27.7.1.3).
    private func addKeySet(_ id: UInt16, key: [UInt8], fabric: FabricIndex) async throws {
        typealias S = GroupKeyManagementCluster.GroupKeySetStruct
        try await writeKeySet(.structure([
            .field(S.groupKeySetId, .unsigned(UInt64(id))),
            .field(S.groupKeySecurityPolicy, .unsigned(GroupKeyManagementCluster.GroupKeySecurityPolicyEnum.trustFirst)),
            .field(S.epochKey0, .bytes(key)), .field(S.epochStartTime0, .unsigned(1)),
            .field(S.epochKey1, .null), .field(S.epochStartTime1, .null), .field(S.epochKey2, .null), .field(S.epochStartTime2, .null),
        ]), fabric: fabric)
    }

    private func groupcastChanged(by admin: NodeID?) async throws {
        guard await membershipChanged(by: admin) == .success else { throw StatusError(.failure) }
    }

    // MARK: - Attributes

    /// Membership: each fabric's groups, a group split in entries of 255 endpoints at most (§11.27.6.1).
    var membershipList: TLVValue {
        typealias M = GroupcastCluster.MembershipStruct
        return .array(fabrics.sorted { $0.key < $1.key }.flatMap { fabric, state in
            state.memberships.sorted { $0.key < $1.key }.flatMap { group, membership -> [TLVElement] in
                let keySet = state.keyMap.first { $0.group == group }?.keySet ?? 0
                let chunks = membership.endpoints.sorted().chunks(of: Self.endpointsPerMembershipEntry)
                return (chunks.isEmpty ? [[]] : chunks).map { endpoints in
                    TLVElement(.structure([
                        .field(M.groupId, .unsigned(UInt64(group))),
                        .field(M.endpoints, .array(endpoints.map { TLVElement(.unsigned(UInt64($0))) })),
                        .field(M.keySetId, .unsigned(UInt64(keySet))), .field(M.hasAuxiliaryAcl, .bool(membership.auxiliaryACL)),
                        .field(M.mcastAddrPolicy, .unsigned(membership.perGroupAddress
                            ? GroupcastCluster.MulticastAddrPolicyEnum.perGroup : GroupcastCluster.MulticastAddrPolicyEnum.ianaAddr)),
                        .field(M.fabricIndex, .unsigned(UInt64(fabric))),
                    ]))
                }
            }
        })
    }

    /// UsedMcastAddrCount: the IANA address once, and each group on its own (§11.27.6.4).
    var usedMulticastAddressCount: Int {
        let memberships = fabrics.values.flatMap(\.memberships.values)
        return memberships.filter(\.perGroupAddress).count + (memberships.contains { !$0.perGroupAddress } ? 1 : 0)
    }

    /// The AuxiliaryACL entries Groupcast memberships generate (§11.27.10): Operate for the group on its endpoints,
    /// as many targets in an entry as an entry holds.
    public var auxiliaryEntries: [AccessControlEntry] {
        fabrics.sorted { $0.key < $1.key }.flatMap { fabric, state in
            state.memberships.sorted { $0.key < $1.key }.filter { $0.value.auxiliaryACL }.flatMap { group, membership in
                membership.endpoints.sorted().chunks(of: AccessControlEntry.targetsPerEntry).map { endpoints in
                    AccessControlEntry(fabricIndex: fabric, privilege: .operate, authMode: .group, subjects: [UInt64(group)],
                                       targets: endpoints.map { AccessControlEntry.Target(endpoint: $0) }, auxiliaryType: .groupcast)
                }
            }
        }
    }

    /// Calls `observer` when the AuxiliaryACL entries change, with the administrator who changed them when known.
    public func onAuxiliaryChange(_ observer: @escaping @Sendable (NodeID?, [FabricIndex]) async -> Void) { auxiliaryObservers.append(observer) }
}

/// GroupcastTesting (§11.27.7.6): while a fabric tests, each group invoke processed for it, and each group message that
/// could not be, is reported as a GroupcastTesting event.
extension Groups {
    struct Testing {
        let fabric: FabricIndex
        let until: ContinuousClock.Instant
    }

    /// FabricUnderTest: the fabric testing listening now, else 0 (§11.27.6.5).
    nonisolated var fabricUnderTest: FabricIndex {
        guard let testing = testing.withLockedValue({ $0 }), testing.until > .now else { return 0 }
        return testing.fabric
    }

    /// Whether a fabric tests now: group messages are reported only then.
    nonisolated var isTesting: Bool { fabricUnderTest != 0 }

    /// Starts listener testing for a fabric, or stops any (nil).
    nonisolated func test(fabric: FabricIndex?, seconds: Int) {
        testing.withLockedValue { $0 = fabric.map { Testing(fabric: $0, until: .now + .seconds(seconds)) } }
    }

    /// Calls `reporter` with each GroupcastTesting event's data (its fabric in field 254).
    public func onTestEvent(_ reporter: @escaping @Sendable (TLVValue) async -> Void) { testReporters.append(reporter) }

    /// Reports a group message's outcome while its fabric (or, when no key found it, any fabric) is under test.
    nonisolated func reportTest(_ result: UInt64, fabric: FabricIndex?, group: GroupID? = nil, path: CommandPath? = nil,
                                allowed: Bool? = nil) async {
        let tested = fabricUnderTest
        guard tested != 0, fabric == nil || fabric == tested else { return }
        var fields: [TLVElement] = []
        if let group { fields.append(.field(2, .unsigned(UInt64(group)))) }
        if let path {
            if let endpoint = path.endpoint { fields.append(.field(3, .unsigned(UInt64(endpoint)))) }
            fields += [.field(4, .unsigned(UInt64(path.cluster))), .field(5, .unsigned(UInt64(path.command)))]
        }
        if let allowed { fields.append(.field(6, .bool(allowed))) }
        fields += [.field(7, .unsigned(result)), .field(fabricIndexFieldTag, .unsigned(UInt64(tested)))]
        await report(.structure(fields))
    }

    private func report(_ event: TLVValue) async {
        for reporter in testReporters { await reporter(event) }
    }
}
