import NIOCore
import Testing
@testable import Matter

/// Core §4.17.3.6's and §2.5.6.2's examples, and privacy's round trip.
struct GroupVectorTests {
    @Test func derivesTheGroupSessionID() {
        #expect(Groups.groupSessionID(operationalKey: hex("a6f5306baf6d050af23ba4bd6b9dd960")) == 0xB9F7)
    }

    @Test func formsTheMulticastAddress() throws {
        let address = try Groups.multicastAddress(fabricID: 0x1122_AABB_CCDD_EEFF, group: 0x3344)
        #expect(address == (try SocketAddress(ipAddress: "ff35:40:fd11:22aa:bbcc:ddee:ff00:3344", port: 5540)))
        #expect(Groups.nodeID(of: 0x3344) == 0xFFFF_FFFF_FFFF_3344)
    }

    @Test func neverReusesAControlCounterAcrossRestarts() async throws {
        let storage = MemoryStorage()
        let fabrics = await FabricTable(storage: storage)
        let groups = await Groups(storage: storage, fabrics: fabrics)
        let first = await groups.nextControlCounter()
        #expect(await groups.nextControlCounter() == first &+ 1)
        // A restart continues after the block the first run reserved.
        let restarted = await Groups(storage: storage, fabrics: fabrics)
        #expect(await restarted.nextControlCounter() == first &+ Groups.counterBlock)
    }

    @Test func obfuscatesTheHeaderAndRestoresIt() throws {
        let key = hex("a6f5306baf6d050af23ba4bd6b9dd960")
        let payloadHeader = PayloadHeader(isInitiator: true, needsAck: false, opcode: 8, exchangeID: 1, protocolID: .interactionModel)
        let frame = try Message.groupFrame(payloadHeader: payloadHeader, payload: [1, 2, 3], group: 7, source: 0x1122, counter: 42,
                                           operationalKey: key)
        // Flags, session id and security flags stay clear; counter, source and group are hidden.
        let (seen, length) = try MessageHeader.decode(frame)
        #expect(seen.sessionID == 0xB9F7 && seen.sessionType == .group && seen.privacy)
        #expect(seen.counter != 42 || seen.source != 0x1122)
        let clear = try MessageHeader.togglePrivacy(frame, privacyKey: AESCCM(key: MatterCrypto.privacyKey(encryptionKey: key)))
        let (header, clearLength) = try MessageHeader.decode(clear)
        #expect(clearLength == length)
        #expect(header.counter == 42 && header.source == 0x1122 && header.destination == .group(7))
        let message = try Message.open(frame: clear, header: header, headerLength: clearLength, key: AESCCM(key: key), nonceSourceNodeID: 0x1122)
        #expect(message.payload == [1, 2, 3])
    }
}

struct GroupTests {
    static let keySetID: UInt64 = 0x0101
    static let group: GroupID = 7
    let epochKey = MatterCrypto.random(16)

    /// Installs group 7 on endpoint 2 the way an administrator does (Core §4.17.4.1), with Operate for the group.
    func installGroup(_ fixture: BridgeTests.Fixture, cacheAndSync: Bool = false) async throws {
        typealias S = GroupKeyManagementCluster.GroupKeySetStruct
        _ = try await fixture.invoke(0, GroupKeyManagementCluster.id, GroupKeyManagementCluster.Command.keySetWrite, [.field(0, .structure([
            .field(S.groupKeySetId, .unsigned(Self.keySetID)), .field(S.groupKeySecurityPolicy, .unsigned(cacheAndSync ? 1 : 0)),
            .field(S.epochKey0, .bytes(epochKey)), .field(S.epochStartTime0, .unsigned(1)), .field(S.epochKey1, .null),
            .field(S.epochStartTime1, .null), .field(S.epochKey2, .null), .field(S.epochStartTime2, .null),
        ]))])
        let client = fixture.base.commissioner.client
        let statuses = try await client.write([
            (AttributePath(endpoint: 0, cluster: GroupKeyManagementCluster.id, attribute: GroupKeyManagementCluster.Attribute.groupKeyMap),
             .array([TLVElement(.structure([.field(1, .unsigned(UInt64(Self.group))), .field(2, .unsigned(Self.keySetID))]))])),
        ], session: fixture.session)
        #expect(statuses.map(\.1.status) == [.success])
        let added = try await fixture.invoke(2, GroupsCluster.id, GroupsCluster.Command.addGroup,
                                             [.field(0, .unsigned(UInt64(Self.group))), .field(1, .utf8("Living room"))])
        guard case .response(_, let fields) = added else { Issue.record("no AddGroupResponse"); return }
        #expect(fields[0]?.uint == 0)
        // The administrator's entry stays; the group gets Operate.
        let admin = AccessControlEntry(fabricIndex: 1, privilege: .administer, authMode: .case, subjects: [0x1122])
        let group = AccessControlEntry(fabricIndex: 1, privilege: .operate, authMode: .group, subjects: [UInt64(Self.group)])
        let acl = try await client.write([
            (AttributePath(endpoint: 0, cluster: AccessControlCluster.id, attribute: AccessControlCluster.Attribute.acl),
             .array([TLVElement(admin.tlv), TLVElement(group.tlv)])),
        ], session: fixture.session)
        #expect(acl.map(\.1.status) == [.success])
    }

    func groupInvoke(_ fixture: BridgeTests.Fixture, _ command: CommandID, counter: UInt32) async throws -> [UInt8] {
        let payload = TLVEncoder.encode(.structure([
            .field(0, .bool(true)), .field(1, .bool(false)),
            // A group's command path has no endpoint (Core §8.2.3).
            .field(2, .array([TLVElement(.structure([.field(0, CommandPath(endpoint: nil, cluster: OnOffCluster.id, command: command).tlv),
                                                     .field(1, .structure([]))]))])),
        ]))
        return try Message.groupFrame(
            payloadHeader: PayloadHeader(isInitiator: true, needsAck: false, opcode: IMOpcode.invokeRequest.rawValue, exchangeID: .random(in: 0...UInt16.max),
                                         protocolID: .interactionModel),
            payload: payload, group: Self.group, source: 0x1122, counter: counter, operationalKey: try await operationalKey(fixture))
    }

    @Test func runsAGroupCommandOnTheGroupsEndpoints() async throws {
        let fixture = try await BridgeTests.Fixture()
        let commands = fixture.commands
        _ = try await fixture.bridge.add(BridgedDeviceInfo(id: "lamp", name: "Lamp"), kind: .onOffLight) { await commands.append($0) }
        _ = try await fixture.bridge.add(BridgedDeviceInfo(id: "plug", name: "Plug"), kind: .onOffPlug)
        try await installGroup(fixture)

        // The group's tables, as an administrator reads them; keys never come back.
        let table = try await fixture.read(0, GroupKeyManagementCluster.id, GroupKeyManagementCluster.Attribute.groupTable)
        #expect(table.elements?.first?.value[1]?.uint == UInt64(Self.group))
        #expect(table.elements?.first?.value[2]?.elements?.map(\.value) == [.unsigned(2)])
        guard case .response(_, let read) = try await fixture.invoke(0, GroupKeyManagementCluster.id, GroupKeyManagementCluster.Command.keySetRead,
                                                                     [.field(0, .unsigned(Self.keySetID))]) else { Issue.record("no response"); return }
        #expect(read[0]?[GroupKeyManagementCluster.GroupKeySetStruct.epochKey0] == .null)
        #expect(read[0]?[GroupKeyManagementCluster.GroupKeySetStruct.epochStartTime0]?.uint == 1)

        // A group invoke reaches the member endpoint only, without an answer.
        let transport = await fixture.base.commissioner.layer.transport
        let on = try await groupInvoke(fixture, OnOffCluster.Command.on, counter: 100)
        try await transport.send(on, to: .memory("node"))
        try await eventually { await commands.values == [.setOn(true)] }
        #expect(try await fixture.read(2, OnOffCluster.id, OnOffCluster.Attribute.onOff) == .bool(true))
        #expect(try await fixture.read(3, OnOffCluster.id, OnOffCluster.Attribute.onOff) == .bool(false))

        // A replayed message is dropped: the counter is behind the peer's.
        _ = try await fixture.invoke(2, OnOffCluster.id, OnOffCluster.Command.off)
        try await transport.send(on, to: .memory("node"))
        for _ in 0..<3 { _ = try await fixture.read(2, OnOffCluster.id, OnOffCluster.Attribute.onOff) }
        #expect(await commands.values == [.setOn(true), .setOn(false)])
        #expect(try await fixture.read(2, OnOffCluster.id, OnOffCluster.Attribute.onOff) == .bool(false))
        // The next counter is taken.
        try await transport.send(try await groupInvoke(fixture, OnOffCluster.Command.toggle, counter: 101), to: .memory("node"))
        try await eventually { await commands.values == [.setOn(true), .setOn(false), .setOn(true)] }

        // Leaving the group stops it.
        _ = try await fixture.invoke(2, GroupsCluster.id, GroupsCluster.Command.removeAllGroups)
        try await transport.send(try await groupInvoke(fixture, OnOffCluster.Command.off, counter: 102), to: .memory("node"))
        _ = try await fixture.read(2, OnOffCluster.id, OnOffCluster.Attribute.onOff)
        #expect(await commands.values.count == 3)
    }

    func operationalKey(_ fixture: BridgeTests.Fixture) async throws -> [UInt8] {
        Fabric.operationalGroupKey(epochKey: epochKey, compressedFabricID: try #require(await fixture.base.node.fabrics.fabric(1)).compressedFabricID)
    }

    /// A message under the group key, its privacy removed and opened.
    func open(_ frame: [UInt8], key: [UInt8]) throws -> Message {
        let clear = try MessageHeader.togglePrivacy(frame, privacyKey: AESCCM(key: MatterCrypto.privacyKey(encryptionKey: key)))
        let (header, length) = try MessageHeader.decode(clear)
        return try Message.open(frame: clear, header: header, headerLength: length, key: AESCCM(key: key), nonceSourceNodeID: try #require(header.source))
    }

    /// The sender's MsgCounterSyncRsp to a request: its counter and the challenge, on the request's exchange.
    func syncResponse(to request: Message, counter: UInt32, key: [UInt8]) throws -> [UInt8] {
        var payload: [UInt8] = []
        payload.appendLittleEndian(counter)
        return try Message.groupFrame(
            payloadHeader: PayloadHeader(isInitiator: false, needsAck: true, ackedCounter: request.header.counter,
                                         opcode: SecureChannelOpcode.messageCounterSyncResponse.rawValue,
                                         exchangeID: request.payloadHeader.exchangeID, protocolID: .secureChannel),
            payload: payload + request.payload, destination: .node(0x42), source: 0x1122, counter: .random(in: 1...1000), control: true,
            operationalKey: key)
    }

    @Test func synchronizesCountersBeforeRunningACacheAndSyncCommand() async throws {
        let fixture = try await BridgeTests.Fixture()
        let commands = fixture.commands
        _ = try await fixture.bridge.add(BridgedDeviceInfo(id: "lamp", name: "Lamp"), kind: .onOffLight) { await commands.append($0) }
        try await installGroup(fixture, cacheAndSync: true)
        let key = try await operationalKey(fixture)
        // The test is the group's sender, on the memory network.
        let received = Recorder<[UInt8]>()
        let peer = await fixture.base.network.transport(named: "peer")
        try await peer.start { bytes, _ in await received.append(bytes) }

        // The first command waits: the node asks the sender for its counter, under the group key, to it alone.
        let on = try await groupInvoke(fixture, OnOffCluster.Command.on, counter: 500)
        try await peer.send(on, to: .memory("node"))
        try await eventually { await !received.values.isEmpty }
        #expect(await commands.values.isEmpty)
        let request = try open(try #require(await received.values.first), key: key)
        #expect(request.header.isControl && request.header.destination == .node(0x1122) && request.header.source == 0x42)
        #expect(request.payloadHeader.opcode == SecureChannelOpcode.messageCounterSyncRequest.rawValue && request.payload.count == 8)

        // The answer carries the sender's counter and the challenge: the waiting command runs, once.
        try await peer.send(try syncResponse(to: request, counter: 500, key: key), to: .memory("node"))
        try await eventually { await commands.values == [.setOn(true)] }
        // The response is acknowledged on its exchange, under the group key.
        try await eventually {
            await received.values.contains { (try? open($0, key: key))?.payloadHeader.opcode == SecureChannelOpcode.standaloneAck.rawValue }
        }
        try await peer.send(on, to: .memory("node"))
        try await peer.send(try await groupInvoke(fixture, OnOffCluster.Command.off, counter: 501), to: .memory("node"))
        try await eventually { await commands.values == [.setOn(true), .setOn(false)] }
    }

    @Test func dropsAWaitingCommandWithoutAnAnswer() async throws {
        let fixture = try await BridgeTests.Fixture()
        let commands = fixture.commands
        _ = try await fixture.bridge.add(BridgedDeviceInfo(id: "lamp", name: "Lamp"), kind: .onOffLight) { await commands.append($0) }
        try await installGroup(fixture, cacheAndSync: true)
        let received = Recorder<[UInt8]>()
        let peer = await fixture.base.network.transport(named: "peer")
        try await peer.start { bytes, _ in await received.append(bytes) }
        try await peer.send(try await groupInvoke(fixture, OnOffCluster.Command.on, counter: 7), to: .memory("node"))
        try await eventually { await !received.values.isEmpty }
        // Past MSG_COUNTER_SYNC_TIMEOUT (scaled), the waiting command is dropped; a late answer finds nothing waiting.
        try await eventually { await fixture.base.node.layer.pendingSyncCount == 0 }
        let key = try await operationalKey(fixture)
        let request = try open(try #require(await received.values.first), key: key)
        try await peer.send(try syncResponse(to: request, counter: 7, key: key), to: .memory("node"))
        _ = try await fixture.read(2, OnOffCluster.id, OnOffCluster.Attribute.onOff)
        #expect(await commands.values.isEmpty)
    }

    @Test func refusesAGroupWithoutKeysOrAccess() async throws {
        let fixture = try await BridgeTests.Fixture()
        let commands = fixture.commands
        _ = try await fixture.bridge.add(BridgedDeviceInfo(id: "lamp", name: "Lamp"), kind: .onOffLight) { await commands.append($0) }
        // No key set mapped: AddGroup is refused (Application Clusters §1.3.7.1).
        let refused = try await fixture.invoke(2, GroupsCluster.id, GroupsCluster.Command.addGroup,
                                               [.field(0, .unsigned(UInt64(Self.group))), .field(1, .utf8(""))])
        guard case .response(_, let fields) = refused else { Issue.record("no AddGroupResponse"); return }
        #expect(fields[0]?.uint == UInt64(IMStatus.unsupportedAccess.rawValue))
        // A key set with a bad key, or the IPK's id, is refused.
        typealias S = GroupKeyManagementCluster.GroupKeySetStruct
        let short = try await fixture.invoke(0, GroupKeyManagementCluster.id, GroupKeyManagementCluster.Command.keySetWrite, [.field(0, .structure([
            .field(S.groupKeySetId, .unsigned(2)), .field(S.groupKeySecurityPolicy, .unsigned(0)),
            .field(S.epochKey0, .bytes([1, 2, 3])), .field(S.epochStartTime0, .unsigned(1)),
        ]))])
        guard case .status(let status) = short else { Issue.record("no status"); return }
        #expect(status.status == .constraintError)
        // A start time without its key, even in a later slot, is malformed.
        let orphan = try await fixture.invoke(0, GroupKeyManagementCluster.id, GroupKeyManagementCluster.Command.keySetWrite, [.field(0, .structure([
            .field(S.groupKeySetId, .unsigned(2)), .field(S.groupKeySecurityPolicy, .unsigned(0)),
            .field(S.epochKey0, .bytes(epochKey)), .field(S.epochStartTime0, .unsigned(1)),
            .field(S.epochKey1, .null), .field(S.epochStartTime1, .unsigned(5)),
        ]))])
        guard case .status(let orphanStatus) = orphan else { Issue.record("no status"); return }
        #expect(orphanStatus.status == .invalidCommand)
    }

    @Test func persistsGroups() async throws {
        let fixture = try await BridgeTests.Fixture()
        _ = try await fixture.bridge.add(BridgedDeviceInfo(id: "lamp", name: "Lamp"), kind: .onOffLight)
        try await installGroup(fixture)
        let reloaded = await Groups(storage: fixture.base.storage, fabrics: fixture.base.node.fabrics)
        #expect(await reloaded.endpoints(of: Self.group, fabric: 1) == [2])
        #expect(await reloaded.multicastAddresses.count == 1)
        // Removing the fabric forgets its groups.
        try await fixture.base.node.removeFabric(1)
        #expect(await fixture.base.node.groups.endpoints(of: Self.group, fabric: 1).isEmpty)
    }
}

struct GroupcastTests {
    let key = MatterCrypto.random(16)
    let groups = GroupTests()

    func join(_ fixture: BridgeTests.Fixture, endpoints: [UInt64], auxiliary: Bool?, key: [UInt8]? = nil) async throws -> InvokeResult {
        var fields: [TLVElement] = [
            .field(0, .unsigned(UInt64(GroupTests.group))), .field(1, .array(endpoints.map { TLVElement(.unsigned($0)) })),
            .field(2, .unsigned(GroupTests.keySetID)),
        ]
        if let key { fields.append(.field(3, .bytes(key))) }
        if let auxiliary { fields.append(.field(4, .bool(auxiliary))) }
        return try await fixture.invoke(0, GroupcastCluster.id, GroupcastCluster.Command.joinGroup, fields)
    }

    @Test func joinsAGroupWhoseSendersOperateItsEndpoints() async throws {
        let fixture = try await BridgeTests.Fixture()
        let commands = fixture.commands
        _ = try await fixture.bridge.add(BridgedDeviceInfo(id: "lamp", name: "Lamp"), kind: .onOffLight) { await commands.append($0) }
        _ = try await fixture.bridge.add(BridgedDeviceInfo(id: "plug", name: "Plug"), kind: .onOffPlug)

        // One command: the key, the endpoint, and Operate for the group's senders through the AuxiliaryACL.
        guard case .status(let joined) = try await join(fixture, endpoints: [2], auxiliary: true, key: key) else { Issue.record("no status"); return }
        #expect(joined.status == .success)
        let membership = try await fixture.read(0, GroupcastCluster.id, GroupcastCluster.Attribute.membership)
        typealias M = GroupcastCluster.MembershipStruct
        let entry = try #require(membership.elements?.first?.value)
        #expect(entry[M.groupId]?.uint == UInt64(GroupTests.group) && entry[M.keySetId]?.uint == GroupTests.keySetID)
        #expect(entry[M.hasAuxiliaryAcl] == .bool(true) && entry[M.mcastAddrPolicy]?.uint == GroupcastCluster.MulticastAddrPolicyEnum.ianaAddr)
        let auxiliary = try await fixture.read(0, AccessControlCluster.id, AccessControlCluster.Attribute.auxiliaryAcl)
        #expect(auxiliary.elements?.first?.value[5]?.uint == UInt64(AccessControlEntry.AuxiliaryType.groupcast.rawValue))
        #expect(await fixture.base.node.groups.multicastAddresses.map { $0.ipAddress } == ["ff05::fa"])
        let (_, events) = try await fixture.base.commissioner.client.read(
            [], events: [EventPath(endpoint: 0, cluster: AccessControlCluster.id, event: AccessControlCluster.Event.auxiliaryAccessUpdated)],
            session: fixture.session)
        #expect(events.count == 1)

        // No ACL entry for the group: the AuxiliaryACL lets its command through, to the member endpoint only.
        let transport = await fixture.base.commissioner.layer.transport
        let operational = Fabric.operationalGroupKey(epochKey: key, compressedFabricID: try #require(await fixture.base.node.fabrics.fabric(1)).compressedFabricID)
        let on = try Message.groupFrame(
            payloadHeader: PayloadHeader(isInitiator: true, needsAck: false, opcode: IMOpcode.invokeRequest.rawValue, exchangeID: 1, protocolID: .interactionModel),
            payload: TLVEncoder.encode(.structure([.field(0, .bool(true)), .field(1, .bool(false)), .field(2, .array([TLVElement(.structure([
                .field(0, CommandPath(endpoint: nil, cluster: OnOffCluster.id, command: OnOffCluster.Command.on).tlv), .field(1, .structure([])),
            ]))]))])),
            group: GroupTests.group, source: 0x1122, counter: 100, operationalKey: operational)
        try await transport.send(on, to: .memory("node"))
        try await eventually { await commands.values == [.setOn(true)] }
        #expect(try await fixture.read(3, OnOffCluster.id, OnOffCluster.Attribute.onOff) == .bool(false))

        // Without the AuxiliaryACL the group has no access again.
        _ = try await fixture.invoke(0, GroupcastCluster.id, GroupcastCluster.Command.configureAuxiliaryAcl,
                                     [.field(0, .unsigned(UInt64(GroupTests.group))), .field(1, .bool(false))])
        #expect(try await fixture.read(0, AccessControlCluster.id, AccessControlCluster.Attribute.auxiliaryAcl) == .array([]))

        // Leaving answers with the endpoints that left, and takes the group's key with it.
        guard case .response(_, let left) = try await fixture.invoke(0, GroupcastCluster.id, GroupcastCluster.Command.leaveGroup,
                                                                     [.field(0, .unsigned(UInt64(GroupTests.group)))]) else { Issue.record("no response"); return }
        #expect(left[1]?.elements?.map(\.value) == [.unsigned(2)])
        #expect(try await fixture.read(0, GroupcastCluster.id, GroupcastCluster.Attribute.membership) == .array([]))
        #expect(await fixture.base.node.groups.keySetIDs(fabric: 1).isEmpty)
    }

    @Test func checksEndpointsKeysAndTesting() async throws {
        let fixture = try await BridgeTests.Fixture()
        _ = try await fixture.bridge.add(BridgedDeviceInfo(id: "lamp", name: "Lamp"), kind: .onOffLight)
        func status(_ result: InvokeResult) -> IMStatus? { if case .status(let status) = result { status.status } else { nil } }
        // The root endpoint, an unknown endpoint, and a key set that does not exist yet without a key.
        #expect(status(try await join(fixture, endpoints: [0], auxiliary: nil, key: key)) == .unsupportedEndpoint)
        #expect(status(try await join(fixture, endpoints: [9], auxiliary: nil, key: key)) == .unsupportedEndpoint)
        #expect(status(try await join(fixture, endpoints: [2], auxiliary: nil)) == .notFound)
        #expect(status(try await join(fixture, endpoints: [2], auxiliary: nil, key: key)) == .success)
        // The key set exists now: a new key under its id is refused.
        #expect(status(try await join(fixture, endpoints: [2], auxiliary: nil, key: key)) == .alreadyExists)

        // Listener testing: the fabric under test, then each failed message reported as an event.
        _ = try await fixture.invoke(0, GroupcastCluster.id, GroupcastCluster.Command.groupcastTesting,
                                     [.field(0, .unsigned(GroupcastCluster.GroupcastTestingEnum.enableListenerTesting)), .field(1, .unsigned(60))])
        #expect(try await fixture.read(0, GroupcastCluster.id, GroupcastCluster.Attribute.fabricUnderTest) == .unsigned(1))
        let stranger = try Message.groupFrame(
            payloadHeader: PayloadHeader(isInitiator: true, needsAck: false, opcode: IMOpcode.invokeRequest.rawValue, exchangeID: 1, protocolID: .interactionModel),
            payload: [0x15, 0x18], group: GroupTests.group, source: 0x1122, counter: 1, operationalKey: MatterCrypto.random(16))
        try await (await fixture.base.commissioner.layer.transport).send(stranger, to: .memory("node"))
        try await eventually {
            let read = try? await fixture.base.commissioner.client.read(
                [], events: [EventPath(endpoint: 0, cluster: GroupcastCluster.id, event: GroupcastCluster.Event.groupcastTesting)],
                session: fixture.session)
            return read?.1.contains { if case .data(let record) = $0 { record.data[7]?.uint == GroupcastCluster.GroupcastTestResultEnum.noAvailableKey } else { false } } ?? false
        }
        _ = try await fixture.invoke(0, GroupcastCluster.id, GroupcastCluster.Command.groupcastTesting,
                                     [.field(0, .unsigned(GroupcastCluster.GroupcastTestingEnum.disableTesting))])
        #expect(try await fixture.read(0, GroupcastCluster.id, GroupcastCluster.Attribute.fabricUnderTest) == .unsigned(0))
    }
}
