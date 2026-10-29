import Testing
@testable import Matter

/// A device with an On/Off light on endpoint 1 and a long label list on endpoint 2, and a commissioner holding a PASE
/// session (which has Administer).
struct IMFixture {
    let pair: Pair
    let model = DataModel()
    let server: InteractionServer
    let client: InteractionClient
    let session: UInt16
    let onOff: AttributeCluster

    init() async throws {
        pair = try await Pair()
        server = InteractionServer(dataModel: model, accessControl: AccessControlList(), payloadLimit: 400)
        await server.setTimeScale(0.01)
        try await pair.device.register(server, for: .interactionModel)
        client = InteractionClient(layer: pair.controller)
        try await pair.controller.register(client, for: .interactionModel)

        onOff = AttributeCluster(OnOffCluster.definition, attributes: [OnOffCluster.Attribute.onOff: .bool(false)])
        let model = model
        await onOff.handle(OnOffCluster.Command.toggle) { cluster, _, _ in
            let current = await cluster.value(OnOffCluster.Attribute.onOff)?.bool ?? false
            await cluster.set(OnOffCluster.Attribute.onOff, .bool(!current))
            await model.emit(endpoint: 1, cluster: OnOffCluster.id, event: 0x99, priority: .info, data: .structure([.field(0, .bool(!current))]))
            return .success
        }
        await onOff.handle(OnOffCluster.Command.offWithEffect) { _, fields, _ in
            guard fields[0]?.uint != nil else { throw StatusError(.invalidCommand) }
            return .success
        }
        try await model.add(Endpoint(number: 0, deviceTypes: [DeviceTypes.rootNode], clusters: []))
        try await model.add(Endpoint(number: 1, deviceTypes: [DeviceTypes.onOffLight], clusters: [onOff]))
        let labels = (0..<40).map { index in
            TLVElement(.structure([.field(0, .utf8("label \(index)")), .field(1, .utf8("value \(index)"))]))
        }
        let fixedLabel = AttributeCluster(FixedLabelCluster.definition, attributes: [FixedLabelCluster.Attribute.labelList: .array(labels)])
        try await model.add(Endpoint(number: 2, deviceTypes: [DeviceTypes.onOffLight], clusters: [fixedLabel], parent: 1))

        session = try await PASE.establish(with: .memory("device"), passcode: Pair.passcode, layer: pair.controller).localSessionID
    }
}

struct InteractionTests {
    @Test func readsConcreteAndWildcardPaths() async throws {
        let fixture = try await IMFixture()
        let value = try await fixture.client.read(endpoint: 1, cluster: OnOffCluster.id, attribute: OnOffCluster.Attribute.onOff,
                                                  session: fixture.session)
        #expect(value == .bool(false))

        // Descriptor: endpoint 0 lists both endpoints, endpoint 1 lists its child.
        let parts = try await fixture.client.read(endpoint: 1, cluster: DescriptorCluster.id, attribute: DescriptorCluster.Attribute.partsList,
                                                  session: fixture.session)
        #expect(parts == .array([TLVElement(.unsigned(2))]))
        let serverList = try await fixture.client.read(endpoint: 1, cluster: DescriptorCluster.id, attribute: DescriptorCluster.Attribute.serverList,
                                                       session: fixture.session)
        #expect(serverList == .array([TLVElement(.unsigned(UInt64(OnOffCluster.id))), TLVElement(.unsigned(UInt64(DescriptorCluster.id)))]))

        // A wildcard over endpoint 1's clusters reports every attribute and no errors.
        let (reports, _) = try await fixture.client.read([AttributePath(endpoint: 1)], session: fixture.session)
        #expect(reports.count == 2 * GlobalAttribute.all.count + 1 + 4)
        #expect(!reports.contains { if case .status = $0 { true } else { false } })
    }

    @Test func reportsErrorsForConcretePaths() async throws {
        let fixture = try await IMFixture()
        await #expect(throws: StatusError(.unsupportedEndpoint)) {
            try await fixture.client.read(endpoint: 9, cluster: OnOffCluster.id, attribute: 0, session: fixture.session)
        }
        await #expect(throws: StatusError(.unsupportedCluster)) {
            try await fixture.client.read(endpoint: 1, cluster: 0x0300, attribute: 0, session: fixture.session)
        }
        await #expect(throws: StatusError(.unsupportedAttribute)) {
            try await fixture.client.read(endpoint: 1, cluster: OnOffCluster.id, attribute: 0x4000, session: fixture.session)
        }
    }

    @Test func chunksLargeLists() async throws {
        let fixture = try await IMFixture()
        let value = try await fixture.client.read(endpoint: 2, cluster: FixedLabelCluster.id, attribute: FixedLabelCluster.Attribute.labelList,
                                                  session: fixture.session)
        #expect(value.elements?.count == 40)
        #expect(value.elements?.last?.value[0] == .utf8("label 39"))
    }

    @Test func invokesCommandsAndReportsEvents() async throws {
        let fixture = try await IMFixture()
        let result = try await fixture.client.invoke(CommandPath(endpoint: 1, cluster: OnOffCluster.id, command: OnOffCluster.Command.toggle),
                                                     session: fixture.session)
        guard case .status(let status) = result else { Issue.record("Expected a status"); return }
        #expect(status.status == .success)
        #expect(try await fixture.client.read(endpoint: 1, cluster: OnOffCluster.id, attribute: 0, session: fixture.session) == .bool(true))

        let (_, events) = try await fixture.client.read([], events: [EventPath(endpoint: 1)], session: fixture.session)
        guard case .data(let record)? = events.first else { Issue.record("Expected an event"); return }
        #expect(record.event == 0x99)
        #expect(record.data[0] == .bool(true))

        let unsupported = try await fixture.client.invoke(CommandPath(endpoint: 1, cluster: OnOffCluster.id, command: OnOffCluster.Command.on),
                                                          session: fixture.session)
        guard case .status(let error) = unsupported else { Issue.record("Expected a status"); return }
        #expect(error.status == .unsupportedCommand)

        let invalid = try await fixture.client.invoke(CommandPath(endpoint: 1, cluster: OnOffCluster.id, command: OnOffCluster.Command.offWithEffect),
                                                      session: fixture.session)
        guard case .status(let invalidStatus) = invalid else { Issue.record("Expected a status"); return }
        #expect(invalidStatus.status == .invalidCommand)
    }

    @Test func writesAttributes() async throws {
        let fixture = try await IMFixture()
        await fixture.onOff.set(OnOffCluster.Attribute.onTime, .unsigned(0))
        let statuses = try await fixture.client.write([
            (AttributePath(endpoint: 1, cluster: OnOffCluster.id, attribute: OnOffCluster.Attribute.onTime), .unsigned(30)),
            (AttributePath(endpoint: 1, cluster: OnOffCluster.id, attribute: OnOffCluster.Attribute.onOff), .bool(true)),
        ], session: fixture.session)
        #expect(statuses.map(\.1.status) == [.success, .unsupportedWrite])
        #expect(await fixture.onOff.value(OnOffCluster.Attribute.onTime) == .unsigned(30))
    }

    @Test func enforcesTimedInteractions() async throws {
        let fixture = try await IMFixture()
        let admin = AttributeCluster(AdministratorCommissioningCluster.definition, attributes: [0: .unsigned(0)])
        await admin.handle(AdministratorCommissioningCluster.Command.revokeCommissioning) { _, _, _ in .success }
        try await fixture.model.add(Endpoint(number: 3, deviceTypes: [], clusters: [admin]))
        let path = CommandPath(endpoint: 3, cluster: AdministratorCommissioningCluster.id,
                               command: AdministratorCommissioningCluster.Command.revokeCommissioning)

        guard case .status(let untimed) = try await fixture.client.invoke(path, session: fixture.session) else { return }
        #expect(untimed.status == .needsTimedInteraction)
        guard case .status(let timed) = try await fixture.client.invoke(path, timed: .seconds(5), session: fixture.session) else { return }
        #expect(timed.status == .success)
    }

    @Test func subscriptionsReportChanges() async throws {
        let fixture = try await IMFixture()
        let path = AttributePath(endpoint: 1, cluster: OnOffCluster.id, attribute: OnOffCluster.Attribute.onOff)
        let subscription = try await fixture.client.subscribe([path], events: [EventPath(endpoint: 1)], minInterval: 0, maxInterval: 60,
                                                              session: fixture.session)
        var reports = subscription.reports.makeAsyncIterator()
        let priming = await reports.next()
        #expect(priming?.attributes.count == 1)

        await fixture.onOff.set(OnOffCluster.Attribute.onOff, .bool(true))
        let change = await reports.next()
        guard case .data(_, _, let value)? = change?.attributes.first else { Issue.record("Expected a change"); return }
        #expect(value == .bool(true))
        #expect(await fixture.server.subscriptionCount == 1)

        // Keep-alive: an empty report at the (scaled) maximum interval.
        let keepAlive = await reports.next()
        #expect(keepAlive?.attributes.isEmpty == true)
    }

    @Test func subscriptionsSeeNewEndpoints() async throws {
        let fixture = try await IMFixture()
        let subscription = try await fixture.client.subscribe([AttributePath(cluster: OnOffCluster.id, attribute: OnOffCluster.Attribute.onOff)],
                                                              minInterval: 0, maxInterval: 60, session: fixture.session)
        var reports = subscription.reports.makeAsyncIterator()
        _ = await reports.next()
        let light = AttributeCluster(OnOffCluster.definition, attributes: [OnOffCluster.Attribute.onOff: .bool(true)])
        try await fixture.model.add(Endpoint(number: 7, deviceTypes: [DeviceTypes.onOffLight], clusters: [light]))
        var sawNewEndpoint = false
        for _ in 0..<3 {
            guard let report = await reports.next() else { break }
            if report.attributes.contains(where: { $0.cluster?.endpoint == 7 }) { sawNewEndpoint = true; break }
        }
        #expect(sawNewEndpoint)
    }
}

struct AccessControlTests {
    func session(node: UInt64, fabric: FabricIndex = 1, tags: [UInt32] = []) -> SessionInfo {
        SessionInfo(kind: .case, localSessionID: 1, peerSessionID: 1, fabricIndex: fabric, peerNodeID: node,
                    caseAuthenticatedTags: tags, peerAddress: .memory("peer"))
    }

    @Test func grantsByNodeCATAndTarget() async {
        let acl = AccessControlList(entries: [
            AccessControlEntry(fabricIndex: 1, privilege: .administer, authMode: .case, subjects: [0x1122]),
            AccessControlEntry(fabricIndex: 1, privilege: .operate, authMode: .case, subjects: [0xFFFF_FFFD_0001_0002],
                               targets: [.init(endpoint: 1)]),
            AccessControlEntry(fabricIndex: 1, privilege: .view, authMode: .case, subjects: nil, targets: [.init(cluster: 6)]),
        ])
        #expect(await acl.privilege(of: session(node: 0x1122), endpoint: 0, cluster: 0x28, deviceTypes: []) == .administer)
        #expect(await acl.privilege(of: session(node: 0x1122, fabric: 2), endpoint: 0, cluster: 0x28, deviceTypes: []) == nil)
        // A CAT of version 3 satisfies a subject requiring version 2; version 1 does not.
        #expect(await acl.privilege(of: session(node: 5, tags: [0x0001_0003]), endpoint: 1, cluster: 0x300, deviceTypes: []) == .operate)
        #expect(await acl.privilege(of: session(node: 5, tags: [0x0001_0001]), endpoint: 1, cluster: 0x300, deviceTypes: []) == nil)
        #expect(await acl.privilege(of: session(node: 5), endpoint: 4, cluster: 6, deviceTypes: []) == .view)
        #expect(Privilege.manage.grants(.operate))
        #expect(!Privilege.operate.grants(.manage))
        #expect(!Privilege.view.grants(.proxyView))
    }

    @Test func validatesWrittenEntries() throws {
        let entry = AccessControlEntry(fabricIndex: 1, privilege: .manage, authMode: .case, subjects: [7], targets: [.init(cluster: 6, endpoint: 1)])
        #expect(try AccessControlEntry(tlv: entry.tlv) == entry)
        var pase = entry.tlv
        if case .structure(var fields) = pase { fields[1] = .field(2, .unsigned(1)); pase = .structure(fields) }
        #expect(throws: StatusError(.constraintError)) { try AccessControlEntry(tlv: pase) }
    }
}

struct FabricScopedListTests {
    func context(fabric: FabricIndex, filtered: Bool = true) -> AccessContext {
        AccessContext(session: SessionInfo(kind: .case, localSessionID: 1, peerSessionID: 1, fabricIndex: fabric, peerAddress: .memory("p")),
                      isFabricFiltered: filtered)
    }

    @Test func isolatesFabrics() async throws {
        let binding = AttributeCluster(BindingCluster.definition, attributes: [BindingCluster.Attribute.binding: .array([])])
        let entry = TLVValue.structure([.field(1, .unsigned(42)), .field(fabricIndexFieldTag, .unsigned(9))])
        try await binding.write(BindingCluster.Attribute.binding, value: .array([TLVElement(entry)]), context: context(fabric: 1))
        try await binding.write(BindingCluster.Attribute.binding, value: .array([TLVElement(entry)]), context: context(fabric: 2))

        // The written FabricIndex is replaced by the writer's.
        let own = try await binding.read(BindingCluster.Attribute.binding, context: context(fabric: 1))
        #expect(own.elements?.map { $0.value[fabricIndexFieldTag] } == [.unsigned(1)])
        #expect(own.elements?.first?.value[1] == .unsigned(42))

        // Unfiltered, another fabric's entry shows only its FabricIndex.
        let unfiltered = try await binding.read(BindingCluster.Attribute.binding, context: context(fabric: 1, filtered: false))
        #expect(unfiltered.elements?.count == 2)
        #expect(unfiltered.elements?.last?.value == .structure([.field(fabricIndexFieldTag, .unsigned(2))]))

        // Clearing fabric 1's list leaves fabric 2's entry.
        try await binding.write(BindingCluster.Attribute.binding, value: .array([]), context: context(fabric: 1))
        #expect(try await binding.read(BindingCluster.Attribute.binding, context: context(fabric: 2)).elements?.count == 1)

        await #expect(throws: StatusError(.constraintError)) {
            try await binding.write(BindingCluster.Attribute.binding, value: .array([TLVElement(.unsigned(1))]), context: context(fabric: 1))
        }
    }
}
