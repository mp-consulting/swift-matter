import Logging

/// The Interaction Model server (Core §8): answers reads, writes, invokes and subscriptions on a node's data model.
public actor InteractionServer: ProtocolHandler {
    public let dataModel: DataModel
    public let accessControl: any AccessController
    let logger: Logger
    /// The largest ReportData or InvokeResponse payload, below the IPv6 minimum MTU with headers.
    let payloadLimit: Int
    private var subscriptions: [UInt32: Subscription] = [:]
    /// Subscriptions per fabric; the spec requires at least three (Core §2.11.1).
    public var maxSubscriptionsPerFabric = 10
    /// Multiplies subscription intervals: tests run them at a fraction of their real length.
    public private(set) var timeScale = 1.0

    public func setTimeScale(_ scale: Double) { timeScale = scale }

    /// The node's groups: the Groups cluster's store, and where group messages go.
    private let groups: Groups?

    public init(dataModel: DataModel, accessControl: any AccessController, payloadLimit: Int = 1024, groups: Groups? = nil,
                logger: Logger = Logger(label: "matter.im")) {
        self.dataModel = dataModel
        self.accessControl = accessControl
        self.payloadLimit = payloadLimit
        self.groups = groups
        self.logger = logger
    }

    /// Serves the Interaction Model on a message layer; subscriptions end with their sessions.
    public func serve(on layer: MessageLayer) async throws {
        try await layer.register(self, for: .interactionModel)
        await layer.onSessionClosed { [weak self] closed in
            await self?.cancelSubscriptions { $0.localSessionID == closed.localSessionID && $0.peerSessionID == closed.peerSessionID }
        }
    }

    public nonisolated func handle(_ exchange: Exchange, first message: Message) async {
        await serve(exchange, first: message)
    }

    private func serve(_ exchange: Exchange, first message: Message) async {
        // Interactions run only over secure sessions (the message layer drops unencrypted ones).
        guard exchange.initialSession.isSecure else { return }
        do {
            var message = message
            var timedDeadline: ContinuousClock.Instant?
            if message.payloadHeader.opcode == IMOpcode.timedRequest.rawValue {
                let timeout = try TLVStruct(decoding: message.payload).uint(0, as: UInt16.self)
                timedDeadline = .now + .milliseconds(Int(timeout))
                try await exchange.sendIMStatus(.success)
                message = try await exchange.receive()
                // Only a write or an invoke may follow a Timed Request (Core §8.6).
                guard [IMOpcode.writeRequest.rawValue, IMOpcode.invokeRequest.rawValue].contains(message.payloadHeader.opcode) else {
                    throw StatusError(.invalidAction)
                }
            }
            switch IMOpcode(rawValue: message.payloadHeader.opcode) {
            case .readRequest: try await read(message, on: exchange)
            case .subscribeRequest: try await subscribe(message, on: exchange)
            case .writeRequest: try await write(message, on: exchange, timedDeadline: timedDeadline)
            case .invokeRequest: try await invoke(message, on: exchange, timedDeadline: timedDeadline)
            default: try await exchange.sendIMStatus(.invalidAction)
            }
        } catch let status as StatusError {
            logger.debug("Interaction with \(exchange.initialSession.peerAddress) answered \(status.status)")
            try? await exchange.sendIMStatus(status.status)
        } catch let status as IMStatus {
            logger.debug("Interaction with \(exchange.initialSession.peerAddress) answered \(status)")
            try? await exchange.sendIMStatus(status)
        } catch {
            logger.debug("Interaction with \(exchange.initialSession.peerAddress) failed: \(error)")
        }
    }

    // MARK: - Diagnostics

    static func describe(_ result: InvokeResult) -> String {
        switch result {
        case .response(let command, _): "response 0x\(String(command, radix: 16))"
        case .status(let status): "\(status.status)\(status.clusterStatus.map { " (cluster status \($0))" } ?? "")"
        }
    }

    // MARK: - Groups

    /// A group's write or invoke (Core §8.2.3): carried out on every endpoint of the group that has the cluster, with
    /// the group's access, and never answered. Reads, subscriptions and timed interactions are not for groups.
    public nonisolated func handleGroup(_ message: Message, session: SessionInfo) async {
        await serveGroup(message, session: session)
    }

    private func serveGroup(_ message: Message, session: SessionInfo) async {
        guard let groups, let group = session.groupID, let fabric = session.fabricIndex,
              let fields = try? TLVStruct(decoding: message.payload), fields[1]?.bool != true else { return }
        let members = await groups.endpoints(of: group, fabric: fabric)
        let context = AccessContext(session: session, groups: groups)
        let testing = groups.isTesting
        /// A path's endpoint when it is a member, or every member: an endpoint without the cluster answers
        /// `unsupportedCluster`, which a group ignores like any other status.
        func targets(_ endpoint: EndpointNumber?) -> [EndpointNumber] { endpoint.map { members.contains($0) ? [$0] : [] } ?? members }
        switch IMOpcode(rawValue: message.payloadHeader.opcode) {
        case .invokeRequest:
            for request in (try? fields.elements(2)) ?? [] {
                guard let pathValue = request.value[0], var path = try? CommandPath(tlv: pathValue) else { continue }
                for endpoint in targets(path.endpoint) {
                    path.endpoint = endpoint
                    let result = await invoke(path, fields: request.value[1] ?? .structure([]), context: context)
                    // Groupcast testing reports each concrete path the invoke reached (Core §11.27.7.6).
                    guard testing else { continue }
                    let status = if case .status(let status) = result { status.status } else { IMStatus.success }
                    if [.unsupportedEndpoint, .unsupportedCluster, .unsupportedCommand].contains(status) { continue }
                    await groups.reportTest(GroupcastCluster.GroupcastTestResultEnum.success, fabric: fabric, group: group, path: path,
                                            allowed: status != .unsupportedAccess)
                }
            }
        case .writeRequest:
            for element in (try? fields.elements(2)) ?? [] {
                guard let pathValue = element.value[1], let value = element.value[2], var path = try? AttributePath(tlv: pathValue) else { continue }
                for endpoint in targets(path.endpoint) {
                    path.endpoint = endpoint
                    _ = await write(path, value: value, dataVersion: nil, context: context)
                }
            }
        default:
            break
        }
    }

    // MARK: - Access

    /// The session's privilege on an endpoint's cluster; checked once per cluster, then compared per attribute.
    private func privilege(_ session: SessionInfo, _ endpoint: EndpointNumber, _ cluster: ClusterID) async -> Privilege? {
        let deviceTypes = await dataModel.endpoint(endpoint)?.deviceTypes.map(\.id) ?? []
        return await accessControl.privilege(of: session, endpoint: endpoint, cluster: cluster, deviceTypes: deviceTypes)
    }

    /// Why a session was refused: whom the ACL saw (node, CATs, fabric) and the privileges held and needed.
    private func logDenial(_ path: String, _ session: SessionInfo, held: Privilege?, required: Privilege) {
        logger.debug("Denied \(path) to \(session.kind) node \(zeroPadded(session.peerNodeID, width: 16, radix: 16)) on fabric \(session.fabricIndex ?? 0), CATs [\(session.caseAuthenticatedTags.map { zeroPadded($0, width: 8, radix: 16) }.joined(separator: ", "))]: holds \(held.map { "\($0)" } ?? "nothing"), needs \(required)")
    }

    private func allowed(_ session: SessionInfo, _ endpoint: EndpointNumber, _ cluster: ClusterID, _ required: Privilege) async -> Bool {
        await privilege(session, endpoint, cluster)?.grants(required) ?? false
    }

    // MARK: - Read

    struct ReadSpec {
        var attributes: [AttributePath]
        var events: [EventPath]
        var eventMinimum: UInt64
        var fabricFiltered: Bool
        var dataVersionFilters: [DataVersionFilter]
    }

    private func readSpec(_ fields: TLVStruct, attributes: UInt8, events: UInt8, eventFilters: UInt8, fabricFiltered: UInt8,
                          dataVersionFilters: UInt8) throws -> ReadSpec {
        let attributePaths = try (fields[attributes]?.elements ?? []).map { try AttributePath(tlv: $0.value) }
        let eventPaths = try (fields[events]?.elements ?? []).map { try EventPath(tlv: $0.value) }
        let minimum = try (fields[eventFilters]?.elements ?? []).compactMap { try TLVStruct($0.value).uint(1) }.max() ?? 0
        let filters = try (fields[dataVersionFilters]?.elements ?? []).map { try DataVersionFilter(tlv: $0.value) }
        guard !attributePaths.isEmpty || !eventPaths.isEmpty else { throw StatusError(.invalidAction) }
        return ReadSpec(attributes: attributePaths, events: eventPaths, eventMinimum: minimum,
                        fabricFiltered: try fields.bool(fabricFiltered), dataVersionFilters: filters)
    }

    private func read(_ message: Message, on exchange: Exchange) async throws {
        let spec = try readSpec(try TLVStruct(decoding: message.payload), attributes: 0, events: 1, eventFilters: 2,
                                fabricFiltered: 3, dataVersionFilters: 4)
        let session = await exchange.session
        logger.debug("Read of \(spec.attributes.count) attribute and \(spec.events.count) event paths from \(session.peerAddress)")
        logger.trace("Read paths: \(spec.attributes.map(\.description).joined(separator: ", "))")
        let attributes = await attributeReports(spec.attributes, session: session, fabricFiltered: spec.fabricFiltered,
                                                filters: spec.dataVersionFilters)
        let events = await eventReports(spec.events, session: session, minimum: spec.eventMinimum)
        try await sendReports(attributes, events, subscriptionID: nil, on: exchange, finalNeedsResponse: false)
    }

    /// The reports of attribute paths (Core §8.4.3.2): concrete paths report errors, wildcards skip what they cannot read.
    /// With `only`, just those attributes are reported (a subscription's changes).
    func attributeReports(_ paths: [AttributePath], session: SessionInfo, fabricFiltered: Bool,
                          filters: [DataVersionFilter] = [], only: Set<ConcreteAttribute>? = nil) async -> [AttributeReport] {
        var reports: [AttributeReport] = []
        let context = AccessContext(session: session, isFabricFiltered: fabricFiltered, groups: groups)
        var seen = Set<ConcreteAttribute>()

        func filtered(_ endpoint: EndpointNumber, _ cluster: ClusterID, _ version: UInt32) -> Bool {
            filters.contains { $0.endpoint == endpoint && $0.cluster == cluster && $0.version == version }
        }

        for path in paths {
            if let endpoint = path.endpoint, let clusterID = path.cluster, let attribute = path.attribute {
                guard await dataModel.endpoint(endpoint) != nil else {
                    if only == nil { reports.append(.status(path: path, StatusError(.unsupportedEndpoint))) }
                    continue
                }
                guard let cluster = await dataModel.cluster(clusterID, on: endpoint) else {
                    if only == nil { reports.append(.status(path: path, StatusError(.unsupportedCluster))) }
                    continue
                }
                let version = await cluster.dataVersion
                if filtered(endpoint, clusterID, version) { continue }
                let privilege = await privilege(session, endpoint, clusterID)
                if let report = await collect(cluster, endpoint, attribute, version: version, privilege: privilege, context: context,
                                              only: only, seen: &seen, requested: only == nil ? path : nil) {
                    reports.append(report)
                }
                continue
            }
            // Changes name their clusters: a subscription's wildcard paths need not walk the whole node.
            let targets: [(EndpointNumber, any ClusterHandler)]
            if let only {
                var clusters: [(EndpointNumber, any ClusterHandler)] = []
                for key in Set(only.map { ConcreteCluster(endpoint: $0.endpoint, cluster: $0.cluster) })
                    where (path.endpoint ?? key.endpoint) == key.endpoint && (path.cluster ?? key.cluster) == key.cluster {
                    if let cluster = await dataModel.cluster(key.cluster, on: key.endpoint) { clusters.append((key.endpoint, cluster)) }
                }
                targets = clusters
            } else {
                targets = await dataModel.clusters(endpoint: path.endpoint, cluster: path.cluster)
            }
            for (endpoint, cluster) in targets {
                let privilege = await privilege(session, endpoint, cluster.id)
                guard privilege?.grants(.view) == true else { continue }
                let version = await cluster.dataVersion
                if filtered(endpoint, cluster.id, version) { continue }
                let ids: [AttributeID]
                if let attribute = path.attribute { ids = [attribute] } else { ids = await cluster.attributeIDs + GlobalAttribute.all }
                for attribute in ids {
                    if let report = await collect(cluster, endpoint, attribute, version: version, privilege: privilege, context: context,
                                                  only: only, seen: &seen, requested: nil) {
                        reports.append(report)
                    }
                }
            }
        }
        return reports
    }

    /// Reads an attribute once per request; errors are reported only for concrete paths (`requested`).
    private func collect(_ cluster: any ClusterHandler, _ endpoint: EndpointNumber, _ attribute: AttributeID, version: UInt32,
                         privilege: Privilege?, context: AccessContext, only: Set<ConcreteAttribute>?,
                         seen: inout Set<ConcreteAttribute>, requested: AttributePath?) async -> AttributeReport? {
        let concrete = ConcreteAttribute(endpoint, cluster.id, attribute)
        guard only?.contains(concrete) ?? true, !seen.contains(concrete) else { return nil }
        let report = await readAttribute(cluster, endpoint, attribute, version: version, privilege: privilege, context: context)
        if case .data = report { seen.insert(concrete) }
        if case .status(_, let status) = report { return requested.map { .status(path: $0, status) } }
        return report
    }

    /// One attribute's value, or the status that keeps it from being read.
    private func readAttribute(_ cluster: any ClusterHandler, _ endpoint: EndpointNumber, _ attribute: AttributeID, version: UInt32,
                               privilege: Privilege?, context: AccessContext) async -> AttributeReport {
        let path = AttributePath(endpoint: endpoint, cluster: cluster.id, attribute: attribute)
        guard privilege?.grants(cluster.definition.attribute(attribute)?.read ?? .view) == true else {
            return .status(path: path, StatusError(.unsupportedAccess))
        }
        do {
            return .data(path: path, dataVersion: version, value: try await cluster.read(attribute, context: context))
        } catch {
            return .status(path: path, error as? StatusError ?? StatusError(.failure))
        }
    }

    func eventReports(_ paths: [EventPath], session: SessionInfo, minimum: UInt64, only: [EventRecord]? = nil) async -> [EventReport] {
        guard !paths.isEmpty else { return [] }
        var reports: [EventReport] = []
        let records: [EventRecord]
        if let only { records = only } else { records = await dataModel.events(from: minimum) }
        var privileges: [ConcreteCluster: Privilege?] = [:]
        for record in records where paths.contains(where: { $0.matches(record) }) {
            let key = ConcreteCluster(endpoint: record.endpoint, cluster: record.cluster)
            if privileges[key] == nil { privileges[key] = .some(await privilege(session, record.endpoint, record.cluster)) }
            let required = await dataModel.cluster(record.cluster, on: record.endpoint)?.definition.event(record.event)?.read ?? .view
            guard privileges[key]??.grants(required) == true else { continue }
            // Fabric-sensitive events are only shown to their fabric.
            if let fabric = record.fabricIndex, fabric != session.fabricIndex { continue }
            reports.append(.data(record))
        }
        return reports
    }

    // MARK: - Reports

    /// Sends attribute and event reports in as many ReportData messages as needed (Core §10.2.3): every chunk but the
    /// last waits for a StatusResponse, and so does the last when `finalNeedsResponse` (subscriptions).
    func sendReports(_ attributes: [AttributeReport], _ events: [EventReport], subscriptionID: UInt32?, on exchange: Exchange,
                     finalNeedsResponse: Bool) async throws {
        // Each report is encoded once; chunks are filled by their encoded sizes.
        let attributeElements = attributes.flatMap { split($0) }.map { TLVElement($0.tlv) }
        let eventElements = events.map { TLVElement($0.tlv) }
        let items = attributeElements.map { (isEvent: false, element: $0, size: TLVEncoder.encode($0).count) }
            + eventElements.map { (isEvent: true, element: $0, size: TLVEncoder.encode($0).count) }
        // Room for the message's own fields: subscription id, array headers, flags and the revision.
        let budget = payloadLimit - 24
        var index = 0
        repeat {
            var chunkAttributes: [TLVElement] = []
            var chunkEvents: [TLVElement] = []
            var size = 0
            while index < items.count, chunkAttributes.isEmpty && chunkEvents.isEmpty || size + items[index].size <= budget {
                let item = items[index]
                if item.isEvent { chunkEvents.append(item.element) } else { chunkAttributes.append(item.element) }
                size += item.size
                index += 1
            }
            let more = index < items.count
            var fields: [TLVElement] = []
            if let subscriptionID { fields.append(.field(0, .unsigned(UInt64(subscriptionID)))) }
            if !chunkAttributes.isEmpty { fields.append(.field(1, .array(chunkAttributes))) }
            if !chunkEvents.isEmpty { fields.append(.field(2, .array(chunkEvents))) }
            if more { fields.append(.field(3, .bool(true))) }
            if !more && !finalNeedsResponse { fields.append(.field(4, .bool(true))) }
            fields.append(interactionModelRevisionField)
            try await exchange.send(IMOpcode.reportData.rawValue, TLVEncoder.encode(.structure(fields)))
            if more || finalNeedsResponse { try await expectStatusResponse(on: exchange) }
        } while index < items.count
    }

    /// A list too large for one message goes as an empty list and then one append per entry (Core §10.6.4.3.1).
    private func split(_ report: AttributeReport) -> [AttributeReport] {
        // Only lists can be split, so only they are measured.
        guard case .data(let path, let version, .array(let entries)) = report,
              TLVEncoder.encode(report.tlv).count > payloadLimit - 64
        else { return [report] }
        var appended = path
        appended.listIndex = .append
        return [.data(path: path, dataVersion: version, value: .array([]))]
            + entries.map { .data(path: appended, dataVersion: version, value: $0.value) }
    }

    func expectStatusResponse(on exchange: Exchange) async throws {
        guard let status = try StatusError(statusResponse: try await exchange.receive()) else { throw StatusError(.invalidAction) }
        guard status.status == .success else { throw status }
    }

    // MARK: - Write

    private func write(_ message: Message, on exchange: Exchange, timedDeadline: ContinuousClock.Instant?) async throws {
        var message = message
        var isFirstChunk = true
        while true {
            let fields = try TLVStruct(decoding: message.payload)
            // The Timed Request's window bounds only the first chunk.
            try checkTimed(fields.bool(1), deadline: isFirstChunk ? timedDeadline : nil, timed: timedDeadline != nil)
            isFirstChunk = false
            let session = await exchange.session
            let context = AccessContext(session: session, isTimed: timedDeadline != nil, exchange: exchange, groups: groups)
            var statuses: [TLVElement] = []
            for element in try fields.elements(2) {
                let data = try TLVStruct(element.value)
                guard let pathValue = data[1], let value = data[2] else { throw StatusError(.invalidAction) }
                let path = try AttributePath(tlv: pathValue)
                let status = await write(path, value: value, dataVersion: try? data.uint(0, as: UInt32.self), context: context)
                logger.debug("Write \(path) from \(session.peerAddress): \(status.status)")
                statuses.append(TLVElement(.structure([.field(0, path.tlv), .field(1, status.tlv)])))
            }
            let more = fields[3]?.bool ?? false
            if fields[0]?.bool != true || more {
                try await exchange.send(IMOpcode.writeResponse.rawValue, TLVEncoder.encode(.structure([
                    .field(0, .array(statuses)), interactionModelRevisionField,
                ])))
            }
            guard more else { return }
            message = try await exchange.receive()
            guard message.payloadHeader.opcode == IMOpcode.writeRequest.rawValue else { throw StatusError(.invalidAction) }
        }
    }

    private func write(_ path: AttributePath, value: TLVValue, dataVersion: UInt32?, context: AccessContext) async -> StatusError {
        guard let endpoint = path.endpoint, let clusterID = path.cluster, let attribute = path.attribute else {
            return StatusError(.unsupportedAttribute) // Wildcard writes are for groups only.
        }
        guard await dataModel.endpoint(endpoint) != nil else { return StatusError(.unsupportedEndpoint) }
        guard let cluster = await dataModel.cluster(clusterID, on: endpoint) else { return StatusError(.unsupportedCluster) }
        guard let definition = cluster.definition.attribute(attribute), await cluster.attributeIDs.contains(attribute) else {
            return StatusError(GlobalAttribute.all.contains(attribute) ? .unsupportedWrite : .unsupportedAttribute)
        }
        guard let required = definition.write else {
            return StatusError(await allowed(context.session, endpoint, clusterID, definition.read) ? .unsupportedWrite : .unsupportedAccess)
        }
        let privilege = await privilege(context.session, endpoint, clusterID)
        guard privilege?.grants(required) ?? false else {
            logDenial("\(path)", context.session, held: privilege, required: required)
            return StatusError(.unsupportedAccess)
        }
        if definition.flags.contains(.timedWrite), !context.isTimed { return StatusError(.needsTimedInteraction) }
        if definition.flags.contains(.fabricScoped), context.fabricIndex == nil { return StatusError(.unsupportedAccess) }
        if let dataVersion, await cluster.dataVersion != dataVersion { return StatusError(.dataVersionMismatch) }
        do {
            var value = value
            if path.listIndex == .append {
                // Appending reads the list as the accessing fabric sees it and writes it back with the entry.
                let current = try await cluster.read(attribute, context: context)
                value = .array((current.elements ?? []) + [TLVElement(value)])
            }
            try await cluster.write(attribute, value: value, context: context)
            return StatusError(.success)
        } catch {
            return error as? StatusError ?? StatusError(.failure)
        }
    }

    private func checkTimed(_ flagged: Bool, deadline: ContinuousClock.Instant?, timed: Bool? = nil) throws {
        // The timed flag and a preceding Timed Request go together (Core §8.7.2, §8.8.2).
        guard flagged == (timed ?? (deadline != nil)) else { throw StatusError(.timedRequestMismatch) }
        if let deadline, ContinuousClock.now > deadline { throw StatusError(.timeout) }
    }

    // MARK: - Invoke

    private func invoke(_ message: Message, on exchange: Exchange, timedDeadline: ContinuousClock.Instant?) async throws {
        let fields = try TLVStruct(decoding: message.payload)
        try checkTimed(fields.bool(1), deadline: timedDeadline)
        let requests = try fields.elements(2)
        guard !requests.isEmpty else { throw StatusError(.invalidAction) }
        let session = await exchange.session
        let context = AccessContext(session: session, isTimed: timedDeadline != nil, exchange: exchange, groups: groups)
        var responses: [TLVElement] = []
        for request in requests {
            let data = try TLVStruct(request.value)
            guard let pathValue = data[0] else { throw StatusError(.invalidAction) }
            let path = try CommandPath(tlv: pathValue)
            // Several commands in one request need a ref each (Core §8.8.2.1).
            let ref = data[2]?.uint
            if requests.count > 1, ref == nil { throw StatusError(.invalidAction) }
            let result = await invoke(path, fields: data[1] ?? .structure([]), context: context)
            // The command and its outcome, never its fields (they carry certificates and keys).
            logger.debug("Invoke \(path) from \(session.peerAddress): \(Self.describe(result))")
            var response: [TLVElement]
            switch result {
            case .response(let command, let responseFields):
                var commandPath = path
                commandPath.command = command
                response = [.field(0, .structure([.field(0, commandPath.tlv), TLVElement(.context(1), responseFields)]
                    + (ref.map { [.field(2, .unsigned($0))] } ?? [])))]
            case .status(let status):
                response = [.field(1, .structure([.field(0, path.tlv), .field(1, status.tlv)]
                    + (ref.map { [.field(2, .unsigned($0))] } ?? [])))]
            }
            responses.append(TLVElement(.structure(response)))
        }
        if fields[0]?.bool == true { return } // SuppressResponse
        try await exchange.send(IMOpcode.invokeResponse.rawValue, TLVEncoder.encode(.structure([
            .field(0, .bool(false)), .field(1, .array(responses)), interactionModelRevisionField,
        ])))
    }

    private func invoke(_ path: CommandPath, fields: TLVValue, context: AccessContext) async -> InvokeResult {
        guard let endpoint = path.endpoint else { return .status(StatusError(.unsupportedEndpoint)) }
        guard await dataModel.endpoint(endpoint) != nil else { return .status(StatusError(.unsupportedEndpoint)) }
        guard let cluster = await dataModel.cluster(path.cluster, on: endpoint) else { return .status(StatusError(.unsupportedCluster)) }
        guard await cluster.acceptedCommands.contains(path.command), let definition = cluster.definition.command(path.command) else {
            return .status(StatusError(.unsupportedCommand))
        }
        let privilege = await privilege(context.session, endpoint, path.cluster)
        guard privilege?.grants(definition.invoke) ?? false else {
            logDenial("\(path)", context.session, held: privilege, required: definition.invoke)
            return .status(StatusError(.unsupportedAccess))
        }
        if definition.fabricScoped, context.fabricIndex == nil { return .status(StatusError(.unsupportedAccess)) }
        if definition.timed, !context.isTimed { return .status(StatusError(.needsTimedInteraction)) }
        var context = context
        context.privilege = privilege
        do {
            return try await cluster.invoke(path.command, fields: fields, context: context)
        } catch {
            return .status(error as? StatusError ?? StatusError(.failure))
        }
    }

    // MARK: - Subscribe

    private func subscribe(_ message: Message, on exchange: Exchange) async throws {
        let fields = try TLVStruct(decoding: message.payload)
        let spec = try readSpec(fields, attributes: 3, events: 4, eventFilters: 5, fabricFiltered: 7, dataVersionFilters: 8)
        let session = await exchange.session
        let floor = try fields.uint(1, as: UInt16.self)
        let ceiling = try fields.uint(2, as: UInt16.self)
        guard floor <= ceiling else { throw StatusError(.invalidAction) }
        if try !fields.bool(0) {
            // KeepSubscriptions false: the subscriber's earlier subscriptions end (Core §8.5.3.1).
            for (id, existing) in subscriptions where existing.isFrom(session) { await cancelSubscription(id) }
        }
        let fabricCount = subscriptions.values.filter { $0.session.fabricIndex == session.fabricIndex }.count
        guard fabricCount < maxSubscriptionsPerFabric else { throw StatusError(.resourceExhausted) }

        var id: UInt32
        repeat { id = UInt32.random(in: 1...UInt32.max) } while subscriptions[id] != nil
        // The publisher may raise the maximum interval up to an hour (Core §8.5.2.1).
        let maxInterval = max(floor, min(max(ceiling, 60), 3600))

        let attributes = await attributeReports(spec.attributes, session: session, fabricFiltered: spec.fabricFiltered,
                                                filters: spec.dataVersionFilters)
        let events = await eventReports(spec.events, session: session, minimum: spec.eventMinimum)
        try await sendReports(attributes, events, subscriptionID: id, on: exchange, finalNeedsResponse: true)
        try await exchange.send(IMOpcode.subscribeResponse.rawValue, TLVEncoder.encode(.structure([
            .field(0, .unsigned(UInt64(id))), .field(2, .unsigned(UInt64(maxInterval))), interactionModelRevisionField,
        ])))

        let subscription = Subscription(id: id, session: session, spec: spec, minInterval: .seconds(Int(floor)) * timeScale,
                                        maxInterval: .seconds(Int(maxInterval)) * timeScale, server: self,
                                        eventMinimum: max(spec.eventMinimum, await dataModel.eventNumber))
        subscriptions[id] = subscription
        await subscription.start(layer: exchange.layer)
        logger.debug("Subscription \(id) for \(session.peerAddress), max interval \(maxInterval) s")
    }

    func cancelSubscription(_ id: UInt32) async {
        guard let subscription = subscriptions.removeValue(forKey: id) else { return }
        await subscription.cancel()
    }

    /// Ends the subscriptions of a closed session or removed fabric.
    public func cancelSubscriptions(where shouldCancel: @Sendable (SessionInfo) -> Bool) async {
        for (id, subscription) in subscriptions where shouldCancel(subscription.session) { await cancelSubscription(id) }
    }

    public var subscriptionCount: Int { subscriptions.count }
}

/// An attribute on a cluster on an endpoint.
public struct ConcreteAttribute: Hashable, Sendable {
    public var endpoint: EndpointNumber
    public var cluster: ClusterID
    public var attribute: AttributeID

    public init(_ endpoint: EndpointNumber, _ cluster: ClusterID, _ attribute: AttributeID) {
        self.endpoint = endpoint
        self.cluster = cluster
        self.attribute = attribute
    }
}

/// An endpoint's cluster, for subscriptions to notice newly added ones.
struct ConcreteCluster: Hashable, Sendable {
    var endpoint: EndpointNumber
    var cluster: ClusterID
}

extension AttributeReport {
    var cluster: ConcreteCluster? {
        guard case .data(let path, _, _) = self, let endpoint = path.endpoint, let cluster = path.cluster else { return nil }
        return ConcreteCluster(endpoint: endpoint, cluster: cluster)
    }
}
