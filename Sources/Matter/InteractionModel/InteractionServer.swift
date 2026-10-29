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
    public var timeScale = 1.0

    public func setTimeScale(_ scale: Double) { timeScale = scale }

    public init(dataModel: DataModel, accessControl: any AccessController, payloadLimit: Int = 1024,
                logger: Logger = Logger(label: "matter.im")) {
        self.dataModel = dataModel
        self.accessControl = accessControl
        self.payloadLimit = payloadLimit
        self.logger = logger
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
                try await sendStatus(.success, on: exchange)
                message = try await exchange.receive()
            }
            switch IMOpcode(rawValue: message.payloadHeader.opcode) {
            case .readRequest: try await read(message, on: exchange)
            case .subscribeRequest: try await subscribe(message, on: exchange)
            case .writeRequest: try await write(message, on: exchange, timedDeadline: timedDeadline)
            case .invokeRequest: try await invoke(message, on: exchange, timedDeadline: timedDeadline)
            default: try await sendStatus(.invalidAction, on: exchange)
            }
        } catch let status as StatusError {
            try? await sendStatus(status.status, on: exchange)
        } catch let status as IMStatus {
            try? await sendStatus(status, on: exchange)
        } catch {
            logger.debug("Interaction with \(exchange.initialSession.peerAddress) failed: \(error)")
        }
    }

    func sendStatus(_ status: IMStatus, on exchange: Exchange) async throws {
        try await exchange.send(IMOpcode.statusResponse.rawValue, TLVEncoder.encode(.structure([
            .field(0, .unsigned(UInt64(status.rawValue))), .field(interactionModelRevisionTag, imRevision),
        ])))
    }

    var imRevision: TLVValue { .unsigned(UInt64(SpecificationVersion.interactionModelRevision)) }

    // MARK: - Access

    private func privilege(_ session: SessionInfo, _ endpoint: EndpointNumber, _ cluster: ClusterID) async -> Privilege? {
        let deviceTypes = await dataModel.endpoint(endpoint)?.deviceTypes.map(\.id) ?? []
        return await accessControl.privilege(of: session, endpoint: endpoint, cluster: cluster, deviceTypes: deviceTypes)
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
        let attributes = await attributeReports(spec.attributes, session: session, fabricFiltered: spec.fabricFiltered,
                                                filters: spec.dataVersionFilters)
        let events = await eventReports(spec.events, session: session, minimum: spec.eventMinimum)
        try await sendReports(attributes, events, subscriptionID: nil, on: exchange, finalNeedsResponse: false)
    }

    /// The reports of attribute paths (Core §8.4.3.2): concrete paths report errors, wildcards skip what they cannot read.
    func attributeReports(_ paths: [AttributePath], session: SessionInfo, fabricFiltered: Bool,
                          filters: [DataVersionFilter] = [], only: Set<ConcreteAttribute>? = nil) async -> [AttributeReport] {
        var reports: [AttributeReport] = []
        let context = AccessContext(session: session, isFabricFiltered: fabricFiltered)
        var seen = Set<ConcreteAttribute>()
        for path in paths {
            if path.isConcrete, let endpoint = path.endpoint, let clusterID = path.cluster, let attribute = path.attribute {
                if let only, !only.contains(ConcreteAttribute(endpoint, clusterID, attribute)) { continue }
                guard await dataModel.endpoint(endpoint) != nil else {
                    reports.append(.status(path: path, StatusError(.unsupportedEndpoint))); continue
                }
                guard let cluster = await dataModel.cluster(clusterID, on: endpoint) else {
                    reports.append(.status(path: path, StatusError(.unsupportedCluster))); continue
                }
                let required = cluster.definition.attribute(attribute)?.read ?? .view
                guard await allowed(session, endpoint, clusterID, required) else {
                    reports.append(.status(path: path, StatusError(.unsupportedAccess))); continue
                }
                let version = await cluster.dataVersion
                if filters.contains(where: { $0.endpoint == endpoint && $0.cluster == clusterID && $0.version == version }) { continue }
                guard seen.insert(ConcreteAttribute(endpoint, clusterID, attribute)).inserted else { continue }
                do {
                    let value = try await cluster.read(attribute, context: context)
                    reports.append(.data(path: AttributePath(endpoint: endpoint, cluster: clusterID, attribute: attribute),
                                         dataVersion: version, value: value))
                } catch {
                    reports.append(.status(path: path, error as? StatusError ?? StatusError(.failure)))
                }
                continue
            }
            for (endpoint, cluster) in await dataModel.clusters(endpoint: path.endpoint, cluster: path.cluster) {
                let clusterID = cluster.id
                guard await allowed(session, endpoint, clusterID, .view) else { continue }
                let version = await cluster.dataVersion
                if filters.contains(where: { $0.endpoint == endpoint && $0.cluster == clusterID && $0.version == version }) { continue }
                let ids: [AttributeID]
                if let attribute = path.attribute { ids = [attribute] } else { ids = await cluster.attributeIDs + GlobalAttribute.all }
                for attribute in ids {
                    let concrete = ConcreteAttribute(endpoint, clusterID, attribute)
                    if let only, !only.contains(concrete) { continue }
                    let required = cluster.definition.attribute(attribute)?.read ?? .view
                    guard seen.insert(concrete).inserted, await allowed(session, endpoint, clusterID, required),
                          let value = try? await cluster.read(attribute, context: context)
                    else { continue }
                    reports.append(.data(path: AttributePath(endpoint: endpoint, cluster: clusterID, attribute: attribute),
                                         dataVersion: version, value: value))
                }
            }
        }
        return reports
    }

    func eventReports(_ paths: [EventPath], session: SessionInfo, minimum: UInt64, only: [EventRecord]? = nil) async -> [EventReport] {
        guard !paths.isEmpty else { return [] }
        var reports: [EventReport] = []
        let records: [EventRecord]
        if let only { records = only } else { records = await dataModel.events(endpoint: nil, cluster: nil, event: nil, minimumNumber: minimum) }
        for record in records where paths.contains(where: { $0.matches(record) }) {
            let required = await dataModel.cluster(record.cluster, on: record.endpoint)?.definition.event(record.event)?.read ?? .view
            guard await allowed(session, record.endpoint, record.cluster, required) else { continue }
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
        var pendingAttributes = attributes.flatMap { split($0) }.map { TLVElement($0.tlv) }
        var pendingEvents = events.map { TLVElement($0.tlv) }
        repeat {
            var chunkAttributes: [TLVElement] = []
            var chunkEvents: [TLVElement] = []
            func payload(more: Bool) -> [UInt8] {
                var fields: [TLVElement] = []
                if let subscriptionID { fields.append(.field(0, .unsigned(UInt64(subscriptionID)))) }
                if !chunkAttributes.isEmpty { fields.append(.field(1, .array(chunkAttributes))) }
                if !chunkEvents.isEmpty { fields.append(.field(2, .array(chunkEvents))) }
                if more { fields.append(.field(3, .bool(true))) }
                if !more && !finalNeedsResponse { fields.append(.field(4, .bool(true))) }
                fields.append(.field(interactionModelRevisionTag, imRevision))
                return TLVEncoder.encode(.structure(fields))
            }
            // Fill the chunk greedily; one oversized report still goes out alone.
            while let next = pendingAttributes.first {
                chunkAttributes.append(next)
                if payload(more: true).count > payloadLimit && chunkAttributes.count > 1 { chunkAttributes.removeLast(); break }
                pendingAttributes.removeFirst()
            }
            while pendingAttributes.isEmpty, let next = pendingEvents.first {
                chunkEvents.append(next)
                if payload(more: true).count > payloadLimit && (chunkEvents.count > 1 || !chunkAttributes.isEmpty) {
                    chunkEvents.removeLast(); break
                }
                pendingEvents.removeFirst()
            }
            let more = !pendingAttributes.isEmpty || !pendingEvents.isEmpty
            try await exchange.send(IMOpcode.reportData.rawValue, payload(more: more))
            if more || finalNeedsResponse { try await expectStatusResponse(on: exchange) }
        } while !pendingAttributes.isEmpty || !pendingEvents.isEmpty
    }

    /// A list too large for one message goes as an empty list and then one append per entry (Core §10.6.4.3.1).
    private func split(_ report: AttributeReport) -> [AttributeReport] {
        guard case .data(let path, let version, .array(let entries)) = report,
              TLVEncoder.encode(report.tlv).count > payloadLimit - 64
        else { return [report] }
        var appended = path
        appended.listIndex = .append
        return [.data(path: path, dataVersion: version, value: .array([]))]
            + entries.map { .data(path: appended, dataVersion: version, value: $0.value) }
    }

    func expectStatusResponse(on exchange: Exchange) async throws {
        let response = try await exchange.receive()
        guard response.payloadHeader.opcode == IMOpcode.statusResponse.rawValue,
              try TLVStruct(decoding: response.payload).uint(0) == UInt64(IMStatus.success.rawValue)
        else { throw StatusError(.invalidAction) }
    }

    // MARK: - Write

    private func write(_ message: Message, on exchange: Exchange, timedDeadline: ContinuousClock.Instant?) async throws {
        var message = message
        while true {
            let fields = try TLVStruct(decoding: message.payload)
            try checkTimed(fields.bool(1), deadline: timedDeadline)
            let session = await exchange.session
            let context = AccessContext(session: session, isTimed: timedDeadline != nil, exchange: exchange)
            var statuses: [TLVElement] = []
            for element in try fields.elements(2) {
                let data = try TLVStruct(element.value)
                guard let pathValue = data[1], let value = data[2] else { throw StatusError(.invalidAction) }
                let path = try AttributePath(tlv: pathValue)
                let status = await write(path, value: value, dataVersion: try? data.uint(0, as: UInt32.self), context: context)
                statuses.append(TLVElement(.structure([.field(0, path.tlv), .field(1, status.tlv)])))
            }
            let more = fields[3]?.bool ?? false
            if fields[0]?.bool != true || more {
                try await exchange.send(IMOpcode.writeResponse.rawValue, TLVEncoder.encode(.structure([
                    .field(0, .array(statuses)), .field(interactionModelRevisionTag, imRevision),
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
        guard await allowed(context.session, endpoint, clusterID, required) else { return StatusError(.unsupportedAccess) }
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

    private func checkTimed(_ flagged: Bool, deadline: ContinuousClock.Instant?) throws {
        // The timed flag and a preceding Timed Request go together (Core §8.7.2, §8.8.2).
        guard flagged == (deadline != nil) else { throw StatusError(.timedRequestMismatch) }
        if let deadline, ContinuousClock.now > deadline { throw StatusError(.timeout) }
    }

    // MARK: - Invoke

    private func invoke(_ message: Message, on exchange: Exchange, timedDeadline: ContinuousClock.Instant?) async throws {
        let fields = try TLVStruct(decoding: message.payload)
        try checkTimed(fields.bool(1), deadline: timedDeadline)
        let requests = try fields.elements(2)
        guard !requests.isEmpty else { throw StatusError(.invalidAction) }
        let session = await exchange.session
        let context = AccessContext(session: session, isTimed: timedDeadline != nil, exchange: exchange)
        var responses: [TLVElement] = []
        for request in requests {
            let data = try TLVStruct(request.value)
            guard let pathValue = data[0] else { throw StatusError(.invalidAction) }
            let path = try CommandPath(tlv: pathValue)
            // Several commands in one request need a ref each (Core §8.8.2.1).
            let ref = data[2]?.uint
            if requests.count > 1, ref == nil { throw StatusError(.invalidAction) }
            let result = await invoke(path, fields: data[1] ?? .structure([]), context: context)
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
            .field(0, .bool(false)), .field(1, .array(responses)), .field(interactionModelRevisionTag, imRevision),
        ])))
    }

    private func invoke(_ path: CommandPath, fields: TLVValue, context: AccessContext) async -> InvokeResult {
        guard let endpoint = path.endpoint else { return .status(StatusError(.unsupportedEndpoint)) }
        guard await dataModel.endpoint(endpoint) != nil else { return .status(StatusError(.unsupportedEndpoint)) }
        guard let cluster = await dataModel.cluster(path.cluster, on: endpoint) else { return .status(StatusError(.unsupportedCluster)) }
        guard await cluster.acceptedCommands.contains(path.command), let definition = cluster.definition.command(path.command) else {
            return .status(StatusError(.unsupportedCommand))
        }
        guard await allowed(context.session, endpoint, path.cluster, definition.invoke) else { return .status(StatusError(.unsupportedAccess)) }
        if definition.fabricScoped, context.fabricIndex == nil { return .status(StatusError(.unsupportedAccess)) }
        if definition.timed, !context.isTimed { return .status(StatusError(.needsTimedInteraction)) }
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
            .field(0, .unsigned(UInt64(id))), .field(2, .unsigned(UInt64(maxInterval))), .field(interactionModelRevisionTag, imRevision),
        ])))

        let subscription = Subscription(id: id, session: session, spec: spec, minInterval: .seconds(Int(floor)) * timeScale,
                                        maxInterval: .seconds(Int(maxInterval)) * timeScale, server: self,
                                        reportedClusters: Set(attributes.compactMap(\.cluster)),
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
