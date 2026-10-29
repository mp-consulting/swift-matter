/// The Interaction Model client (Core §8): reads, writes, invokes and subscriptions toward a peer over a secure session.
/// Register it on the message layer for `.interactionModel` to receive subscription reports.
public actor InteractionClient: ProtocolHandler {
    public let layer: MessageLayer
    private var subscriptions: [UInt32: AsyncStream<SubscriptionReport>.Continuation] = [:]

    public init(layer: MessageLayer) { self.layer = layer }

    public struct SubscriptionReport: Sendable {
        public var attributes: [AttributeReport]
        public var events: [EventReport]
    }

    // MARK: - Read

    public func read(_ attributes: [AttributePath], events: [EventPath] = [], fabricFiltered: Bool = true,
                     session: UInt16) async throws -> (attributes: [AttributeReport], events: [EventReport]) {
        var fields: [TLVElement] = []
        if !attributes.isEmpty { fields.append(.field(0, .array(attributes.map { TLVElement($0.tlv) }))) }
        if !events.isEmpty { fields.append(.field(1, .array(events.map { TLVElement($0.tlv) }))) }
        fields.append(.field(3, .bool(fabricFiltered)))
        fields.append(.field(interactionModelRevisionTag, .unsigned(UInt64(SpecificationVersion.interactionModelRevision))))
        let exchange = try await layer.newExchange(session: session, protocolID: .interactionModel)
        defer { Task { await exchange.close() } }
        try await exchange.send(IMOpcode.readRequest.rawValue, TLVEncoder.encode(.structure(fields)))
        let report = try await receiveReports(on: exchange, subscription: false)
        return (report.attributes, report.events)
    }

    /// The value of one attribute, or its status as an error.
    public func read(endpoint: EndpointNumber, cluster: ClusterID, attribute: AttributeID, session: UInt16) async throws -> TLVValue {
        let (reports, _) = try await read([AttributePath(endpoint: endpoint, cluster: cluster, attribute: attribute)], session: session)
        // A list split into appends arrives as several reports.
        var value: TLVValue?
        for report in reports {
            switch report {
            case .data(let path, _, let data):
                if path.listIndex == .append, case .array(let entries) = value ?? .array([]) {
                    value = .array(entries + [TLVElement(data)])
                } else {
                    value = data
                }
            case .status(_, let status): throw status
            }
        }
        guard let value else { throw StatusError(.failure) }
        return value
    }

    /// Collects ReportData chunks, acknowledging each but a final one that suppresses its response.
    private func receiveReports(on exchange: Exchange, subscription: Bool) async throws -> SubscriptionReport {
        var attributes: [AttributeReport] = []
        var events: [EventReport] = []
        while true {
            let message = try await exchange.receive()
            if message.payloadHeader.opcode == IMOpcode.statusResponse.rawValue {
                let status = try TLVStruct(decoding: message.payload).uint(0, as: UInt8.self)
                throw StatusError(IMStatus(rawValue: status) ?? .failure)
            }
            guard message.payloadHeader.opcode == IMOpcode.reportData.rawValue else { throw StatusError(.invalidAction) }
            let fields = try TLVStruct(decoding: message.payload)
            attributes += try (fields[1]?.elements ?? []).map { try AttributeReport(tlv: $0.value) }
            events += try (fields[2]?.elements ?? []).map { try EventReport(tlv: $0.value) }
            let more = fields[3]?.bool ?? false
            if more || fields[4]?.bool != true { try await Self.sendStatus(.success, on: exchange) }
            if !more { return SubscriptionReport(attributes: attributes, events: events) }
        }
    }

    static func sendStatus(_ status: IMStatus, on exchange: Exchange) async throws {
        try await exchange.send(IMOpcode.statusResponse.rawValue, TLVEncoder.encode(.structure([
            .field(0, .unsigned(UInt64(status.rawValue))),
            .field(interactionModelRevisionTag, .unsigned(UInt64(SpecificationVersion.interactionModelRevision))),
        ])))
    }

    // MARK: - Write

    /// Writes attributes, returning each path's status.
    public func write(_ values: [(AttributePath, TLVValue)], timed: Duration? = nil, session: UInt16) async throws -> [(AttributePath, StatusError)] {
        let exchange = try await layer.newExchange(session: session, protocolID: .interactionModel)
        defer { Task { await exchange.close() } }
        if let timed { try await timedRequest(timed, on: exchange) }
        let requests = values.map { path, value in TLVElement(.structure([.field(1, path.tlv), TLVElement(.context(2), value)])) }
        try await exchange.send(IMOpcode.writeRequest.rawValue, TLVEncoder.encode(.structure([
            .field(0, .bool(false)), .field(1, .bool(timed != nil)), .field(2, .array(requests)),
            .field(interactionModelRevisionTag, .unsigned(UInt64(SpecificationVersion.interactionModelRevision))),
        ])))
        let response = try await exchange.receive()
        if response.payloadHeader.opcode == IMOpcode.statusResponse.rawValue {
            throw StatusError(IMStatus(rawValue: try TLVStruct(decoding: response.payload).uint(0, as: UInt8.self)) ?? .failure)
        }
        return try TLVStruct(decoding: response.payload).elements(0).map { element in
            let fields = try TLVStruct(element.value)
            guard let path = fields[0], let status = fields[1] else { throw StatusError(.invalidAction) }
            return (try AttributePath(tlv: path), try StatusError(tlv: status))
        }
    }

    private func timedRequest(_ timeout: Duration, on exchange: Exchange) async throws {
        try await exchange.send(IMOpcode.timedRequest.rawValue, TLVEncoder.encode(.structure([
            .field(0, .unsigned(UInt64(max(1, min(timeout.milliseconds, 65_535))))),
            .field(interactionModelRevisionTag, .unsigned(UInt64(SpecificationVersion.interactionModelRevision))),
        ])))
        let status = try await exchange.receive()
        guard status.payloadHeader.opcode == IMOpcode.statusResponse.rawValue,
              try TLVStruct(decoding: status.payload).uint(0) == 0
        else { throw StatusError(.timedRequestMismatch) }
    }

    // MARK: - Invoke

    public func invoke(_ path: CommandPath, fields: TLVValue = .structure([]), timed: Duration? = nil, session: UInt16) async throws -> InvokeResult {
        let exchange = try await layer.newExchange(session: session, protocolID: .interactionModel)
        defer { Task { await exchange.close() } }
        if let timed { try await timedRequest(timed, on: exchange) }
        try await exchange.send(IMOpcode.invokeRequest.rawValue, TLVEncoder.encode(.structure([
            .field(0, .bool(false)), .field(1, .bool(timed != nil)),
            .field(2, .array([TLVElement(.structure([.field(0, path.tlv), TLVElement(.context(1), fields)]))])),
            .field(interactionModelRevisionTag, .unsigned(UInt64(SpecificationVersion.interactionModelRevision))),
        ])))
        let response = try await exchange.receive()
        let payload = try TLVStruct(decoding: response.payload)
        if response.payloadHeader.opcode == IMOpcode.statusResponse.rawValue {
            return .status(StatusError(IMStatus(rawValue: try payload.uint(0, as: UInt8.self)) ?? .failure))
        }
        guard response.payloadHeader.opcode == IMOpcode.invokeResponse.rawValue, let first = try payload.elements(1).first else {
            throw StatusError(.invalidAction)
        }
        let item = try TLVStruct(first.value)
        if let command = item[0] {
            let data = try TLVStruct(command)
            guard let pathValue = data[0] else { throw StatusError(.invalidAction) }
            return .response(try CommandPath(tlv: pathValue).command, data[1] ?? .structure([]))
        }
        let status = try item.structure(1)
        guard let statusValue = status[1] else { throw StatusError(.invalidAction) }
        return .status(try StatusError(tlv: statusValue))
    }

    // MARK: - Subscribe

    /// Subscribes; the stream yields the priming report and then each change report.
    public func subscribe(_ attributes: [AttributePath], events: [EventPath] = [], minInterval: UInt16, maxInterval: UInt16,
                          keepSubscriptions: Bool = true, session: UInt16) async throws -> (id: UInt32, maxInterval: UInt16, reports: AsyncStream<SubscriptionReport>) {
        var fields: [TLVElement] = [
            .field(0, .bool(keepSubscriptions)), .field(1, .unsigned(UInt64(minInterval))), .field(2, .unsigned(UInt64(maxInterval))),
        ]
        if !attributes.isEmpty { fields.append(.field(3, .array(attributes.map { TLVElement($0.tlv) }))) }
        if !events.isEmpty { fields.append(.field(4, .array(events.map { TLVElement($0.tlv) }))) }
        fields.append(.field(7, .bool(true)))
        fields.append(.field(interactionModelRevisionTag, .unsigned(UInt64(SpecificationVersion.interactionModelRevision))))

        let exchange = try await layer.newExchange(session: session, protocolID: .interactionModel)
        defer { Task { await exchange.close() } }
        try await exchange.send(IMOpcode.subscribeRequest.rawValue, TLVEncoder.encode(.structure(fields)))
        let priming = try await receiveReports(on: exchange, subscription: true)
        let response = try await exchange.receive()
        guard response.payloadHeader.opcode == IMOpcode.subscribeResponse.rawValue else { throw StatusError(.invalidAction) }
        let responseFields = try TLVStruct(decoding: response.payload)
        let id = try responseFields.uint(0, as: UInt32.self)
        let (stream, continuation) = AsyncStream.makeStream(of: SubscriptionReport.self)
        continuation.yield(priming)
        subscriptions[id] = continuation
        return (id, try responseFields.uint(2, as: UInt16.self), stream)
    }

    public func cancelSubscription(_ id: UInt32) {
        subscriptions.removeValue(forKey: id)?.finish()
    }

    /// Reports of established subscriptions arrive as exchanges the publisher starts.
    public nonisolated func handle(_ exchange: Exchange, first message: Message) async {
        await receiveSubscriptionReport(exchange, first: message)
    }

    private func receiveSubscriptionReport(_ exchange: Exchange, first message: Message) async {
        guard message.payloadHeader.opcode == IMOpcode.reportData.rawValue,
              let fields = try? TLVStruct(decoding: message.payload), let id = fields[0]?.uint.flatMap(UInt32.init(exactly:)),
              let continuation = subscriptions[id]
        else {
            try? await Self.sendStatus(.invalidSubscription, on: exchange)
            return
        }
        var report = SubscriptionReport(
            attributes: (try? (fields[1]?.elements ?? []).map { try AttributeReport(tlv: $0.value) }) ?? [],
            events: (try? (fields[2]?.elements ?? []).map { try EventReport(tlv: $0.value) }) ?? [])
        if fields[3]?.bool == true {
            // A chunked report: acknowledge and collect the rest on the same exchange.
            try? await Self.sendStatus(.success, on: exchange)
            guard let rest = try? await receiveReports(on: exchange, subscription: true) else { return }
            report.attributes += rest.attributes
            report.events += rest.events
        } else {
            try? await Self.sendStatus(.success, on: exchange)
        }
        continuation.yield(report)
    }
}
