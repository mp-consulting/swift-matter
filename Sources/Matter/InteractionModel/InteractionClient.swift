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

    /// Runs one interaction on a new exchange, closing it afterwards.
    private func interact<T: Sendable>(session: UInt16, timed: Duration? = nil, _ body: (Exchange) async throws -> T) async throws -> T {
        let exchange = try await layer.newExchange(session: session, protocolID: .interactionModel)
        do {
            if let timed { try await timedRequest(timed, on: exchange) }
            let result = try await body(exchange)
            await exchange.close()
            return result
        } catch {
            await exchange.close()
            throw error
        }
    }

    // MARK: - Read

    public func read(_ attributes: [AttributePath], events: [EventPath] = [], fabricFiltered: Bool = true,
                     session: UInt16) async throws -> (attributes: [AttributeReport], events: [EventReport]) {
        var fields: [TLVElement] = []
        if !attributes.isEmpty { fields.append(.field(0, .array(attributes.map { TLVElement($0.tlv) }))) }
        if !events.isEmpty { fields.append(.field(1, .array(events.map { TLVElement($0.tlv) }))) }
        fields += [.field(3, .bool(fabricFiltered)), interactionModelRevisionField]
        let report = try await interact(session: session) { exchange in
            try await exchange.send(IMOpcode.readRequest.rawValue, TLVEncoder.encode(.structure(fields)))
            return try await receiveReports(on: exchange)
        }
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
    private func receiveReports(on exchange: Exchange, first: ReportDataContents? = nil) async throws -> SubscriptionReport {
        var report = SubscriptionReport(attributes: [], events: [])
        var next = first
        while true {
            let contents: ReportDataContents
            if let pending = next {
                contents = pending
                next = nil
            } else {
                let message = try await exchange.receive()
                if let status = try StatusError(statusResponse: message) { throw status }
                guard message.payloadHeader.opcode == IMOpcode.reportData.rawValue else { throw StatusError(.invalidAction) }
                contents = try ReportDataContents(message.payload)
            }
            report.attributes += contents.attributes
            report.events += contents.events
            if contents.moreChunks || !contents.suppressResponse { try await exchange.sendIMStatus(.success) }
            if !contents.moreChunks { return report }
        }
    }

    // MARK: - Write

    /// Writes attributes, returning each path's status.
    public func write(_ values: [(AttributePath, TLVValue)], timed: Duration? = nil, session: UInt16) async throws -> [(AttributePath, StatusError)] {
        let requests = values.map { path, value in TLVElement(.structure([.field(1, path.tlv), TLVElement(.context(2), value)])) }
        return try await interact(session: session, timed: timed) { exchange in
            try await exchange.send(IMOpcode.writeRequest.rawValue, TLVEncoder.encode(.structure([
                .field(0, .bool(false)), .field(1, .bool(timed != nil)), .field(2, .array(requests)), interactionModelRevisionField,
            ])))
            let response = try await exchange.receive()
            if let status = try StatusError(statusResponse: response) { throw status }
            return try TLVStruct(decoding: response.payload).elements(0).map { element in
                let fields = try TLVStruct(element.value)
                guard let path = fields[0], let status = fields[1] else { throw StatusError(.invalidAction) }
                return (try AttributePath(tlv: path), try StatusError(tlv: status))
            }
        }
    }

    private func timedRequest(_ timeout: Duration, on exchange: Exchange) async throws {
        try await exchange.send(IMOpcode.timedRequest.rawValue, TLVEncoder.encode(.structure([
            .field(0, .unsigned(UInt64(max(1, min(timeout.milliseconds, 65_535))))), interactionModelRevisionField,
        ])))
        guard try StatusError(statusResponse: try await exchange.receive())?.status == .success else {
            throw StatusError(.timedRequestMismatch)
        }
    }

    // MARK: - Invoke

    public func invoke(_ path: CommandPath, fields: TLVValue = .structure([]), timed: Duration? = nil, session: UInt16) async throws -> InvokeResult {
        try await interact(session: session, timed: timed) { exchange in
            try await exchange.send(IMOpcode.invokeRequest.rawValue, TLVEncoder.encode(.structure([
                .field(0, .bool(false)), .field(1, .bool(timed != nil)),
                .field(2, .array([TLVElement(.structure([.field(0, path.tlv), TLVElement(.context(1), fields)]))])),
                interactionModelRevisionField,
            ])))
            let response = try await exchange.receive()
            if let status = try StatusError(statusResponse: response) { return .status(status) }
            guard response.payloadHeader.opcode == IMOpcode.invokeResponse.rawValue,
                  let first = try TLVStruct(decoding: response.payload).elements(1).first
            else { throw StatusError(.invalidAction) }
            let item = try TLVStruct(first.value)
            if let command = item[0] {
                let data = try TLVStruct(command)
                guard let pathValue = data[0] else { throw StatusError(.invalidAction) }
                return .response(try CommandPath(tlv: pathValue).command, data[1] ?? .structure([]))
            }
            guard let status = try item.structure(1)[1] else { throw StatusError(.invalidAction) }
            return .status(try StatusError(tlv: status))
        }
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
        fields += [.field(7, .bool(true)), interactionModelRevisionField]

        let (priming, id, negotiated) = try await interact(session: session) { exchange in
            try await exchange.send(IMOpcode.subscribeRequest.rawValue, TLVEncoder.encode(.structure(fields)))
            let priming = try await receiveReports(on: exchange)
            let response = try await exchange.receive()
            guard response.payloadHeader.opcode == IMOpcode.subscribeResponse.rawValue else { throw StatusError(.invalidAction) }
            let responseFields = try TLVStruct(decoding: response.payload)
            return (priming, try responseFields.uint(0, as: UInt32.self), try responseFields.uint(2, as: UInt16.self))
        }
        let (stream, continuation) = AsyncStream.makeStream(of: SubscriptionReport.self)
        continuation.yield(priming)
        subscriptions[id] = continuation
        return (id, negotiated, stream)
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
              let contents = try? ReportDataContents(message.payload), let id = contents.subscriptionID,
              let continuation = subscriptions[id]
        else {
            try? await exchange.sendIMStatus(.invalidSubscription)
            return
        }
        guard let report = try? await receiveReports(on: exchange, first: contents) else { return }
        continuation.yield(report)
    }
}
