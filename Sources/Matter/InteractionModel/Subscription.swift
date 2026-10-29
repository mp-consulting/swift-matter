/// A subscription a peer holds (Core §8.5): changes are reported no sooner than the minimum interval after the last
/// report, and an empty report keeps it alive at the maximum interval. A report the subscriber does not acknowledge
/// ends it.
actor Subscription {
    let id: UInt32
    let session: SessionInfo
    let spec: InteractionServer.ReadSpec
    let minInterval: Duration
    let maxInterval: Duration
    private unowned let server: InteractionServer
    private var dirty = Set<ConcreteAttribute>()
    private var pendingEvents: [EventRecord] = []
    /// Endpoints added since the last report: reported in full when the paths cover them.
    private var addedEndpoints = Set<EndpointNumber>()
    private var eventMinimum: UInt64
    private var wake: AsyncStream<Void>.Continuation?
    private var task: Task<Void, Never>?
    private var observerID: UInt64?

    init(id: UInt32, session: SessionInfo, spec: InteractionServer.ReadSpec, minInterval: Duration, maxInterval: Duration,
         server: InteractionServer, eventMinimum: UInt64) {
        self.id = id
        self.session = session
        self.spec = spec
        self.minInterval = minInterval
        self.maxInterval = maxInterval
        self.server = server
        self.eventMinimum = eventMinimum
    }

    nonisolated func isFrom(_ other: SessionInfo) -> Bool {
        session.fabricIndex == other.fabricIndex && session.peerNodeID == other.peerNodeID && session.kind == other.kind
            && (session.kind == .case || session.localSessionID == other.localSessionID)
    }

    func start(layer: MessageLayer) async {
        let (observer, changes) = await server.dataModel.changes()
        observerID = observer
        let (wakes, wake) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
        self.wake = wake
        let watcher = Task { [weak self] in
            for await change in changes { await self?.note(change) }
        }
        task = Task { [weak self] in
            await self?.run(layer: layer, wakes: wakes)
            watcher.cancel()
        }
    }

    func cancel() async {
        task?.cancel()
        wake?.finish()
        if let observerID { await server.dataModel.stopObserving(observerID) }
    }

    private func note(_ change: DataModelChange) {
        switch change {
        case .attributes(let endpoint, let cluster, let attributes):
            for attribute in attributes where spec.attributes.contains(where: { $0.matches(endpoint: endpoint, cluster: cluster, attribute: attribute) }) {
                dirty.insert(ConcreteAttribute(endpoint, cluster, attribute))
            }
        case .event(let record):
            if record.number >= eventMinimum, spec.events.contains(where: { $0.matches(record) }) {
                pendingEvents.append(record)
                // Events beyond the node's own log would be lost anyway.
                if pendingEvents.count > 256 { pendingEvents.removeFirst(pendingEvents.count - 256) }
            }
        case .structure(let added, let removed):
            addedEndpoints.formUnion(added)
            addedEndpoints.subtract(removed)
            dirty = dirty.filter { !removed.contains($0.endpoint) }
        }
        if hasChanges { wakeUp() }
    }

    private func wakeUp() { wake?.yield() }

    private var hasChanges: Bool { !dirty.isEmpty || !pendingEvents.isEmpty || !addedEndpoints.isEmpty }

    private func run(layer: MessageLayer, wakes: AsyncStream<Void>) async {
        var lastReport = ContinuousClock.now
        var iterator = wakes.makeAsyncIterator()
        while !Task.isCancelled {
            // Wait for a change or the keep-alive deadline, then for the minimum interval.
            let deadline = lastReport + maxInterval
            if !hasChanges {
                let timer = Task { [weak self] in
                    try? await Task.sleep(until: deadline, clock: .continuous)
                    await self?.wakeUp()
                }
                _ = await iterator.next()
                timer.cancel()
            }
            guard !Task.isCancelled else { return }
            let earliest = lastReport + minInterval
            if ContinuousClock.now < earliest { try? await Task.sleep(until: earliest, clock: .continuous) }
            guard !Task.isCancelled else { return }
            if !hasChanges && ContinuousClock.now < deadline { continue }

            do {
                try await report(layer: layer)
                lastReport = .now
            } catch {
                // The subscriber is gone or refused the report: the subscription ends (Core §8.5.4).
                await server.cancelSubscription(id)
                return
            }
        }
    }

    private func report(layer: MessageLayer) async throws {
        let changed = dirty
        let events = pendingEvents
        let added = addedEndpoints
        dirty = []
        pendingEvents = []
        addedEndpoints = []

        var attributes = changed.isEmpty ? [] : await server.attributeReports(spec.attributes, session: session,
                                                                              fabricFiltered: spec.fabricFiltered, only: changed)
        // New endpoints are reported in full under the paths that cover them, wildcard or naming them.
        for endpoint in added.sorted() {
            let paths = spec.attributes.filter { $0.endpoint == nil || $0.endpoint == endpoint }.map { path -> AttributePath in
                var concrete = path
                concrete.endpoint = endpoint
                return concrete
            }
            attributes += await server.attributeReports(paths, session: session, fabricFiltered: spec.fabricFiltered)
                .filter { if case .data = $0 { true } else { false } }
        }
        let eventReports = await server.eventReports(spec.events, session: session, minimum: eventMinimum, only: events)
        if let last = events.last { eventMinimum = last.number + 1 }

        // The session must still be the subscriber's: a reused session id belongs to someone else.
        guard let current = await layer.session(session.localSessionID), current.peerNodeID == session.peerNodeID,
              current.fabricIndex == session.fabricIndex, current.peerSessionID == session.peerSessionID
        else { throw ExchangeError.sessionGone }
        let exchange = try await layer.newExchange(session: session.localSessionID, protocolID: .interactionModel)
        do {
            try await server.sendReports(attributes, eventReports, subscriptionID: id, on: exchange, finalNeedsResponse: true)
        } catch {
            await exchange.close()
            throw error
        }
        await exchange.close()
    }
}
