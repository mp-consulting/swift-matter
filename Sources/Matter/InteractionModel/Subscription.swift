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
    private var structureChanged = false
    private var reportedClusters: Set<ConcreteCluster>
    private var eventMinimum: UInt64
    private var wake: AsyncStream<Void>.Continuation?
    private var task: Task<Void, Never>?
    private var observerID: UInt64?

    init(id: UInt32, session: SessionInfo, spec: InteractionServer.ReadSpec, minInterval: Duration, maxInterval: Duration,
         server: InteractionServer, reportedClusters: Set<ConcreteCluster>, eventMinimum: UInt64) {
        self.id = id
        self.session = session
        self.spec = spec
        self.minInterval = minInterval
        self.maxInterval = maxInterval
        self.server = server
        self.reportedClusters = reportedClusters
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
            if record.number >= eventMinimum, spec.events.contains(where: { $0.matches(record) }) { pendingEvents.append(record) }
        case .structure:
            structureChanged = true
        }
        if !dirty.isEmpty || !pendingEvents.isEmpty || structureChanged { wake?.yield() }
    }

    private func wakeUp() { wake?.yield() }

    private var hasChanges: Bool { !dirty.isEmpty || !pendingEvents.isEmpty || structureChanged }

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
        let structure = structureChanged
        dirty = []
        pendingEvents = []
        structureChanged = false

        var attributes = changed.isEmpty ? [] : await server.attributeReports(spec.attributes, session: session,
                                                                              fabricFiltered: spec.fabricFiltered, only: changed)
        if structure {
            // New endpoints or clusters under wildcard paths are reported in full.
            let all = await server.attributeReports(spec.attributes, session: session, fabricFiltered: spec.fabricFiltered)
            let added = all.filter { report in report.cluster.map { !reportedClusters.contains($0) } ?? false }
            attributes += added
            reportedClusters = Set(all.compactMap(\.cluster))
        }
        let eventReports = await server.eventReports(spec.events, session: session, minimum: eventMinimum, only: events)
        if let last = events.last { eventMinimum = last.number + 1 }

        let exchange = try await layer.newExchange(session: session.localSessionID, protocolID: .interactionModel)
        do {
            try await server.sendReports(attributes, eventReports, subscriptionID: id, on: exchange, finalNeedsResponse: true)
            await exchange.close()
        } catch {
            await exchange.close()
            throw error
        }
    }
}
