import Foundation

/// A node's endpoints and clusters (Core §9.2), with the Descriptor clusters derived from them.

/// One endpoint: its device types, its clusters and its place in the composition tree.
public struct Endpoint: Sendable {
    public var number: EndpointNumber
    public var deviceTypes: [DeviceType]
    public var clusters: [any ClusterHandler]
    /// The endpoint whose PartsList includes this one (the Aggregator for bridged devices); nil for top-level ones.
    public var parent: EndpointNumber?
    /// Semantic tags (Descriptor's TagList).
    public var tags: [SemanticTag]

    public init(number: EndpointNumber, deviceTypes: [DeviceType], clusters: [any ClusterHandler], parent: EndpointNumber? = nil,
                tags: [SemanticTag] = []) {
        self.number = number
        self.deviceTypes = deviceTypes
        self.clusters = clusters
        self.parent = parent
        self.tags = tags
    }
}

/// A Descriptor TagList entry (Core §9.5.5.1, the Standard Namespaces).
public struct SemanticTag: Hashable, Sendable {
    public var namespace: UInt8
    public var tag: UInt8
    public var label: String?

    public init(namespace: UInt8, tag: UInt8, label: String? = nil) {
        self.namespace = namespace
        self.tag = tag
        self.label = label
    }
}

/// A recorded event (Core §7.14).
public struct EventRecord: Sendable {
    public var number: UInt64
    public var endpoint: EndpointNumber
    public var cluster: ClusterID
    public var event: EventID
    public var priority: EventDefinition.Priority
    /// Milliseconds since the Unix epoch.
    public var timestamp: UInt64
    public var data: TLVValue
    /// For fabric-sensitive events: the fabric that may see the data.
    public var fabricIndex: FabricIndex?
}

/// What changed, for subscriptions.
public enum DataModelChange: Sendable {
    case attributes(EndpointNumber, ClusterID, [AttributeID])
    case event(EventRecord)
    /// Endpoints were added or removed: PartsList and wildcard paths change.
    case structure
}

public enum DataModelError: Error, Equatable, Sendable {
    case endpointExists(EndpointNumber)
    case unknownEndpoint(EndpointNumber)
}

/// The node's endpoints, clusters and events.
public actor DataModel {
    private var endpoints: [EndpointNumber: Endpoint] = [:]
    private var descriptors: [EndpointNumber: AttributeCluster] = [:]
    private var events: [EventRecord] = []
    private var nextEventNumber: UInt64
    private let maxEvents: Int
    private var observers: [UInt64: AsyncStream<DataModelChange>.Continuation] = [:]
    private var nextObserver: UInt64 = 0

    public init(firstEventNumber: UInt64 = 0, maxEvents: Int = 256) {
        nextEventNumber = firstEventNumber
        self.maxEvents = maxEvents
    }

    // MARK: - Structure

    public var endpointNumbers: [EndpointNumber] { endpoints.keys.sorted() }

    public func endpoint(_ number: EndpointNumber) -> Endpoint? { endpoints[number] }

    /// Adds an endpoint; its Descriptor cluster is created here.
    public func add(_ endpoint: Endpoint) async throws {
        guard endpoints[endpoint.number] == nil else { throw DataModelError.endpointExists(endpoint.number) }
        let reporter = changeReporter
        for cluster in endpoint.clusters { await cluster.attach(endpoint: endpoint.number, reporter: reporter) }
        let descriptor = AttributeCluster(DescriptorCluster.definition)
        await descriptor.attach(endpoint: endpoint.number, reporter: reporter)
        endpoints[endpoint.number] = endpoint
        descriptors[endpoint.number] = descriptor
        await refreshDescriptors()
        publish(.structure)
    }

    public func remove(_ number: EndpointNumber) async throws {
        guard endpoints.removeValue(forKey: number) != nil else { throw DataModelError.unknownEndpoint(number) }
        descriptors[number] = nil
        // Children of a removed endpoint go with it.
        for child in endpoints.values.filter({ $0.parent == number }) { try await remove(child.number) }
        await refreshDescriptors()
        publish(.structure)
    }

    /// DeviceTypeList, ServerList, ClientList, PartsList and TagList (Core §9.5).
    private func refreshDescriptors() async {
        for (number, endpoint) in endpoints {
            guard let descriptor = descriptors[number] else { continue }
            let deviceTypes = endpoint.deviceTypes.map { type in
                TLVElement(.structure([.field(0, .unsigned(UInt64(type.id))), .field(1, .unsigned(UInt64(type.revision)))]))
            }
            let servers = ([DescriptorCluster.id] + endpoint.clusters.map(\.id)).sorted().map { TLVElement(.unsigned(UInt64($0))) }
            var values: [AttributeID: TLVValue] = [
                DescriptorCluster.Attribute.deviceTypeList: .array(deviceTypes),
                DescriptorCluster.Attribute.serverList: .array(servers),
                DescriptorCluster.Attribute.clientList: .array([]),
                DescriptorCluster.Attribute.partsList: .array(parts(of: number).map { TLVElement(.unsigned(UInt64($0))) }),
            ]
            if !endpoint.tags.isEmpty {
                values[DescriptorCluster.Attribute.tagList] = .array(endpoint.tags.map { tag in
                    var fields: [TLVElement] = [.field(0, .null), .field(1, .unsigned(UInt64(tag.namespace))),
                                                .field(2, .unsigned(UInt64(tag.tag)))]
                    if let label = tag.label { fields.append(.field(3, .utf8(label))) }
                    return TLVElement(.structure(fields))
                })
                await descriptor.setFeatureMap(DescriptorCluster.Feature.tagList.rawValue)
            }
            await descriptor.set(values)
        }
    }

    /// The root endpoint lists every other endpoint; others list their descendants (Core §9.2.2).
    private func parts(of number: EndpointNumber) -> [EndpointNumber] {
        if number == 0 { return endpoints.keys.filter { $0 != 0 }.sorted() }
        var result: [EndpointNumber] = []
        var pending = [number]
        while let parent = pending.popLast() {
            let children = endpoints.values.filter { $0.parent == parent }.map(\.number)
            result += children
            pending += children
        }
        return result.sorted()
    }

    // MARK: - Lookup

    /// The cluster on an endpoint, the Descriptor included.
    public func cluster(_ cluster: ClusterID, on endpoint: EndpointNumber) -> (any ClusterHandler)? {
        if cluster == DescriptorCluster.id { return descriptors[endpoint] }
        return endpoints[endpoint]?.clusters.first { $0.id == cluster }
    }

    /// All (endpoint, cluster) pairs matching optional endpoint and cluster filters, in order.
    public func clusters(endpoint: EndpointNumber?, cluster: ClusterID?) -> [(EndpointNumber, any ClusterHandler)] {
        var result: [(EndpointNumber, any ClusterHandler)] = []
        for number in endpoints.keys.sorted() where endpoint == nil || endpoint == number {
            let all: [any ClusterHandler] = (descriptors[number].map { [$0] } ?? []) + (endpoints[number]?.clusters ?? [])
            for handler in all.sorted(by: { $0.id < $1.id }) where cluster == nil || cluster == handler.id {
                result.append((number, handler))
            }
        }
        return result
    }

    // MARK: - Events

    /// Records an event and reports it to subscriptions.
    @discardableResult
    public func emit(endpoint: EndpointNumber, cluster: ClusterID, event: EventID, priority: EventDefinition.Priority,
                     data: TLVValue, fabricIndex: FabricIndex? = nil) -> EventRecord {
        let record = EventRecord(number: nextEventNumber, endpoint: endpoint, cluster: cluster, event: event, priority: priority,
                                 timestamp: UInt64(Date().timeIntervalSince1970 * 1000), data: data, fabricIndex: fabricIndex)
        nextEventNumber += 1
        events.append(record)
        if events.count > maxEvents { events.removeFirst(events.count - maxEvents) }
        publish(.event(record))
        return record
    }

    public func events(endpoint: EndpointNumber?, cluster: ClusterID?, event: EventID?, minimumNumber: UInt64) -> [EventRecord] {
        events.filter {
            (endpoint == nil || $0.endpoint == endpoint) && (cluster == nil || $0.cluster == cluster)
                && (event == nil || $0.event == event) && $0.number >= minimumNumber
        }
    }

    public var eventNumber: UInt64 { nextEventNumber }

    // MARK: - Changes

    /// Changes as they happen; the stream ends when the observer is removed.
    public func changes() -> (UInt64, AsyncStream<DataModelChange>) {
        let (stream, continuation) = AsyncStream.makeStream(of: DataModelChange.self, bufferingPolicy: .bufferingNewest(1024))
        nextObserver += 1
        observers[nextObserver] = continuation
        return (nextObserver, stream)
    }

    public func stopObserving(_ id: UInt64) { observers.removeValue(forKey: id)?.finish() }

    private func publish(_ change: DataModelChange) {
        for continuation in observers.values { continuation.yield(change) }
    }

    private nonisolated var changeReporter: ChangeReporter {
        ChangeReporter { [weak self] endpoint, cluster, attributes in
            guard let self else { return }
            Task { await self.publish(.attributes(endpoint, cluster, attributes)) }
        }
    }
}
