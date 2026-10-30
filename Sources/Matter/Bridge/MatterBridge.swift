import Foundation

/// A bridge (Core §9.12): an Aggregator endpoint whose parts are bridged devices, each a Bridged Node with its device
/// type's clusters and a Bridged Device Basic Information cluster.

/// The kinds of devices the bridge can expose, with the device types they map to (Device Library).
public enum BridgedDeviceKind: Hashable, Sendable {
    case onOffLight
    case dimmableLight
    case colorTemperatureLight(mireds: ClosedRange<UInt16>)
    case extendedColorLight(mireds: ClosedRange<UInt16>)
    case onOffPlug
    case dimmablePlug
    case contactSensor
    case occupancySensor
    case temperatureSensor
    case humiditySensor
    case lightSensor
    case windowCovering
    case fan

    public var deviceType: DeviceType {
        switch self {
        case .onOffLight: DeviceTypes.onOffLight
        case .dimmableLight: DeviceTypes.dimmableLight
        case .colorTemperatureLight: DeviceTypes.colorTemperatureLight
        case .extendedColorLight: DeviceTypes.extendedColorLight
        case .onOffPlug: DeviceTypes.onOffPlugInUnit
        case .dimmablePlug: DeviceTypes.dimmablePlugInUnit
        case .contactSensor: DeviceTypes.contactSensor
        case .occupancySensor: DeviceTypes.occupancySensor
        case .temperatureSensor: DeviceTypes.temperatureSensor
        case .humiditySensor: DeviceTypes.humiditySensor
        case .lightSensor: DeviceTypes.lightSensor
        case .windowCovering: DeviceTypes.windowCovering
        case .fan: DeviceTypes.fan
        }
    }
}

/// A bridged device's identity, shown in Bridged Device Basic Information (Core §9.13).
public struct BridgedDeviceInfo: Hashable, Sendable {
    /// Stable across restarts: it keeps the device's endpoint number, and is reported as UniqueID.
    public var id: String
    public var name: String
    public var vendorName: String?
    public var productName: String?
    public var serialNumber: String?

    public init(id: String, name: String, vendorName: String? = nil, productName: String? = nil, serialNumber: String? = nil) {
        self.id = id
        self.name = name
        self.vendorName = vendorName
        self.productName = productName
        self.serialNumber = serialNumber
    }
}

/// State a bridged device reports, as it changes on the device.
public enum DeviceState: Hashable, Sendable {
    case on(Bool)
    case level(UInt8)
    case colorTemperature(mireds: UInt16)
    case hueSaturation(hue: UInt8, saturation: UInt8)
    /// Contact sensors: true when the contact is closed.
    case contact(Bool)
    case occupied(Bool)
    /// Degrees Celsius.
    case temperature(Double?)
    /// Percent.
    case humidity(Double?)
    case illuminance(lux: Double?)
    /// Hundredths of a percent closed (0 open, 10000 closed).
    case coveringPosition(percent100ths: UInt16)
    case fanSpeed(percent: UInt8)
    case battery(percent: UInt8)
}

/// A device on the bridge.
public actor BridgedDevice {
    public nonisolated let info: BridgedDeviceInfo
    public nonisolated let kind: BridgedDeviceKind
    public nonisolated let endpoint: EndpointNumber
    let clusters: [ClusterID: AttributeCluster]
    let basicInformation: AttributeCluster
    weak var dataModel: DataModel?

    init(info: BridgedDeviceInfo, kind: BridgedDeviceKind, endpoint: EndpointNumber, clusters: [AttributeCluster],
         basicInformation: AttributeCluster, dataModel: DataModel) {
        self.info = info
        self.kind = kind
        self.endpoint = endpoint
        self.clusters = Dictionary(clusters.map { ($0.definition.id, $0) }) { first, _ in first }
        self.basicInformation = basicInformation
        self.dataModel = dataModel
    }

    /// Reports state the device changed on its own (or confirmed).
    public func update(_ state: DeviceState) async {
        switch state {
        case .on(let on): await clusters[OnOffCluster.id]?.set(OnOffCluster.Attribute.onOff, .bool(on))
        case .level(let level): await clusters[LevelControlCluster.id]?.set(LevelControlCluster.Attribute.currentLevel, .unsigned(UInt64(max(1, min(254, level)))))
        case .colorTemperature(let mireds):
            await clusters[ColorControlCluster.id]?.set([ColorControlCluster.Attribute.colorTemperatureMireds: .unsigned(UInt64(mireds)),
                                                          ColorControlCluster.Attribute.colorMode: .unsigned(2),
                                                          ColorControlCluster.Attribute.enhancedColorMode: .unsigned(2)])
        case .hueSaturation(let hue, let saturation):
            await clusters[ColorControlCluster.id]?.set([ColorControlCluster.Attribute.currentHue: .unsigned(UInt64(min(hue, 254))),
                                                          ColorControlCluster.Attribute.currentSaturation: .unsigned(UInt64(min(saturation, 254))),
                                                          ColorControlCluster.Attribute.colorMode: .unsigned(0),
                                                          ColorControlCluster.Attribute.enhancedColorMode: .unsigned(0)])
        case .contact(let closed):
            let cluster = clusters[BooleanStateCluster.id]
            if await cluster?.value(BooleanStateCluster.Attribute.stateValue) != .bool(closed) {
                await cluster?.set(BooleanStateCluster.Attribute.stateValue, .bool(closed))
                // StateChange (Application Clusters §1.7.5.1).
                await dataModel?.emit(endpoint: endpoint, cluster: BooleanStateCluster.id, event: 0, priority: .info,
                                      data: .structure([.field(0, .bool(closed))]))
            }
        case .occupied(let occupied):
            await clusters[OccupancySensingCluster.id]?.set(OccupancySensingCluster.Attribute.occupancy, .unsigned(occupied ? 1 : 0))
        case .temperature(let celsius):
            await clusters[TemperatureMeasurementCluster.id]?.set(0, celsius.map { .signed(Int64(($0 * 100).rounded())) } ?? .null)
        case .humidity(let percent):
            await clusters[RelativeHumidityMeasurementCluster.id]?.set(0, percent.map { .unsigned(UInt64(max(0, min(100, $0)) * 100)) } ?? .null)
        case .illuminance(let lux):
            // MeasuredValue = 10000 × log10(lux) + 1, 0 for darkness (Application Clusters §2.2.5.1).
            let value: TLVValue = lux.map { $0 < 1 ? .unsigned(0) : .unsigned(UInt64(min(0xFFFE, (10_000 * log10($0) + 1).rounded()))) } ?? .null
            await clusters[IlluminanceMeasurementCluster.id]?.set(0, value)
        case .coveringPosition(let position):
            let clamped = UInt64(min(position, 10_000))
            await clusters[WindowCoveringCluster.id]?.set([
                WindowCoveringCluster.Attribute.currentPositionLiftPercent100ths: .unsigned(clamped),
                WindowCoveringCluster.Attribute.currentPositionLiftPercentage: .unsigned(clamped / 100),
            ])
        case .fanSpeed(let percent):
            let clamped = UInt64(min(percent, 100))
            await clusters[FanControlCluster.id]?.set([
                FanControlCluster.Attribute.percentCurrent: .unsigned(clamped), FanControlCluster.Attribute.percentSetting: .unsigned(clamped),
                FanControlCluster.Attribute.fanMode: .unsigned(clamped == 0 ? 0 : clamped <= 33 ? 1 : clamped <= 66 ? 2 : 3),
            ])
        case .battery(let percent):
            // BatPercentRemaining is in half percents; the charge level warns below 20 % and is critical below 10 %.
            let clamped = UInt64(min(percent, 100))
            await clusters[PowerSourceCluster.id]?.set([
                PowerSourceCluster.Attribute.batPercentRemaining: .unsigned(clamped * 2),
                PowerSourceCluster.Attribute.batChargeLevel: .unsigned(clamped < 10 ? 2 : clamped < 20 ? 1 : 0),
            ])
        }
    }

    /// Whether the bridge can reach the device (Bridged Device Basic Information's Reachable, Core §9.13.5.1).
    public func setReachable(_ reachable: Bool) async {
        guard await basicInformation.value(BridgedDeviceBasicInformationCluster.Attribute.reachable) != .bool(reachable) else { return }
        await basicInformation.set(BridgedDeviceBasicInformationCluster.Attribute.reachable, .bool(reachable))
        // ReachableChanged event (Core §9.13.6.3).
        await dataModel?.emit(endpoint: endpoint, cluster: BridgedDeviceBasicInformationCluster.id, event: 3, priority: .info,
                              data: .structure([.field(0, .bool(reachable))]))
    }

    public func setName(_ name: String) async {
        await basicInformation.set(BridgedDeviceBasicInformationCluster.Attribute.nodeLabel, .utf8(String(name.prefix(32))))
    }
}

public enum BridgeError: Error, Equatable, Sendable {
    case deviceExists(String)
    case unknownDevice(String)
    case endpointsExhausted
}

/// A Matter bridge on a node: endpoint 1 is the Aggregator, bridged devices take endpoints from 2 up, persisted by
/// device id and never reused (Core §9.2.10).
public actor MatterBridge {
    public static let aggregatorEndpoint: EndpointNumber = 1
    public let node: MatterNode
    private var devices: [String: BridgedDevice] = [:]
    /// Every device id ever seen, with its endpoint.
    private var endpoints: [String: EndpointNumber] = [:]
    private var nextEndpoint: EndpointNumber = 2

    public init(node: MatterNode) async throws {
        self.node = node
        if let data = await node.storage.value(for: StorageKey.bridgeEndpoints), let fields = try? TLVStruct(decoding: data) {
            nextEndpoint = (try? fields.uint(1, as: UInt16.self)) ?? 2
            for entry in (try? fields.elements(2)) ?? [] {
                if let id = entry.value[0]?.string, let number = entry.value[1]?.uint.flatMap(UInt16.init(exactly:)) { endpoints[id] = number }
            }
        }
        try await node.add(Endpoint(number: Self.aggregatorEndpoint, deviceTypes: [DeviceTypes.aggregator], clusters: []))
    }

    public var allDevices: [BridgedDevice] { devices.values.sorted { $0.endpoint < $1.endpoint } }

    public func device(_ id: String) -> BridgedDevice? { devices[id] }

    /// Adds a device; its commands arrive at `handler`.
    @discardableResult
    public func add(_ info: BridgedDeviceInfo, kind: BridgedDeviceKind, battery: Bool = false,
                    handler: @escaping DeviceCommandHandler = { _ in }) async throws -> BridgedDevice {
        guard devices[info.id] == nil else { throw BridgeError.deviceExists(info.id) }
        let number = try await endpoint(for: info.id)
        var clusters = await Self.clusters(for: kind, handler: handler)
        let basicInformation = Self.basicInformation(info)
        var deviceTypes = [kind.deviceType, DeviceTypes.bridgedNode]
        if battery {
            let power = DeviceClusters.battery()
            await power.set(PowerSourceCluster.Attribute.endpointList, .array([TLVElement(.unsigned(UInt64(number)))]))
            clusters.append(power)
            deviceTypes.append(DeviceTypes.powerSource)
        }
        let device = BridgedDevice(info: info, kind: kind, endpoint: number, clusters: clusters, basicInformation: basicInformation,
                                   dataModel: node.dataModel)
        try await node.add(Endpoint(number: number, deviceTypes: deviceTypes, clusters: clusters + [basicInformation],
                                    parent: Self.aggregatorEndpoint))
        devices[info.id] = device
        return device
    }

    /// Removes a device; its endpoint number is not given to another device.
    public func remove(_ id: String) async throws {
        guard let device = devices.removeValue(forKey: id) else { throw BridgeError.unknownDevice(id) }
        try await node.remove(endpoint: device.endpoint)
    }

    private func endpoint(for id: String) async throws -> EndpointNumber {
        if let known = endpoints[id] { return known }
        guard nextEndpoint < EndpointNumber.max else { throw BridgeError.endpointsExhausted }
        let number = nextEndpoint
        nextEndpoint += 1
        endpoints[id] = number
        try await node.storage.setValue(TLVEncoder.encode(.structure([
            .field(1, .unsigned(UInt64(nextEndpoint))),
            .field(2, .array(endpoints.sorted { $0.value < $1.value }.map { id, number in
                TLVElement(.structure([.field(0, .utf8(id)), .field(1, .unsigned(UInt64(number)))]))
            })),
        ])), for: StorageKey.bridgeEndpoints)
        return number
    }

    static func basicInformation(_ info: BridgedDeviceInfo) -> AttributeCluster {
        typealias A = BridgedDeviceBasicInformationCluster.Attribute
        var attributes: [AttributeID: TLVValue] = [
            A.nodeLabel: .utf8(String(info.name.prefix(32))), A.reachable: .bool(true), A.uniqueId: .utf8(String(info.id.prefix(32))),
            A.configurationVersion: .unsigned(1),
        ]
        if let vendor = info.vendorName { attributes[A.vendorName] = .utf8(String(vendor.prefix(32))) }
        if let product = info.productName { attributes[A.productName] = .utf8(String(product.prefix(32))) }
        if let serial = info.serialNumber { attributes[A.serialNumber] = .utf8(String(serial.prefix(32))) }
        return AttributeCluster(BridgedDeviceBasicInformationCluster.definition, attributes: attributes)
    }

    /// The clusters a device type requires (Device Library), wired to the handler.
    static func clusters(for kind: BridgedDeviceKind, handler: @escaping DeviceCommandHandler) async -> [AttributeCluster] {
        switch kind {
        case .onOffLight:
            return [await DeviceClusters.identify(handler), await DeviceClusters.groups(), await DeviceClusters.scenes(),
                    await DeviceClusters.onOff(lighting: true, handler)]
        case .dimmableLight, .colorTemperatureLight, .extendedColorLight:
            let onOff = await DeviceClusters.onOff(lighting: true, handler)
            var clusters = [await DeviceClusters.identify(handler), await DeviceClusters.groups(), await DeviceClusters.scenes(), onOff,
                            await DeviceClusters.levelControl(onOff: onOff, handler)]
            if case .colorTemperatureLight(let range) = kind {
                clusters.append(await DeviceClusters.colorControl(hueSaturation: false, temperatureRange: range, handler))
            }
            if case .extendedColorLight(let range) = kind {
                clusters.append(await DeviceClusters.colorControl(hueSaturation: true, temperatureRange: range, handler))
            }
            return clusters
        case .onOffPlug:
            return [await DeviceClusters.identify(handler), await DeviceClusters.groups(), await DeviceClusters.scenes(),
                    await DeviceClusters.onOff(lighting: false, handler)]
        case .dimmablePlug:
            let onOff = await DeviceClusters.onOff(lighting: false, handler)
            return [await DeviceClusters.identify(handler), await DeviceClusters.groups(), await DeviceClusters.scenes(), onOff,
                    await DeviceClusters.levelControl(onOff: onOff, handler)]
        case .contactSensor:
            return [await DeviceClusters.identify(handler), DeviceClusters.booleanState()]
        case .occupancySensor:
            return [await DeviceClusters.identify(handler), DeviceClusters.occupancySensing()]
        case .temperatureSensor:
            return [await DeviceClusters.identify(handler),
                    DeviceClusters.measurement(TemperatureMeasurementCluster.definition, value: .null, minimum: .signed(-5000), maximum: .signed(10000))]
        case .humiditySensor:
            return [await DeviceClusters.identify(handler),
                    DeviceClusters.measurement(RelativeHumidityMeasurementCluster.definition, value: .null, minimum: .unsigned(0), maximum: .unsigned(10000))]
        case .lightSensor:
            return [await DeviceClusters.identify(handler),
                    DeviceClusters.measurement(IlluminanceMeasurementCluster.definition, value: .null, minimum: .unsigned(1), maximum: .unsigned(0xFFFE))]
        case .windowCovering:
            return [await DeviceClusters.identify(handler), await DeviceClusters.windowCovering(handler)]
        case .fan:
            return [await DeviceClusters.identify(handler), await DeviceClusters.groups(), await DeviceClusters.fanControl(handler)]
        }
    }
}
