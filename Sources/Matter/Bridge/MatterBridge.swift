import Crypto
import Foundation

/// A bridge (Core §9.12): an Aggregator endpoint whose parts are bridged devices. A device is a Bridged Node endpoint
/// with Bridged Device Basic Information; its functions are on that endpoint, or on child endpoints when it has several
/// (a fan with a light, a power strip), as compound devices are (Core §9.12.2.1).

/// A function a bridged device offers: its device types and the clusters that serve them. The presets cover common
/// devices; anything else (a thermostat, a lock, a vendor cluster) is a kind with its own clusters.
public struct DeviceKind: Sendable {
    public var deviceTypes: [DeviceType]
    /// Builds the clusters; their commands go to the handler.
    public var makeClusters: @Sendable (_ handler: @escaping DeviceCommandHandler) async -> [any ClusterHandler]

    public init(deviceTypes: [DeviceType], makeClusters: @escaping @Sendable (_ handler: @escaping DeviceCommandHandler) async -> [any ClusterHandler]) {
        self.deviceTypes = deviceTypes
        self.makeClusters = makeClusters
    }

    /// Identify, and Groups and Scenes Management for devices that act (Device Library §4-5); `groups` alone for a
    /// device that takes group commands without scenes (a fan).
    static func base(_ handler: @escaping DeviceCommandHandler, actuator: Bool, groups: Bool? = nil) async -> [any ClusterHandler] {
        let identify = await DeviceClusters.identify(handler)
        var clusters: [any ClusterHandler] = [identify]
        if groups ?? actuator {
            clusters.append(await DeviceClusters.groups { await identify.value(IdentifyCluster.Attribute.identifyTime)?.uint ?? 0 > 0 })
        }
        if actuator { clusters.append(await DeviceClusters.scenes()) }
        return clusters
    }

    /// Lights and plugs: On/Off, and Level Control and Color Control as the type needs.
    static func switched(_ type: DeviceType, lighting: Bool, dimmable: Bool, color: (range: ClosedRange<UInt16>, hueSaturation: Bool)? = nil) -> DeviceKind {
        DeviceKind(deviceTypes: [type]) { handler in
            let onOff = await DeviceClusters.onOff(lighting: lighting, handler)
            var clusters = await base(handler, actuator: true) + [onOff]
            if dimmable { clusters.append(await DeviceClusters.levelControl(onOff: onOff, handler)) }
            if let color {
                clusters.append(await DeviceClusters.colorControl(hueSaturation: color.hueSaturation, temperatureRange: color.range, handler))
            }
            return clusters
        }
    }

    static func sensor(_ type: DeviceType, _ make: @escaping @Sendable () -> any ClusterHandler) -> DeviceKind {
        DeviceKind(deviceTypes: [type]) { handler in await base(handler, actuator: false) + [make()] }
    }

    public static let onOffLight = switched(DeviceTypes.onOffLight, lighting: true, dimmable: false)
    public static let dimmableLight = switched(DeviceTypes.dimmableLight, lighting: true, dimmable: true)
    public static func colorTemperatureLight(mireds: ClosedRange<UInt16>) -> DeviceKind {
        switched(DeviceTypes.colorTemperatureLight, lighting: true, dimmable: true, color: (mireds, false))
    }
    public static func extendedColorLight(mireds: ClosedRange<UInt16>) -> DeviceKind {
        switched(DeviceTypes.extendedColorLight, lighting: true, dimmable: true, color: (mireds, true))
    }
    public static let onOffPlug = switched(DeviceTypes.onOffPlugInUnit, lighting: false, dimmable: false)
    public static let dimmablePlug = switched(DeviceTypes.dimmablePlugInUnit, lighting: false, dimmable: true)
    public static let contactSensor = sensor(DeviceTypes.contactSensor) { DeviceClusters.booleanState() }
    public static let waterLeakDetector = sensor(DeviceTypes.waterLeakDetector) { DeviceClusters.booleanState() }
    public static let occupancySensor = sensor(DeviceTypes.occupancySensor) { DeviceClusters.occupancySensing() }
    public static let temperatureSensor = sensor(DeviceTypes.temperatureSensor) {
        DeviceClusters.measurement(TemperatureMeasurementCluster.definition, value: .null, minimum: .signed(-5000), maximum: .signed(10000))
    }
    public static let humiditySensor = sensor(DeviceTypes.humiditySensor) {
        DeviceClusters.measurement(RelativeHumidityMeasurementCluster.definition, value: .null, minimum: .unsigned(0), maximum: .unsigned(10000))
    }
    public static let lightSensor = sensor(DeviceTypes.lightSensor) {
        DeviceClusters.measurement(IlluminanceMeasurementCluster.definition, value: .null, minimum: .unsigned(1), maximum: .unsigned(0xFFFE))
    }
    public static let windowCovering = DeviceKind(deviceTypes: [DeviceTypes.windowCovering]) { handler in
        await base(handler, actuator: false) + [await DeviceClusters.windowCovering(handler)]
    }
    public static let fan = DeviceKind(deviceTypes: [DeviceTypes.fan]) { handler in
        await base(handler, actuator: false, groups: true) + [await DeviceClusters.fanControl(handler)]
    }
    public static func thermostat(heating: Bool = true, cooling: Bool = false) -> DeviceKind {
        DeviceKind(deviceTypes: [DeviceTypes.thermostat]) { handler in
            await base(handler, actuator: false) + [await DeviceClusters.thermostat(heating: heating, cooling: cooling, handler)]
        }
    }
    /// Locking and unlocking need a timed interaction, as the Door Lock cluster requires (§5.2.10).
    public static let doorLock = DeviceKind(deviceTypes: [DeviceTypes.doorLock]) { handler in
        await base(handler, actuator: false) + [await DeviceClusters.doorLock(handler)]
    }
    /// A button: presses are reported with `BridgedDevice.press`.
    public static let genericSwitch = sensor(DeviceTypes.genericSwitch) { DeviceClusters.genericSwitch() }
    public static let airQualitySensor = sensor(DeviceTypes.airQualitySensor) { DeviceClusters.airQuality() }
    public static func smokeCOAlarm(smoke: Bool = true, carbonMonoxide: Bool = false) -> DeviceKind {
        sensor(DeviceTypes.smokeCoAlarm) { DeviceClusters.smokeCOAlarm(smoke: smoke, carbonMonoxide: carbonMonoxide) }
    }
    /// Opening and closing go to the handler; the valve's state comes back with `DeviceState.valveOpen`.
    public static let waterValve = DeviceKind(deviceTypes: [DeviceTypes.waterValve]) { handler in
        await base(handler, actuator: false) + [await DeviceClusters.valve(handler)]
    }

    /// A robot vacuum: cleaning starts and stops through RVC Run Mode, and it pauses, resumes and goes home through RVC
    /// Operational State; it reports its state with `DeviceState.robot`.
    public static let roboticVacuum = DeviceKind(deviceTypes: [DeviceTypes.roboticVacuumCleaner]) { handler in
        await base(handler, actuator: false) + [await DeviceClusters.rvcRunMode(handler), await DeviceClusters.rvcOperationalState(handler)]
    }

    /// The same device measuring its power and energy too: an Electrical Sensor on its endpoint (Device Library §2.5),
    /// reported with `DeviceState.power` and `.energy`.
    public func metered() -> DeviceKind {
        let kind = self
        return DeviceKind(deviceTypes: deviceTypes + [DeviceTypes.electricalSensor]) { handler in
            await kind.makeClusters(handler) + DeviceClusters.metering()
        }
    }
}

/// One function of a device, with the handler of its commands and tags that tell it from the device's other parts.
public struct DevicePart: Sendable {
    public var kind: DeviceKind
    public var tags: [SemanticTag]
    public var handler: DeviceCommandHandler

    public init(_ kind: DeviceKind, tags: [SemanticTag] = [], handler: @escaping DeviceCommandHandler = { _ in }) {
        self.kind = kind
        self.tags = tags
        self.handler = handler
    }
}

/// A bridged device's identity, shown in Bridged Device Basic Information (Core §9.13).
public struct BridgedDeviceInfo: Hashable, Sendable {
    /// Stable across restarts: it keeps the device's endpoint numbers, and is reported as UniqueID (`uniqueID`).
    public var id: String
    public var name: String
    public var vendorName: String?
    public var productName: String?
    public var serialNumber: String?

    /// UniqueID holds 32 characters (Core §9.13.5): the id itself when it fits, else the first 32 hex digits of its
    /// SHA-256, so two long ids with a common prefix stay apart.
    public var uniqueID: String {
        id.utf8.count <= 32 ? id : String(hexString(Array(SHA256.hash(data: Array(id.utf8)))).prefix(32))
    }

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
    /// Water leak detectors: true when a leak is detected.
    case leak(Bool)
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
    /// Degrees Celsius.
    case localTemperature(Double?)
    case heatingSetpoint(Double)
    case coolingSetpoint(Double)
    /// Thermostat SystemMode: off 0, cool 3, heat 4.
    case thermostatMode(UInt8)
    /// Nil when the lock is neither locked nor unlocked (jammed, in motion).
    case locked(Bool?)
    /// Air Quality's AirQualityEnum: unknown 0, good 1 to extremely poor 6.
    case airQuality(UInt8)
    case smoke(Bool)
    case carbonMonoxide(Bool)
    /// Where the valve is now, open or closed.
    case valveOpen(Bool)
    /// Watts drawn now; a metered device's.
    case power(watts: Double?)
    /// Energy used since the meter started, kWh; a metered device's.
    case energy(kilowattHours: Double?)
    /// A robot vacuum's state.
    case robot(RobotState)
}

/// A press of a bridged button (Generic Switch).
public enum ButtonPress: Sendable {
    case single
    case double
    case long
}

/// A device on the bridge, or the device a node is (`MatterNode.addDevice`).
public actor BridgedDevice {
    public nonisolated let info: BridgedDeviceInfo
    /// The Bridged Node endpoint.
    public nonisolated let endpoint: EndpointNumber
    /// The endpoint of each part: the Bridged Node's own for a single part, children otherwise.
    public nonisolated let partEndpoints: [EndpointNumber]
    private let parts: [[any ClusterHandler]]
    /// Bridged Device Basic Information; nil for a node's own device, which the node's Basic Information describes.
    private let basicInformation: AttributeCluster?
    private let power: AttributeCluster?

    init(info: BridgedDeviceInfo, endpoint: EndpointNumber, partEndpoints: [EndpointNumber], parts: [[any ClusterHandler]],
         basicInformation: AttributeCluster?, power: AttributeCluster?) {
        self.info = info
        self.endpoint = endpoint
        self.partEndpoints = partEndpoints
        self.parts = parts
        self.basicInformation = basicInformation
        self.power = power
    }

    /// A part's stored-attribute cluster, for `set` and `emit` (nil for a custom handler that is not an `AttributeCluster`).
    public func cluster(_ id: ClusterID, part: Int = 0) -> AttributeCluster? {
        if id == PowerSourceCluster.id, let power { return power }
        guard parts.indices.contains(part) else { return nil }
        return parts[part].first { $0.id == id } as? AttributeCluster
    }

    /// Sets attributes of a part's cluster directly: for state the presets do not model.
    public func set(_ values: [AttributeID: TLVValue], cluster id: ClusterID, part: Int = 0) async {
        await cluster(id, part: part)?.set(values)
    }

    /// Records an event of a part's cluster.
    public func emit(_ event: EventID, data: TLVValue, cluster id: ClusterID, part: Int = 0) async {
        await cluster(id, part: part)?.emit(event, data: data)
    }

    /// Reports state the device changed on its own (or confirmed).
    public func update(_ state: DeviceState, part: Int = 0) async {
        func set(_ cluster: ClusterID, _ values: [AttributeID: TLVValue]) async { await self.set(values, cluster: cluster, part: part) }
        /// A finite reading scaled to the cluster's integer units, or nil.
        func scaled(_ value: Double?, by factor: Double, in range: ClosedRange<Double>) -> Double? {
            guard let value, value.isFinite else { return nil }
            return min(max(value * factor, range.lowerBound), range.upperBound).rounded()
        }
        switch state {
        case .on(let on): await set(OnOffCluster.id, [OnOffCluster.Attribute.onOff: .bool(on)])
        case .level(let level): await set(LevelControlCluster.id, [LevelControlCluster.Attribute.currentLevel: .unsigned(UInt64(max(1, min(254, level))))])
        case .colorTemperature(let mireds): await set(ColorControlCluster.id, DeviceClusters.colorTemperatureValues(mireds))
        case .hueSaturation(let hue, let saturation): await set(ColorControlCluster.id, DeviceClusters.hueSaturationValues(hue: hue, saturation: saturation))
        case .contact(let value), .leak(let value):
            let cluster = cluster(BooleanStateCluster.id, part: part)
            guard await cluster?.value(BooleanStateCluster.Attribute.stateValue) != .bool(value) else { return }
            await cluster?.set(BooleanStateCluster.Attribute.stateValue, .bool(value))
            await cluster?.emit(BooleanStateCluster.Event.stateChange, data: .structure([.field(0, .bool(value))]))
        case .occupied(let occupied):
            await set(OccupancySensingCluster.id, [OccupancySensingCluster.Attribute.occupancy: .unsigned(occupied ? 1 : 0)])
        case .temperature(let celsius):
            let value = scaled(celsius, by: 100, in: -27315...32767).map { TLVValue.signed(Int64($0)) } ?? .null
            await set(TemperatureMeasurementCluster.id, [TemperatureMeasurementCluster.Attribute.measuredValue: value])
        case .humidity(let percent):
            let value = scaled(percent, by: 100, in: 0...10000).map { TLVValue.unsigned(UInt64($0)) } ?? .null
            await set(RelativeHumidityMeasurementCluster.id, [RelativeHumidityMeasurementCluster.Attribute.measuredValue: value])
        case .illuminance(let lux):
            // MeasuredValue = 10000 × log10(lux) + 1, 0 for darkness (Application Clusters §2.2.5.1).
            let value: TLVValue = lux.flatMap { $0.isFinite ? $0 : nil }.map {
                $0 < 1 ? .unsigned(0) : .unsigned(UInt64(min(0xFFFE, (10_000 * log10($0) + 1).rounded())))
            } ?? .null
            await set(IlluminanceMeasurementCluster.id, [IlluminanceMeasurementCluster.Attribute.measuredValue: value])
        case .coveringPosition(let position):
            let clamped = UInt64(min(position, 10_000))
            await set(WindowCoveringCluster.id, [WindowCoveringCluster.Attribute.currentPositionLiftPercent100ths: .unsigned(clamped),
                                                 WindowCoveringCluster.Attribute.currentPositionLiftPercentage: .unsigned(clamped / 100)])
        case .fanSpeed(let percent): await set(FanControlCluster.id, DeviceClusters.fanValues(percent: percent))
        case .localTemperature(let celsius):
            let value = scaled(celsius, by: 100, in: -27315...32767).map { TLVValue.signed(Int64($0)) } ?? .null
            await set(ThermostatCluster.id, [ThermostatCluster.Attribute.localTemperature: value])
        case .heatingSetpoint(let celsius):
            if let value = scaled(celsius, by: 100, in: Double(DeviceClusters.heatingRange.lowerBound)...Double(DeviceClusters.heatingRange.upperBound)) {
                await set(ThermostatCluster.id, [ThermostatCluster.Attribute.occupiedHeatingSetpoint: .signed(Int64(value))])
            }
        case .coolingSetpoint(let celsius):
            if let value = scaled(celsius, by: 100, in: Double(DeviceClusters.coolingRange.lowerBound)...Double(DeviceClusters.coolingRange.upperBound)) {
                await set(ThermostatCluster.id, [ThermostatCluster.Attribute.occupiedCoolingSetpoint: .signed(Int64(value))])
            }
        case .thermostatMode(let mode): await set(ThermostatCluster.id, [ThermostatCluster.Attribute.systemMode: .unsigned(UInt64(mode))])
        case .locked(let locked):
            // LockState: not fully locked 0, locked 1, unlocked 2.
            await set(DoorLockCluster.id, [DoorLockCluster.Attribute.lockState: .unsigned(locked.map { $0 ? 1 : 2 } ?? 0)])
        case .airQuality(let quality):
            await set(AirQualityCluster.id, [AirQualityCluster.Attribute.airQuality: .unsigned(UInt64(min(quality, 6)))])
        case .smoke(let detected):
            if let cluster = cluster(SmokeCoAlarmCluster.id, part: part) { await DeviceClusters.setAlarm(cluster, smoke: true, detected: detected) }
        case .carbonMonoxide(let detected):
            if let cluster = cluster(SmokeCoAlarmCluster.id, part: part) { await DeviceClusters.setAlarm(cluster, smoke: false, detected: detected) }
        case .valveOpen(let open):
            guard let cluster = cluster(ValveConfigurationAndControlCluster.id, part: part) else { return }
            await DeviceClusters.setValve(cluster, open: open)
        case .power(let watts):
            let value = scaled(watts, by: 1000, in: Double(DeviceClusters.powerRange.lowerBound)...Double(DeviceClusters.powerRange.upperBound))
            await set(ElectricalPowerMeasurementCluster.id, [ElectricalPowerMeasurementCluster.Attribute.activePower: value.map { .signed(Int64($0)) } ?? .null])
        case .energy(let kilowattHours):
            typealias S = ElectricalEnergyMeasurementCluster.EnergyMeasurementStruct
            guard let cluster = cluster(ElectricalEnergyMeasurementCluster.id, part: part) else { return }
            guard let milliwattHours = scaled(kilowattHours, by: 1_000_000, in: 0...Double(Int64.max / 2)) else {
                await cluster.set(ElectricalEnergyMeasurementCluster.Attribute.cumulativeEnergyImported, .null)
                return
            }
            let previous = await cluster.value(ElectricalEnergyMeasurementCluster.Attribute.cumulativeEnergyImported)?[S.energy]?.int
            guard previous != Int64(milliwattHours) else { return }
            let measurement = TLVValue.structure([.field(S.energy, .signed(Int64(milliwattHours))),
                                                  .field(S.endTimestamp, .unsigned(UInt64(MatterCertificate.matterSeconds(Date()))))])
            await cluster.set(ElectricalEnergyMeasurementCluster.Attribute.cumulativeEnergyImported, measurement)
            await cluster.emit(ElectricalEnergyMeasurementCluster.Event.cumulativeEnergyMeasured, data: .structure([.field(0, measurement)]))
        case .robot(let robot):
            await DeviceClusters.setRobot(robot, runMode: cluster(RvcRunModeCluster.id, part: part),
                                          operational: cluster(RvcOperationalStateCluster.id, part: part))
        case .battery(let percent):
            // BatPercentRemaining is in half percents; the charge level warns below 20 % and is critical below 10 %.
            let clamped = UInt64(min(percent, 100))
            await power?.set([PowerSourceCluster.Attribute.batPercentRemaining: .unsigned(clamped * 2),
                              PowerSourceCluster.Attribute.batChargeLevel: .unsigned(clamped < 10 ? 2 : clamped < 20 ? 1 : 0)])
        }
    }

    /// Reports a button press as the Switch cluster's events (Application Clusters §1.13.7).
    public func press(_ press: ButtonPress, part: Int = 0) async {
        guard let cluster = cluster(SwitchCluster.id, part: part) else { return }
        typealias E = SwitchCluster.Event
        // NewPosition or PreviousPosition: the pressed position, 1.
        let position = TLVValue.structure([.field(0, .unsigned(1))])
        await cluster.set(SwitchCluster.Attribute.currentPosition, .unsigned(1))
        await cluster.emit(E.initialPress, data: position)
        switch press {
        case .long:
            await cluster.emit(E.longPress, data: position)
            await cluster.emit(E.longRelease, data: position)
        case .single:
            await cluster.emit(E.shortRelease, data: position)
            await cluster.emit(E.multiPressComplete, data: .structure([.field(0, .unsigned(1)), .field(1, .unsigned(1))]))
        case .double:
            // The second press starts again, then counts as the second of a multi-press (§1.13.7).
            await cluster.emit(E.shortRelease, data: position)
            await cluster.emit(E.initialPress, data: position)
            await cluster.emit(E.multiPressOngoing, data: .structure([.field(0, .unsigned(1)), .field(1, .unsigned(2))]))
            await cluster.emit(E.shortRelease, data: position)
            await cluster.emit(E.multiPressComplete, data: .structure([.field(0, .unsigned(1)), .field(1, .unsigned(2))]))
        }
        await cluster.set(SwitchCluster.Attribute.currentPosition, .unsigned(0))
    }

    /// Whether the bridge can reach the device (Bridged Device Basic Information's Reachable, Core §9.13.5.1); a
    /// node's own device has nothing to say it.
    public func setReachable(_ reachable: Bool) async {
        guard let basicInformation, await basicInformation.value(BridgedDeviceBasicInformationCluster.Attribute.reachable) != .bool(reachable) else { return }
        await basicInformation.set(BridgedDeviceBasicInformationCluster.Attribute.reachable, .bool(reachable))
        await basicInformation.emit(BridgedDeviceBasicInformationCluster.Event.reachableChanged, data: .structure([.field(0, .bool(reachable))]))
    }

    public func setName(_ name: String) async {
        await basicInformation?.set(BridgedDeviceBasicInformationCluster.Attribute.nodeLabel, .utf8(name.utf8Prefix(32)))
    }
}

extension MatterNode {
    /// Makes the node one device rather than a bridge (Core §9.2): each part on an endpoint of its own from 1, which
    /// the root's PartsList lists. The node's Basic Information (`NodeInformation`) names it; `info` is kept for the
    /// caller. A battery's Power Source is on endpoint 1.
    @discardableResult
    public func addDevice(_ info: BridgedDeviceInfo, parts: [DevicePart], battery: Bool = false) async throws -> BridgedDevice {
        guard !parts.isEmpty else { throw BridgeError.noParts }
        let endpoints = parts.indices.map { EndpointNumber($0 + 1) }
        let (partClusters, power) = await MatterBridge.build(parts, battery: battery, powering: endpoints)
        for (index, part) in parts.enumerated() {
            let first = index == 0
            try await add(Endpoint(number: endpoints[index],
                                   deviceTypes: part.kind.deviceTypes + (first && battery ? [DeviceTypes.powerSource] : []),
                                   clusters: partClusters[index] + (first ? power.map { [$0] } ?? [] : []), tags: part.tags))
        }
        return BridgedDevice(info: info, endpoint: 1, partEndpoints: endpoints, parts: partClusters,
                             basicInformation: nil, power: power)
    }
}

public enum BridgeError: Error, Equatable, Sendable {
    case deviceExists(String)
    case unknownDevice(String)
    case noParts
    case endpointsExhausted
}

/// A Matter bridge on a node: an Aggregator endpoint, and bridged devices on endpoints after it, persisted by device id
/// and never reused (Core §9.2.10).
public actor MatterBridge {
    public let node: MatterNode
    public nonisolated let aggregatorEndpoint: EndpointNumber
    private var devices: [String: BridgedDevice] = [:]
    /// Every endpoint ever given, by device id (a part's id is "<id>#<n>").
    private var endpoints: [String: EndpointNumber] = [:]
    private var nextEndpoint: EndpointNumber

    public init(node: MatterNode, aggregatorEndpoint: EndpointNumber = 1) async throws {
        self.node = node
        self.aggregatorEndpoint = aggregatorEndpoint
        nextEndpoint = aggregatorEndpoint + 1
        if let data = await node.storage.value(for: StorageKey.bridgeEndpoints), let fields = try? TLVStruct(decoding: data) {
            nextEndpoint = (try? fields.uint(1, as: UInt16.self)) ?? nextEndpoint
            for entry in (try? fields.elements(2)) ?? [] {
                if let id = entry.value[0]?.string, let number = entry.value[1]?.uint.flatMap(UInt16.init(exactly:)) { endpoints[id] = number }
            }
        }
        try await node.add(Endpoint(number: aggregatorEndpoint, deviceTypes: [DeviceTypes.aggregator], clusters: []))
    }

    public var allDevices: [BridgedDevice] { devices.values.sorted { $0.endpoint < $1.endpoint } }

    public func device(_ id: String) -> BridgedDevice? { devices[id] }

    /// Adds a device with one function.
    @discardableResult
    public func add(_ info: BridgedDeviceInfo, kind: DeviceKind, battery: Bool = false,
                    handler: @escaping DeviceCommandHandler = { _ in }) async throws -> BridgedDevice {
        try await add(info, parts: [DevicePart(kind, handler: handler)], battery: battery)
    }

    /// Adds a device; several parts make a compound device with a child endpoint per part.
    @discardableResult
    public func add(_ info: BridgedDeviceInfo, parts: [DevicePart], battery: Bool = false) async throws -> BridgedDevice {
        guard devices[info.id] == nil else { throw BridgeError.deviceExists(info.id) }
        guard !parts.isEmpty else { throw BridgeError.noParts }
        var allocated = false
        let top = try allocate(info.id, &allocated)
        let partEndpoints = parts.count == 1 ? [top] : try parts.indices.map { try allocate("\(info.id)#\($0)", &allocated) }
        if allocated { try await saveEndpoints() }

        let basicInformation = Self.basicInformation(info)
        // A battery powers the whole device: its Power Source is on the Bridged Node (Core §9.12.2.3).
        let (partClusters, power) = await Self.build(parts, battery: battery, powering: [top] + (parts.count > 1 ? partEndpoints : []))
        var topTypes = [DeviceTypes.bridgedNode] + (battery ? [DeviceTypes.powerSource] : [])
        var topClusters: [any ClusterHandler] = [basicInformation] + (power.map { [$0] } ?? [])
        if parts.count == 1 {
            topTypes = parts[0].kind.deviceTypes + topTypes
            topClusters = partClusters[0] + topClusters
        }
        try await node.add(Endpoint(number: top, deviceTypes: topTypes, clusters: topClusters, parent: aggregatorEndpoint))
        if parts.count > 1 {
            for (index, part) in parts.enumerated() {
                try await node.add(Endpoint(number: partEndpoints[index], deviceTypes: part.kind.deviceTypes,
                                            clusters: partClusters[index], parent: top, tags: part.tags))
            }
        }
        let device = BridgedDevice(info: info, endpoint: top, partEndpoints: partEndpoints, parts: partClusters,
                                   basicInformation: basicInformation, power: power)
        devices[info.id] = device
        return device
    }

    /// Removes a device; its endpoint numbers are not given to another device.
    public func remove(_ id: String) async throws {
        guard let device = devices.removeValue(forKey: id) else { throw BridgeError.unknownDevice(id) }
        try await node.remove(endpoint: device.endpoint)
    }

    private func allocate(_ id: String, _ allocated: inout Bool) throws -> EndpointNumber {
        if let known = endpoints[id] { return known }
        guard nextEndpoint < EndpointNumber.max else { throw BridgeError.endpointsExhausted }
        defer { nextEndpoint += 1 }
        endpoints[id] = nextEndpoint
        allocated = true
        return nextEndpoint
    }

    private func saveEndpoints() async throws {
        try await node.storage.setValue(TLVEncoder.encode(.structure([
            .field(1, .unsigned(UInt64(nextEndpoint))),
            .field(2, .array(endpoints.sorted { $0.value < $1.value }.map { id, number in
                TLVElement(.structure([.field(0, .utf8(id)), .field(1, .unsigned(UInt64(number)))]))
            })),
        ])), for: StorageKey.bridgeEndpoints)
    }

    /// Each part's clusters, and the Power Source of a battery that powers `endpoints`.
    static func build(_ parts: [DevicePart], battery: Bool, powering endpoints: [EndpointNumber]) async
        -> (clusters: [[any ClusterHandler]], power: AttributeCluster?) {
        var clusters: [[any ClusterHandler]] = []
        for part in parts { clusters.append(await part.kind.makeClusters(part.handler)) }
        return (clusters, battery ? DeviceClusters.battery(endpoints: endpoints) : nil)
    }

    static func basicInformation(_ info: BridgedDeviceInfo) -> AttributeCluster {
        typealias A = BridgedDeviceBasicInformationCluster.Attribute
        func label(_ text: String) -> TLVValue { .utf8(text.utf8Prefix(32)) }
        var attributes: [AttributeID: TLVValue] = [
            A.nodeLabel: label(info.name), A.reachable: .bool(true), A.uniqueId: .utf8(info.uniqueID), A.configurationVersion: .unsigned(1),
        ]
        if let vendor = info.vendorName { attributes[A.vendorName] = label(vendor) }
        if let product = info.productName { attributes[A.productName] = label(product) }
        if let serial = info.serialNumber { attributes[A.serialNumber] = label(serial) }
        return AttributeCluster(BridgedDeviceBasicInformationCluster.definition, attributes: attributes)
    }
}
