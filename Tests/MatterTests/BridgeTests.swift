import Testing
@testable import Matter

struct BridgeTests {
    /// A commissioned bridge and its commissioner's CASE session.
    struct Fixture {
        let base: CommissioningFixture
        let bridge: MatterBridge
        let session: UInt16
        let commands = Recorder<DeviceCommand>()

        init() async throws {
            base = try await CommissioningFixture()
            bridge = try await MatterBridge(node: base.node)
            session = try await base.commissioner.commission(.memory("node"), passcode: CommissioningFixture.passcode, nodeID: 0x42).localSessionID
        }

        func read(_ endpoint: EndpointNumber, _ cluster: ClusterID, _ attribute: AttributeID) async throws -> TLVValue {
            try await base.commissioner.client.read(endpoint: endpoint, cluster: cluster, attribute: attribute, session: session)
        }

        func invoke(_ endpoint: EndpointNumber, _ cluster: ClusterID, _ command: CommandID, _ fields: [TLVElement] = []) async throws -> InvokeResult {
            try await base.commissioner.client.invoke(CommandPath(endpoint: endpoint, cluster: cluster, command: command),
                                                      fields: .structure(fields), session: session)
        }
    }

    @Test func exposesBridgedDevicesUnderTheAggregator() async throws {
        let fixture = try await Fixture()
        let commands = fixture.commands
        let light = try await fixture.bridge.add(BridgedDeviceInfo(id: "hue-1", name: "Kitchen", vendorName: "Hue"),
                                                 kind: .extendedColorLight(mireds: 153...500)) { await commands.append($0) }
        _ = try await fixture.bridge.add(BridgedDeviceInfo(id: "door", name: "Front door"), kind: .contactSensor, battery: true)
        #expect(light.endpoint == 2)

        #expect(try await fixture.read(1, DescriptorCluster.id, DescriptorCluster.Attribute.partsList) == .array([TLVElement(.unsigned(2)), TLVElement(.unsigned(3))]))
        let types = try await fixture.read(2, DescriptorCluster.id, DescriptorCluster.Attribute.deviceTypeList)
        #expect(types.elements?.compactMap { $0.value[0]?.uint } == [UInt64(DeviceTypes.extendedColorLight.id), UInt64(DeviceTypes.bridgedNode.id)])
        #expect(try await fixture.read(2, BridgedDeviceBasicInformationCluster.id, BridgedDeviceBasicInformationCluster.Attribute.nodeLabel) == .utf8("Kitchen"))
        // The root's PartsList has every endpoint.
        #expect(try await fixture.read(0, DescriptorCluster.id, DescriptorCluster.Attribute.partsList).elements?.count == 3)

        // Commands reach the handler and update the attributes.
        _ = try await fixture.invoke(2, OnOffCluster.id, OnOffCluster.Command.on)
        _ = try await fixture.invoke(2, LevelControlCluster.id, LevelControlCluster.Command.moveToLevelWithOnOff,
                                     [.field(0, .unsigned(100)), .field(1, .null), .field(2, .unsigned(0)), .field(3, .unsigned(0))])
        _ = try await fixture.invoke(2, ColorControlCluster.id, ColorControlCluster.Command.moveToColorTemperature,
                                     [.field(0, .unsigned(370)), .field(1, .unsigned(0)), .field(2, .unsigned(0)), .field(3, .unsigned(0))])
        #expect(await commands.values == [.setOn(true), .setLevel(100), .setOn(true), .setColorTemperature(mireds: 370)])
        #expect(try await fixture.read(2, LevelControlCluster.id, LevelControlCluster.Attribute.currentLevel) == .unsigned(100))
        #expect(try await fixture.read(2, ColorControlCluster.id, ColorControlCluster.Attribute.colorTemperatureMireds) == .unsigned(370))

        // Device-side changes show up.
        await light.update(.on(false))
        #expect(try await fixture.read(2, OnOffCluster.id, OnOffCluster.Attribute.onOff) == .bool(false))
        await light.setReachable(false)
        #expect(try await fixture.read(2, BridgedDeviceBasicInformationCluster.id, BridgedDeviceBasicInformationCluster.Attribute.reachable) == .bool(false))
    }

    @Test func reportsSensorValues() async throws {
        let fixture = try await Fixture()
        let temperature = try await fixture.bridge.add(BridgedDeviceInfo(id: "t", name: "Office"), kind: .temperatureSensor)
        let door = try await fixture.bridge.add(BridgedDeviceInfo(id: "d", name: "Door"), kind: .contactSensor, battery: true)
        let light = try await fixture.bridge.add(BridgedDeviceInfo(id: "l", name: "Lux"), kind: .lightSensor)
        await temperature.update(.temperature(21.56))
        await door.update(.contact(true))
        await door.update(.battery(percent: 15))
        await light.update(.illuminance(lux: 1000))
        #expect(try await fixture.read(2, TemperatureMeasurementCluster.id, 0) == .signed(2156))
        #expect(try await fixture.read(3, BooleanStateCluster.id, BooleanStateCluster.Attribute.stateValue) == .bool(true))
        #expect(try await fixture.read(3, PowerSourceCluster.id, PowerSourceCluster.Attribute.batPercentRemaining) == .unsigned(30))
        #expect(try await fixture.read(3, PowerSourceCluster.id, PowerSourceCluster.Attribute.batChargeLevel) == .unsigned(1))
        #expect(try await fixture.read(4, IlluminanceMeasurementCluster.id, 0) == .unsigned(30001))
        // The contact change was recorded as an event.
        let (_, events) = try await fixture.base.commissioner.client.read([], events: [EventPath(endpoint: 3)], session: fixture.session)
        #expect(events.count == 1)
    }

    @Test func keepsEndpointNumbersAndNeverReusesThem() async throws {
        let fixture = try await Fixture()
        _ = try await fixture.bridge.add(BridgedDeviceInfo(id: "a", name: "A"), kind: .onOffPlug)
        _ = try await fixture.bridge.add(BridgedDeviceInfo(id: "b", name: "B"), kind: .onOffPlug)
        try await fixture.bridge.remove("a")
        let c = try await fixture.bridge.add(BridgedDeviceInfo(id: "c", name: "C"), kind: .onOffPlug)
        #expect(c.endpoint == 4)
        #expect(try await fixture.read(1, DescriptorCluster.id, DescriptorCluster.Attribute.partsList) == .array([TLVElement(.unsigned(3)), TLVElement(.unsigned(4))]))

        // A new bridge on the same storage gives known devices their endpoints back.
        await fixture.base.node.stop()
        var configuration = NodeConfiguration(passcode: CommissioningFixture.passcode, discriminator: 3840)
        configuration.reliability = .fast
        let node = try await MatterNode(configuration: configuration, storage: fixture.base.storage,
                                        transport: await fixture.base.network.transport(named: "node2"))
        let bridge = try await MatterBridge(node: node)
        #expect(try await bridge.add(BridgedDeviceInfo(id: "a", name: "A"), kind: .onOffPlug).endpoint == 2)
        #expect(try await bridge.add(BridgedDeviceInfo(id: "d", name: "D"), kind: .onOffPlug).endpoint == 5)
        await #expect(throws: BridgeError.deviceExists("d")) {
            try await bridge.add(BridgedDeviceInfo(id: "d", name: "D"), kind: .onOffPlug)
        }
    }

    @Test func coversAndFans() async throws {
        let fixture = try await Fixture()
        let commands = fixture.commands
        _ = try await fixture.bridge.add(BridgedDeviceInfo(id: "blind", name: "Blind"), kind: .windowCovering) { await commands.append($0) }
        _ = try await fixture.bridge.add(BridgedDeviceInfo(id: "fan", name: "Fan"), kind: .fan) { await commands.append($0) }
        _ = try await fixture.invoke(2, WindowCoveringCluster.id, WindowCoveringCluster.Command.goToLiftPercentage, [.field(0, .unsigned(2500))])
        _ = try await fixture.invoke(2, WindowCoveringCluster.id, WindowCoveringCluster.Command.downOrClose)
        let statuses = try await fixture.base.commissioner.client.write([
            (AttributePath(endpoint: 3, cluster: FanControlCluster.id, attribute: FanControlCluster.Attribute.percentSetting), .unsigned(50)),
        ], session: fixture.session)
        #expect(statuses.map(\.1.status) == [.success])
        #expect(await commands.values == [.setCoveringPosition(percent100ths: 2500), .setCoveringPosition(percent100ths: 10_000), .setFanSpeed(percent: 50)])
        #expect(try await fixture.read(3, FanControlCluster.id, FanControlCluster.Attribute.fanMode) == .unsigned(2))
    }

    @Test func composesDevicesFromParts() async throws {
        let fixture = try await Fixture()
        let commands = fixture.commands
        // A ceiling fan with a light: a Bridged Node with two child endpoints.
        let fan = try await fixture.bridge.add(BridgedDeviceInfo(id: "ceiling-fan", name: "Ceiling fan"), parts: [
            DevicePart(.fan) { await commands.append($0) },
            DevicePart(.dimmableLight, tags: [SemanticTag(namespace: 0x07, tag: 0x00, label: "Light")]) { await commands.append($0) },
        ], battery: false)
        #expect(fan.endpoint == 2)
        #expect(fan.partEndpoints == [3, 4])
        #expect(try await fixture.read(2, DescriptorCluster.id, DescriptorCluster.Attribute.partsList) == .array([TLVElement(.unsigned(3)), TLVElement(.unsigned(4))]))
        #expect(try await fixture.read(1, DescriptorCluster.id, DescriptorCluster.Attribute.partsList).elements?.count == 3)
        let types = try await fixture.read(2, DescriptorCluster.id, DescriptorCluster.Attribute.deviceTypeList)
        #expect(types.elements?.compactMap { $0.value[0]?.uint } == [UInt64(DeviceTypes.bridgedNode.id)])
        #expect(try await fixture.read(4, DescriptorCluster.id, DescriptorCluster.Attribute.tagList).elements?.count == 1)

        _ = try await fixture.invoke(4, OnOffCluster.id, OnOffCluster.Command.on)
        #expect(await commands.values == [.setOn(true)])
        await fan.update(.fanSpeed(percent: 40), part: 0)
        #expect(try await fixture.read(3, FanControlCluster.id, FanControlCluster.Attribute.fanMode) == .unsigned(2))
        await fan.update(.on(false), part: 1)
        #expect(try await fixture.read(4, OnOffCluster.id, OnOffCluster.Attribute.onOff) == .bool(false))
    }

    @Test func acceptsCustomKindsAndRawAttributes() async throws {
        let fixture = try await Fixture()
        // A thermostat the presets do not model: the application gives its clusters.
        let thermostat = DeviceKind(deviceTypes: [DeviceTypes.thermostat]) { _ in
            [AttributeCluster(ThermostatCluster.definition, featureMap: ThermostatCluster.Feature.heating.rawValue, attributes: [
                ThermostatCluster.Attribute.localTemperature: .signed(2000), ThermostatCluster.Attribute.systemMode: .unsigned(4),
                ThermostatCluster.Attribute.controlSequenceOfOperation: .unsigned(2),
                ThermostatCluster.Attribute.occupiedHeatingSetpoint: .signed(2100),
            ])]
        }
        let device = try await fixture.bridge.add(BridgedDeviceInfo(id: "tado", name: "Radiator"), kind: thermostat)
        await device.set([ThermostatCluster.Attribute.localTemperature: .signed(2150)], cluster: ThermostatCluster.id)
        #expect(try await fixture.read(2, ThermostatCluster.id, ThermostatCluster.Attribute.localTemperature) == .signed(2150))
        // Non-finite readings become null rather than trapping.
        let sensor = try await fixture.bridge.add(BridgedDeviceInfo(id: "t", name: "T"), kind: .temperatureSensor)
        await sensor.update(.temperature(.nan))
        #expect(try await fixture.read(3, TemperatureMeasurementCluster.id, TemperatureMeasurementCluster.Attribute.measuredValue) == .null)
    }

    @Test func rejectsOversizedLevelSteps() async throws {
        let fixture = try await Fixture()
        _ = try await fixture.bridge.add(BridgedDeviceInfo(id: "l", name: "L"), kind: .dimmableLight)
        let result = try await fixture.invoke(2, LevelControlCluster.id, LevelControlCluster.Command.step,
                                              [.field(0, .unsigned(0)), .field(1, .unsigned(UInt64.max)), .field(2, .null),
                                               .field(3, .unsigned(0)), .field(4, .unsigned(0))])
        guard case .status(let status) = result else { Issue.record("Expected a status"); return }
        #expect(status.status != .success)
    }

    @Test func thermostatsLocksAndButtons() async throws {
        let fixture = try await Fixture()
        let commands = fixture.commands
        let thermostat = try await fixture.bridge.add(BridgedDeviceInfo(id: "thermo", name: "Hall"), kind: .thermostat(heating: true, cooling: true)) {
            await commands.append($0)
        }
        _ = try await fixture.bridge.add(BridgedDeviceInfo(id: "lock", name: "Front door"), kind: .doorLock) { await commands.append($0) }
        let button = try await fixture.bridge.add(BridgedDeviceInfo(id: "button", name: "Button"), kind: .genericSwitch)

        // Setpoints: a write and a relative change.
        let statuses = try await fixture.base.commissioner.client.write([
            (AttributePath(endpoint: 2, cluster: ThermostatCluster.id, attribute: ThermostatCluster.Attribute.occupiedHeatingSetpoint), .signed(2150)),
            (AttributePath(endpoint: 2, cluster: ThermostatCluster.id, attribute: ThermostatCluster.Attribute.occupiedHeatingSetpoint), .signed(9000)),
        ], session: fixture.session)
        #expect(statuses.map(\.1.status) == [.success, .constraintError])
        _ = try await fixture.invoke(2, ThermostatCluster.id, ThermostatCluster.Command.setpointRaiseLower, [.field(0, .unsigned(0)), .field(1, .signed(-5))])
        #expect(try await fixture.read(2, ThermostatCluster.id, ThermostatCluster.Attribute.occupiedHeatingSetpoint) == .signed(2100))
        await thermostat.update(.localTemperature(19.5))
        #expect(try await fixture.read(2, ThermostatCluster.id, ThermostatCluster.Attribute.localTemperature) == .signed(1950))

        // Unlocking needs a timed invoke.
        let untimed = try await fixture.invoke(3, DoorLockCluster.id, DoorLockCluster.Command.unlockDoor)
        guard case .status(let refused) = untimed else { Issue.record("Expected a status"); return }
        #expect(refused.status == .needsTimedInteraction)
        let timed = try await fixture.base.commissioner.client.invoke(
            CommandPath(endpoint: 3, cluster: DoorLockCluster.id, command: DoorLockCluster.Command.unlockDoor), timed: .seconds(5),
            session: fixture.session)
        guard case .status(let unlocked) = timed else { Issue.record("Expected a status"); return }
        #expect(unlocked.status == .success)
        #expect(try await fixture.read(3, DoorLockCluster.id, DoorLockCluster.Attribute.lockState) == .unsigned(2))

        #expect(await commands.values == [.setHeatingSetpoint(celsius: 21.5), .setHeatingSetpoint(celsius: 21.0), .setLocked(false)])

        // A double press is reported as Switch events.
        await button.press(.double)
        let (_, events) = try await fixture.base.commissioner.client.read([], events: [EventPath(endpoint: 4, cluster: SwitchCluster.id)],
                                                                         session: fixture.session)
        let ids = events.compactMap { if case .data(let record) = $0 { record.event } else { nil } }
        #expect(ids == [SwitchCluster.Event.initialPress, SwitchCluster.Event.shortRelease, SwitchCluster.Event.initialPress,
                        SwitchCluster.Event.multiPressOngoing,
                        SwitchCluster.Event.shortRelease, SwitchCluster.Event.multiPressComplete])
    }
}
