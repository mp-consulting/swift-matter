/// Application clusters for bridged devices (Application Cluster specification), as `AttributeCluster`s whose commands
/// update their own attributes and tell the device through `DeviceCommand`s.

/// What a controller asked a bridged device to do.
public enum DeviceCommand: Hashable, Sendable {
    case setOn(Bool)
    /// 1...254 (Level Control's CurrentLevel).
    case setLevel(UInt8)
    case setColorTemperature(mireds: UInt16)
    /// Hue and saturation, 0...254.
    case setHueSaturation(hue: UInt8, saturation: UInt8)
    /// CIE 1931 x and y, 0...65279 for 0...0.9961.
    case setColorXY(x: UInt16, y: UInt16)
    /// The covering's target, in hundredths of a percent closed (0 open, 10000 closed).
    case setCoveringPosition(percent100ths: UInt16)
    case stopCovering
    /// 0...100.
    case setFanSpeed(percent: UInt8)
    case identify(seconds: UInt16)
}

/// Delivers a device's commands to the application.
public typealias DeviceCommandHandler = @Sendable (DeviceCommand) async throws -> Void

enum DeviceClusters {
    /// Runs the application's handler; a failure becomes a FAILURE status for the controller.
    static func deliver(_ command: DeviceCommand, to handler: DeviceCommandHandler) async throws {
        do { try await handler(command) } catch { throw StatusError(.failure) }
    }

    // MARK: - Identify (§1.2)

    static func identify(_ handler: @escaping DeviceCommandHandler) async -> AttributeCluster {
        typealias A = IdentifyCluster.Attribute
        let cluster = AttributeCluster(IdentifyCluster.definition, attributes: [A.identifyTime: .unsigned(0), A.identifyType: .unsigned(0)])
        await cluster.onWrite { _, attribute, value, _ in
            guard attribute == A.identifyTime, let seconds = value.uint.flatMap(UInt16.init(exactly:)) else { throw StatusError(.constraintError) }
            try await deliver(.identify(seconds: seconds), to: handler)
        }
        await cluster.handle(IdentifyCluster.Command.identify) { _, fields, _ in
            try await deliver(.identify(seconds: try TLVStruct(fields).uint(0, as: UInt16.self)), to: handler)
            return .success
        }
        await cluster.handle(IdentifyCluster.Command.triggerEffect) { _, _, _ in
            try await deliver(.identify(seconds: 1), to: handler)
            return .success
        }
        return cluster
    }

    // MARK: - Groups (§1.3) and Scenes Management (§1.4)

    /// Groups without capacity: group communication is not supported, so every add fails with RESOURCE_EXHAUSTED.
    static func groups() async -> AttributeCluster {
        typealias C = GroupsCluster.Command
        let cluster = AttributeCluster(GroupsCluster.definition, attributes: [GroupsCluster.Attribute.nameSupport: .unsigned(0)])
        @Sendable func status(_ command: CommandID, _ status: IMStatus, _ fields: TLVValue) -> InvokeResult {
            .response(command, .structure([.field(0, .unsigned(UInt64(status.rawValue))), .field(1, .unsigned(fields[0]?.uint ?? 0))]))
        }
        await cluster.handle([
            C.addGroup: { _, fields, _ in status(C.addGroupResponse, .resourceExhausted, fields) },
            C.addGroupIfIdentifying: { _, _, _ in throw StatusError(.resourceExhausted) },
            C.viewGroup: { _, fields, _ in
                .response(C.viewGroupResponse, .structure([
                    .field(0, .unsigned(UInt64(IMStatus.notFound.rawValue))), .field(1, .unsigned(fields[0]?.uint ?? 0)), .field(2, .utf8("")),
                ]))
            },
            C.getGroupMembership: { _, _, _ in
                .response(C.getGroupMembershipResponse, .structure([.field(0, .null), .field(1, .array([]))]))
            },
            C.removeGroup: { _, fields, _ in status(C.removeGroupResponse, .notFound, fields) },
            C.removeAllGroups: { _, _, _ in .success },
        ])
        return cluster
    }

    /// Scenes without stored scenes: every fabric sees an empty table.
    static func scenes() async -> AttributeCluster {
        typealias A = ScenesManagementCluster.Attribute
        typealias C = ScenesManagementCluster.Command
        let cluster = AttributeCluster(ScenesManagementCluster.definition, attributes: [A.sceneTableSize: .unsigned(16)])
        await cluster.provide(A.fabricSceneInfo) { context in
            typealias Info = ScenesManagementCluster.SceneInfoStruct
            guard let fabric = context.fabricIndex else { return .array([]) }
            return .array([TLVElement(.structure([
                .field(Info.sceneCount, .unsigned(0)), .field(Info.currentScene, .unsigned(0)), .field(Info.currentGroup, .unsigned(0)),
                .field(Info.sceneValid, .bool(false)), .field(Info.remainingCapacity, .unsigned(16)),
                .field(Info.fabricIndex, .unsigned(UInt64(fabric))),
            ]))])
        }
        @Sendable func response(_ command: CommandID, _ status: IMStatus, _ fields: TLVValue, scene: Bool = true) -> InvokeResult {
            var result: [TLVElement] = [.field(0, .unsigned(UInt64(status.rawValue))), .field(1, .unsigned(fields[0]?.uint ?? 0))]
            if scene { result.append(.field(2, .unsigned(fields[1]?.uint ?? 0))) }
            return .response(command, .structure(result))
        }
        await cluster.handle([
            C.addScene: { _, fields, _ in response(C.addSceneResponse, .resourceExhausted, fields) },
            C.viewScene: { _, fields, _ in response(C.viewSceneResponse, .notFound, fields) },
            C.removeScene: { _, fields, _ in response(C.removeSceneResponse, .notFound, fields) },
            C.removeAllScenes: { _, fields, _ in response(C.removeAllScenesResponse, .success, fields, scene: false) },
            C.storeScene: { _, fields, _ in response(C.storeSceneResponse, .resourceExhausted, fields) },
            C.recallScene: { _, _, _ in throw StatusError(.notFound) },
            C.getSceneMembership: { _, fields, _ in
                .response(C.getSceneMembershipResponse, .structure([
                    .field(0, .unsigned(0)), .field(1, .unsigned(16)), .field(2, .unsigned(fields[0]?.uint ?? 0)), .field(3, .array([])),
                ]))
            },
            C.copyScene: { _, fields, _ in
                .response(C.copySceneResponse, .structure([
                    .field(0, .unsigned(UInt64(IMStatus.resourceExhausted.rawValue))), .field(1, .unsigned(fields[1]?.uint ?? 0)),
                    .field(2, .unsigned(fields[2]?.uint ?? 0)),
                ]))
            },
        ])
        return cluster
    }

    // MARK: - On/Off (§1.5)

    static func onOff(lighting: Bool, _ handler: @escaping DeviceCommandHandler) async -> AttributeCluster {
        typealias A = OnOffCluster.Attribute
        typealias C = OnOffCluster.Command
        var attributes: [AttributeID: TLVValue] = [A.onOff: .bool(false)]
        if lighting {
            attributes.merge([A.globalSceneControl: .bool(true), A.onTime: .unsigned(0), A.offWaitTime: .unsigned(0), A.startUpOnOff: .null]) { $1 }
        }
        let cluster = AttributeCluster(OnOffCluster.definition, featureMap: lighting ? OnOffCluster.Feature.lighting.rawValue : 0,
                                       attributes: attributes)
        @Sendable func set(_ cluster: AttributeCluster, _ on: Bool) async throws -> InvokeResult {
            try await deliver(.setOn(on), to: handler)
            await cluster.set(A.onOff, .bool(on))
            return .success
        }
        await cluster.handle(C.on) { cluster, _, _ in try await set(cluster, true) }
        await cluster.handle(C.off) { cluster, _, _ in try await set(cluster, false) }
        await cluster.handle(C.toggle) { cluster, _, _ in try await set(cluster, !(await cluster.value(A.onOff)?.bool ?? false)) }
        if lighting {
            await cluster.handle(C.offWithEffect) { cluster, _, _ in try await set(cluster, false) }
            await cluster.handle(C.onWithRecallGlobalScene) { cluster, _, _ in try await set(cluster, true) }
            await cluster.handle(C.onWithTimedOff) { cluster, fields, _ in
                // Accept-only-when-on (bit 0 of the control) leaves an off light off.
                if (fields[0]?.uint ?? 0) & 1 == 1, await cluster.value(A.onOff)?.bool != true { return .success }
                return try await set(cluster, true)
            }
        }
        return cluster
    }

    // MARK: - Level Control (§1.6)

    static func levelControl(onOff: AttributeCluster?, _ handler: @escaping DeviceCommandHandler) async -> AttributeCluster {
        typealias A = LevelControlCluster.Attribute
        typealias C = LevelControlCluster.Command
        let features = LevelControlCluster.Feature([.onOff, .lighting])
        let cluster = AttributeCluster(LevelControlCluster.definition, featureMap: features.rawValue, attributes: [
            A.currentLevel: .unsigned(254), A.remainingTime: .unsigned(0), A.minLevel: .unsigned(1), A.maxLevel: .unsigned(254),
            A.options: .unsigned(0), A.onLevel: .null, A.startUpCurrentLevel: .null, A.onOffTransitionTime: .unsigned(0),
        ])
        @Sendable func moveTo(_ cluster: AttributeCluster, _ level: UInt64, withOnOff: Bool) async throws -> InvokeResult {
            let clamped = UInt8(max(1, min(254, level)))
            try await deliver(.setLevel(clamped), to: handler)
            await cluster.set(A.currentLevel, .unsigned(UInt64(clamped)))
            if withOnOff, let onOff {
                // The "with On/Off" commands turn the light on above the minimum and off at it (§1.6.7).
                let on = clamped > 1
                try await deliver(.setOn(on), to: handler)
                await onOff.set(OnOffCluster.Attribute.onOff, .bool(on))
            }
            return .success
        }
        @Sendable func step(_ cluster: AttributeCluster, _ fields: TLVValue, withOnOff: Bool) async throws -> InvokeResult {
            // StepMode and StepSize are 8-bit (§1.6.7.3): narrowed so a large peer value cannot overflow.
            let request = try TLVStruct(fields)
            let current = await cluster.value(A.currentLevel)?.uint ?? 254
            let size = UInt64(try request.uint(1, as: UInt8.self))
            let target = try request.uint(0, as: UInt8.self) == 0 ? current + size : (current > size ? current - size : 1)
            return try await moveTo(cluster, target, withOnOff: withOnOff)
        }
        @Sendable func move(_ cluster: AttributeCluster, _ fields: TLVValue, withOnOff: Bool) async throws -> InvokeResult {
            // Moves complete at once: up to the maximum or down to the minimum.
            try await moveTo(cluster, fields[0]?.uint == 0 ? 254 : 1, withOnOff: withOnOff)
        }
        await cluster.handle(C.moveToLevel) { cluster, fields, _ in try await moveTo(cluster, try TLVStruct(fields).uint(0), withOnOff: false) }
        await cluster.handle(C.moveToLevelWithOnOff) { cluster, fields, _ in try await moveTo(cluster, try TLVStruct(fields).uint(0), withOnOff: true) }
        await cluster.handle(C.move) { cluster, fields, _ in try await move(cluster, fields, withOnOff: false) }
        await cluster.handle(C.moveWithOnOff) { cluster, fields, _ in try await move(cluster, fields, withOnOff: true) }
        await cluster.handle(C.step) { cluster, fields, _ in try await step(cluster, fields, withOnOff: false) }
        await cluster.handle(C.stepWithOnOff) { cluster, fields, _ in try await step(cluster, fields, withOnOff: true) }
        await cluster.handle(C.stop) { _, _, _ in .success }
        await cluster.handle(C.stopWithOnOff) { _, _, _ in .success }
        return cluster
    }

    // MARK: - Color Control (§3.2)

    static func colorControl(hueSaturation: Bool, temperatureRange: ClosedRange<UInt16>, _ handler: @escaping DeviceCommandHandler) async -> AttributeCluster {
        typealias A = ColorControlCluster.Attribute
        typealias C = ColorControlCluster.Command
        // Extended color lights support XY as well (Device Library §4.4); color temperature lights only CT.
        var features: ColorControlCluster.Feature = [.colorTemperature]
        if hueSaturation { features.formUnion([.hueSaturation, .xy]) }
        var attributes: [AttributeID: TLVValue] = [
            A.remainingTime: .unsigned(0), A.colorMode: .unsigned(2), A.enhancedColorMode: .unsigned(2), A.options: .unsigned(0),
            A.numberOfPrimaries: .null, A.colorCapabilities: .unsigned(UInt64(features.rawValue)),
            A.colorTemperatureMireds: .unsigned(UInt64(temperatureRange.lowerBound)),
            A.colorTempPhysicalMinMireds: .unsigned(UInt64(temperatureRange.lowerBound)),
            A.colorTempPhysicalMaxMireds: .unsigned(UInt64(temperatureRange.upperBound)),
            A.coupleColorTempToLevelMinMireds: .unsigned(UInt64(temperatureRange.lowerBound)), A.startUpColorTemperatureMireds: .null,
        ]
        if hueSaturation {
            attributes.merge([A.currentHue: .unsigned(0), A.currentSaturation: .unsigned(0), A.currentX: .unsigned(0x616B),
                              A.currentY: .unsigned(0x607D)]) { $1 }
        }
        let cluster = AttributeCluster(ColorControlCluster.definition, featureMap: features.rawValue, attributes: attributes)

        await cluster.handle(C.moveToColorTemperature) { cluster, fields, _ in
            let mireds = UInt16(clamping: min(max(try TLVStruct(fields).uint(0), UInt64(temperatureRange.lowerBound)), UInt64(temperatureRange.upperBound)))
            try await deliver(.setColorTemperature(mireds: mireds), to: handler)
            await cluster.set(colorTemperatureValues(mireds))
            return .success
        }
        await cluster.handle(C.stopMoveStep) { _, _, _ in .success }
        await cluster.handle(C.moveColorTemperature) { _, _, _ in .success }
        await cluster.handle(C.stepColorTemperature) { _, _, _ in .success }
        guard hueSaturation else { return cluster }

        @Sendable func hueSat(_ cluster: AttributeCluster, hue: UInt64?, saturation: UInt64?) async throws -> InvokeResult {
            let currentHue = await cluster.value(A.currentHue)?.uint ?? 0
            let currentSaturation = await cluster.value(A.currentSaturation)?.uint ?? 0
            let newHue = UInt8(min(254, hue ?? currentHue))
            let newSaturation = UInt8(min(254, saturation ?? currentSaturation))
            try await deliver(.setHueSaturation(hue: newHue, saturation: newSaturation), to: handler)
            await cluster.set(hueSaturationValues(hue: newHue, saturation: newSaturation))
            return .success
        }
        await cluster.handle(C.moveToHue) { cluster, fields, _ in try await hueSat(cluster, hue: try TLVStruct(fields).uint(0), saturation: nil) }
        await cluster.handle(C.moveToSaturation) { cluster, fields, _ in try await hueSat(cluster, hue: nil, saturation: try TLVStruct(fields).uint(0)) }
        await cluster.handle(C.moveToHueAndSaturation) { cluster, fields, _ in
            let request = try TLVStruct(fields)
            return try await hueSat(cluster, hue: try request.uint(0), saturation: try request.uint(1))
        }
        await cluster.handle(C.moveToColor) { cluster, fields, _ in
            let request = try TLVStruct(fields)
            let x = try request.uint(0, as: UInt16.self), y = try request.uint(1, as: UInt16.self)
            try await deliver(.setColorXY(x: x, y: y), to: handler)
            await cluster.set([A.currentX: .unsigned(UInt64(x)), A.currentY: .unsigned(UInt64(y)), A.colorMode: .unsigned(1),
                               A.enhancedColorMode: .unsigned(1)])
            return .success
        }
        for command in [C.moveHue, C.stepHue, C.moveSaturation, C.stepSaturation, C.moveColor, C.stepColor] {
            await cluster.handle(command) { _, _, _ in .success }
        }
        return cluster
    }

    /// A color temperature and the color mode it puts the light in (ColorMode 2).
    static func colorTemperatureValues(_ mireds: UInt16) -> [AttributeID: TLVValue] {
        typealias A = ColorControlCluster.Attribute
        return [A.colorTemperatureMireds: .unsigned(UInt64(mireds)), A.colorMode: .unsigned(2), A.enhancedColorMode: .unsigned(2)]
    }

    /// A hue and saturation and the color mode they put the light in (ColorMode 0).
    static func hueSaturationValues(hue: UInt8, saturation: UInt8) -> [AttributeID: TLVValue] {
        typealias A = ColorControlCluster.Attribute
        return [A.currentHue: .unsigned(UInt64(min(hue, 254))), A.currentSaturation: .unsigned(UInt64(min(saturation, 254))),
                A.colorMode: .unsigned(0), A.enhancedColorMode: .unsigned(0)]
    }

    // MARK: - Sensors (§2)

    /// The measurement clusters share their layout: MeasuredValue (0), MinMeasuredValue (1), MaxMeasuredValue (2).
    static func measurement(_ definition: ClusterDefinition, value: TLVValue, minimum: TLVValue, maximum: TLVValue) -> AttributeCluster {
        typealias A = TemperatureMeasurementCluster.Attribute
        return AttributeCluster(definition, attributes: [A.measuredValue: value, A.minMeasuredValue: minimum, A.maxMeasuredValue: maximum])
    }

    static func booleanState() -> AttributeCluster {
        AttributeCluster(BooleanStateCluster.definition, attributes: [BooleanStateCluster.Attribute.stateValue: .bool(false)])
    }

    static func occupancySensing() -> AttributeCluster {
        typealias A = OccupancySensingCluster.Attribute
        return AttributeCluster(OccupancySensingCluster.definition, featureMap: OccupancySensingCluster.Feature.passiveInfrared.rawValue,
                                attributes: [A.occupancy: .unsigned(0), A.occupancySensorType: .unsigned(0), A.occupancySensorTypeBitmap: .unsigned(1)])
    }

    // MARK: - Window Covering (§5.3)

    static func windowCovering(_ handler: @escaping DeviceCommandHandler) async -> AttributeCluster {
        typealias A = WindowCoveringCluster.Attribute
        typealias C = WindowCoveringCluster.Command
        let features = WindowCoveringCluster.Feature([.lift, .positionAwareLift])
        let cluster = AttributeCluster(WindowCoveringCluster.definition, featureMap: features.rawValue, attributes: [
            A.type: .unsigned(0), A.configStatus: .unsigned(0b1011), A.operationalStatus: .unsigned(0), A.endProductType: .unsigned(0),
            A.mode: .unsigned(0), A.targetPositionLiftPercent100ths: .unsigned(0), A.currentPositionLiftPercent100ths: .unsigned(0),
        ])
        @Sendable func goTo(_ cluster: AttributeCluster, _ position: UInt64) async throws -> InvokeResult {
            let target = UInt16(min(position, 10_000))
            try await deliver(.setCoveringPosition(percent100ths: target), to: handler)
            await cluster.set(A.targetPositionLiftPercent100ths, .unsigned(UInt64(target)))
            return .success
        }
        await cluster.handle(C.upOrOpen) { cluster, _, _ in try await goTo(cluster, 0) }
        await cluster.handle(C.downOrClose) { cluster, _, _ in try await goTo(cluster, 10_000) }
        await cluster.handle(C.goToLiftPercentage) { cluster, fields, _ in try await goTo(cluster, try TLVStruct(fields).uint(0)) }
        await cluster.handle(C.stopMotion) { cluster, _, _ in
            try await deliver(.stopCovering, to: handler)
            if let current = await cluster.value(A.currentPositionLiftPercent100ths) { await cluster.set(A.targetPositionLiftPercent100ths, current) }
            return .success
        }
        return cluster
    }

    // MARK: - Fan Control (§4.4)

    static func fanControl(_ handler: @escaping DeviceCommandHandler) async -> AttributeCluster {
        typealias A = FanControlCluster.Attribute
        // Fan modes off, low, medium, high (FanModeSequence 0: Off/Low/Med/High) and a percentage.
        let cluster = AttributeCluster(FanControlCluster.definition, attributes: [
            A.fanMode: .unsigned(0), A.fanModeSequence: .unsigned(0), A.percentSetting: .unsigned(0), A.percentCurrent: .unsigned(0),
        ])
        await cluster.onWrite { cluster, attribute, value, _ in
            let percent: UInt8
            switch attribute {
            case A.percentSetting:
                guard let raw = value.uint, raw <= 100 else { throw StatusError(.constraintError) }
                percent = UInt8(raw)
            case A.fanMode:
                // Off 0, Low 1, Medium 2, High 3, On 4 (high), Auto 5 (unsupported), Smart 6 (high).
                guard let mode = value.uint, mode <= 6, mode != 5 else { throw StatusError(.constraintError) }
                percent = [0, 33, 66, 100, 100, 100, 100][Int(mode)]
            default:
                throw StatusError(.unsupportedWrite)
            }
            try await deliver(.setFanSpeed(percent: percent), to: handler)
            // The written attribute is stored by the cluster after this hook; the others follow it.
            var values = fanValues(percent: percent)
            values[attribute] = nil
            await cluster.set(values)
        }
        return cluster
    }

    /// The fan attributes for a speed: the setting, the current speed, and the mode it falls in.
    static func fanValues(percent: UInt8) -> [AttributeID: TLVValue] {
        typealias A = FanControlCluster.Attribute
        let clamped = UInt64(min(percent, 100))
        return [A.percentSetting: .unsigned(clamped), A.percentCurrent: .unsigned(clamped),
                A.fanMode: .unsigned(clamped == 0 ? 0 : clamped <= 33 ? 1 : clamped <= 66 ? 2 : 3)]
    }

    // MARK: - Power Source (§11.7), a battery

    static func battery(endpoint: EndpointNumber) -> AttributeCluster {
        typealias A = PowerSourceCluster.Attribute
        let features = PowerSourceCluster.Feature([.battery, .replaceable])
        return AttributeCluster(PowerSourceCluster.definition, featureMap: features.rawValue, attributes: [
            A.status: .unsigned(1), A.order: .unsigned(0), A.description: .utf8("Battery"), A.batChargeLevel: .unsigned(0),
            A.batReplacementNeeded: .bool(false), A.batReplaceability: .unsigned(0), A.batPercentRemaining: .null,
            A.activeBatFaults: .array([]), A.batReplacementDescription: .utf8(""), A.batQuantity: .unsigned(1),
            A.endpointList: .array([TLVElement(.unsigned(UInt64(endpoint)))]),
        ])
    }
}
