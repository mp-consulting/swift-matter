import Foundation

/// The clusters of alarms, air quality, valves and metering (Application Clusters §2.9, §2.11-2.13, §4.6).
extension DeviceClusters {
    // MARK: - Air Quality (§2.9)

    static func airQuality() -> AttributeCluster {
        typealias F = AirQualityCluster.Feature
        return AttributeCluster(AirQualityCluster.definition, featureMap: F([.fair, .moderate, .veryPoor, .extremelyPoor]).rawValue,
                                attributes: [AirQualityCluster.Attribute.airQuality: .unsigned(AirQualityCluster.AirQualityEnum.unknown)])
    }

    // MARK: - Smoke CO Alarm (§2.11)

    static func smokeCOAlarm(smoke: Bool, carbonMonoxide: Bool) -> AttributeCluster {
        typealias A = SmokeCoAlarmCluster.Attribute
        var features: SmokeCoAlarmCluster.Feature = []
        var attributes: [AttributeID: TLVValue] = [
            A.expressedState: .unsigned(SmokeCoAlarmCluster.ExpressedStateEnum.normal),
            A.batteryAlert: .unsigned(SmokeCoAlarmCluster.AlarmStateEnum.normal), A.testInProgress: .bool(false),
            A.hardwareFaultAlert: .bool(false), A.endOfServiceAlert: .unsigned(SmokeCoAlarmCluster.EndOfServiceEnum.normal),
        ]
        if smoke {
            features.insert(.smokeAlarm)
            attributes[A.smokeState] = .unsigned(SmokeCoAlarmCluster.AlarmStateEnum.normal)
        }
        if carbonMonoxide {
            features.insert(.coAlarm)
            attributes[A.coState] = .unsigned(SmokeCoAlarmCluster.AlarmStateEnum.normal)
        }
        return AttributeCluster(SmokeCoAlarmCluster.definition, featureMap: features.rawValue, attributes: attributes)
    }

    /// Sets the smoke or CO state, the expressed state that follows (smoke first, then CO), and the events of the change:
    /// SmokeAlarm or COAlarm when it sounds, AllClear when nothing does any more (§2.11.8).
    static func setAlarm(_ cluster: AttributeCluster, smoke: Bool, detected: Bool) async {
        typealias A = SmokeCoAlarmCluster.Attribute
        typealias State = SmokeCoAlarmCluster.AlarmStateEnum
        let attribute = smoke ? A.smokeState : A.coState
        let value = TLVValue.unsigned(detected ? State.critical : State.normal)
        guard let current = await cluster.value(attribute), current != value else { return }
        await cluster.set(attribute, value)
        let smokeOn = await cluster.value(A.smokeState) == .unsigned(State.critical)
        let coOn = await cluster.value(A.coState) == .unsigned(State.critical)
        typealias Expressed = SmokeCoAlarmCluster.ExpressedStateEnum
        await cluster.set(A.expressedState, .unsigned(smokeOn ? Expressed.smokeAlarm : coOn ? Expressed.coAlarm : Expressed.normal))
        if detected {
            await cluster.emit(smoke ? SmokeCoAlarmCluster.Event.smokeAlarm : SmokeCoAlarmCluster.Event.coAlarm,
                               data: .structure([.field(0, .unsigned(State.critical))]))
        } else if !smokeOn, !coOn {
            await cluster.emit(SmokeCoAlarmCluster.Event.allClear, data: .structure([]))
        }
    }

    // MARK: - Valve Configuration and Control (§4.6)

    static func valve(_ handler: @escaping DeviceCommandHandler) async -> AttributeCluster {
        typealias A = ValveConfigurationAndControlCluster.Attribute
        typealias C = ValveConfigurationAndControlCluster.Command
        typealias State = ValveConfigurationAndControlCluster.ValveStateEnum
        let cluster = AttributeCluster(ValveConfigurationAndControlCluster.definition, attributes: [
            A.openDuration: .null, A.defaultOpenDuration: .null, A.remainingDuration: .null,
            A.currentState: .unsigned(State.closed), A.targetState: .null,
        ])
        await cluster.onWrite { _, attribute, value, _ in
            // DefaultOpenDuration is stored as written: null, or at least a second (§4.6.7.2).
            guard attribute == A.defaultOpenDuration, value == .null || (value.uint ?? 0) >= 1 else { throw StatusError(.constraintError) }
        }
        @Sendable func move(_ cluster: AttributeCluster, open: Bool) async throws -> InvokeResult {
            try await deliver(.setValveOpen(open), to: handler)
            // The target until the device reports the valve there (`DeviceState.valveOpen`).
            await cluster.set(A.targetState, .unsigned(open ? State.open : State.closed))
            return .success
        }
        await cluster.handle(C.open) { cluster, fields, _ in
            if let duration = fields[0], duration != .null, (duration.uint ?? 0) < 1 { throw StatusError(.constraintError) }
            return try await move(cluster, open: true)
        }
        await cluster.handle(C.close) { cluster, _, _ in try await move(cluster, open: false) }
        return cluster
    }

    /// The valve reached a state: CurrentState, TargetState cleared, and ValveStateChanged (§4.6.9.1).
    static func setValve(_ cluster: AttributeCluster, open: Bool) async {
        typealias A = ValveConfigurationAndControlCluster.Attribute
        typealias State = ValveConfigurationAndControlCluster.ValveStateEnum
        let state = TLVValue.unsigned(open ? State.open : State.closed)
        await cluster.set([A.targetState: .null])
        guard await cluster.value(A.currentState) != state else { return }
        await cluster.set(A.currentState, state)
        await cluster.emit(ValveConfigurationAndControlCluster.Event.valveStateChanged, data: .structure([.field(0, state)]))
    }

    // MARK: - Metering (§2.12, §2.13, Power Topology)

    /// The power ranges a bridged meter reports in, mW: up to 32 kW.
    static let powerRange: ClosedRange<Int64> = 0...32_000_000

    /// MeasurementAccuracyStruct for one measurement type: measured, within `fixed` of the true value.
    static func accuracy(_ type: UInt64, range: ClosedRange<Int64>, fixed: UInt64) -> TLVValue {
        .structure([
            .field(0, .unsigned(type)), .field(1, .bool(true)), .field(2, .signed(range.lowerBound)), .field(3, .signed(range.upperBound)),
            .field(4, .array([TLVElement(.structure([
                .field(0, .signed(range.lowerBound)), .field(1, .signed(range.upperBound)), .field(5, .unsigned(fixed)),
            ]))])),
        ])
    }

    /// Power Topology (node: it measures itself), Electrical Power Measurement with ActivePower, and Electrical Energy
    /// Measurement with the cumulative energy imported: what an Electrical Sensor carries (Device Library §2.5).
    static func metering() -> [AttributeCluster] {
        typealias Power = ElectricalPowerMeasurementCluster
        typealias Energy = ElectricalEnergyMeasurementCluster
        let topology = AttributeCluster(PowerTopologyCluster.definition, featureMap: PowerTopologyCluster.Feature.nodeTopology.rawValue,
                                        attributes: [:])
        let power = AttributeCluster(Power.definition, attributes: [
            Power.Attribute.powerMode: .unsigned(Power.PowerModeEnum.ac), Power.Attribute.numberOfMeasurementTypes: .unsigned(1),
            Power.Attribute.accuracy: .array([TLVElement(accuracy(Power.MeasurementTypeEnum.activePower, range: powerRange, fixed: 1000))]),
            Power.Attribute.activePower: .null,
        ])
        let energy = AttributeCluster(Energy.definition, featureMap: Energy.Feature([.importedEnergy, .cumulativeEnergy]).rawValue, attributes: [
            Energy.Attribute.accuracy: accuracy(Energy.MeasurementTypeEnum.electricalEnergy, range: 0...Int64.max / 2, fixed: 1000),
            Energy.Attribute.cumulativeEnergyImported: .null,
        ])
        return [topology, power, energy]
    }
}
