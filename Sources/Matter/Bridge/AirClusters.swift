/// What an air quality sensor measures besides its overall quality, each in a concentration measurement cluster
/// (Application Clusters §2.10) with a numeric value in its usual unit.
public enum Concentration: Hashable, Sendable, CaseIterable {
    /// Carbon dioxide, in ppm.
    case carbonDioxide
    /// Particles under 2.5 µm, in µg/m³.
    case pm25
    /// Particles under 10 µm, in µg/m³.
    case pm10
    /// Total volatile organic compounds, in µg/m³.
    case totalVolatileOrganicCompounds

    var clusterID: ClusterID { definition.id }

    var definition: ClusterDefinition {
        switch self {
        case .carbonDioxide: CarbonDioxideConcentrationMeasurementCluster.definition
        case .pm25: Pm25ConcentrationMeasurementCluster.definition
        case .pm10: Pm10ConcentrationMeasurementCluster.definition
        case .totalVolatileOrganicCompounds: TotalVolatileOrganicCompoundsConcentrationMeasurementCluster.definition
        }
    }

    /// The concentration clusters share their attributes and enums: the carbon dioxide one's names stand for all.
    var unit: UInt64 {
        typealias Unit = CarbonDioxideConcentrationMeasurementCluster.MeasurementUnitEnum
        return self == .carbonDioxide ? Unit.ppm : Unit.ugm3
    }
}

/// Concentrations (§2.10) and an air purifier's filter (Resource Monitoring, §2.8).
extension DeviceClusters {
    static func concentration(_ kind: Concentration) -> AttributeCluster {
        typealias A = CarbonDioxideConcentrationMeasurementCluster.Attribute
        return AttributeCluster(kind.definition, featureMap: CarbonDioxideConcentrationMeasurementCluster.Feature.numericMeasurement.rawValue, attributes: [
            A.measuredValue: .null, A.minMeasuredValue: .null, A.maxMeasuredValue: .null, A.measurementUnit: .unsigned(kind.unit),
            A.measurementMedium: .unsigned(CarbonDioxideConcentrationMeasurementCluster.MeasurementMediumEnum.air),
        ])
    }

    /// A HEPA filter's condition, counting down from 100 % as it wears; ResetCondition (a new filter) goes to the handler.
    static func hepaFilter(_ handler: @escaping DeviceCommandHandler) async -> AttributeCluster {
        typealias A = HepaFilterMonitoringCluster.Attribute
        let features = HepaFilterMonitoringCluster.Feature([.condition, .warning])
        let cluster = AttributeCluster(HepaFilterMonitoringCluster.definition, featureMap: features.rawValue, attributes: [
            A.condition: .unsigned(100), A.degradationDirection: .unsigned(HepaFilterMonitoringCluster.DegradationDirectionEnum.down),
            A.changeIndication: .unsigned(HepaFilterMonitoringCluster.ChangeIndicationEnum.ok), A.inPlaceIndicator: .bool(true),
        ])
        await cluster.handle(HepaFilterMonitoringCluster.Command.resetCondition) { cluster, _, _ in
            try await deliver(.resetFilter, to: handler)
            await cluster.set(filterValues(percentLeft: 100, needsChange: false))
            return .success
        }
        return cluster
    }

    /// The filter's attributes: critical when it needs changing, a warning with less than 10 % left.
    static func filterValues(percentLeft: UInt8?, needsChange: Bool) -> [AttributeID: TLVValue] {
        typealias A = HepaFilterMonitoringCluster.Attribute
        typealias Change = HepaFilterMonitoringCluster.ChangeIndicationEnum
        let left = percentLeft.map { min($0, 100) }
        var values: [AttributeID: TLVValue] = [A.changeIndication: .unsigned(needsChange ? Change.critical : (left ?? 100) < 10 ? Change.warning : Change.ok)]
        if let left { values[A.condition] = .unsigned(UInt64(left)) }
        return values
    }
}
