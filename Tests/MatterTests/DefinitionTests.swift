import Testing
@testable import Matter

/// The generated definitions of clusters derived from a base (Mode Base, Operational State, the concentration
/// measurements) carry the base's elements.
struct DefinitionTests {
    @Test func derivedClustersInheritTheirBase() throws {
        let runMode = RvcRunModeCluster.definition
        #expect(runMode.attribute(RvcRunModeCluster.Attribute.supportedModes)?.flags.contains(.list) == true)
        #expect(runMode.command(RvcRunModeCluster.Command.changeToMode)?.response == RvcRunModeCluster.Command.changeToModeResponse)
        let operational = RvcOperationalStateCluster.definition
        #expect(operational.attribute(RvcOperationalStateCluster.Attribute.operationalState) != nil)
        #expect(operational.command(RvcOperationalStateCluster.Command.goHome)?.response == RvcOperationalStateCluster.Command.operationalCommandResponse)
        #expect(operational.event(RvcOperationalStateCluster.Event.operationalError) != nil)
        // Every attribute of every standard cluster has a type, but the placeholders the spec reserves without one.
        let reserved: Set = ["GeneralDiagnostics.DoNotUse", "ScenesManagement.DoNotUse", "DoorLock.SecurityLevel"]
        let untyped = ClusterDefinition.standard.values.flatMap { cluster in
            cluster.attributes.filter { $0.type.isEmpty }.map { "\(cluster.name).\($0.name)" }
        }
        #expect(Set(untyped) == reserved)
    }
}
