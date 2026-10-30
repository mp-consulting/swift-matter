import Foundation
import Crypto
import Testing
@testable import Matter

/// Core §4.3.2.2, §4.14.2.4 and §4.17.2's examples.
struct FabricVectorTests {
    let rootKey = hex("044a9f42b1ca4840d37292bbc7f6a7e11e22200c976fc900dbc98a7a383a641cb8254a2e56d4e295a847943b4e3897c4a773e930277b4d9fbede8a052686bfacfa")

    @Test func derivesTheCompressedFabricID() {
        #expect(Fabric.compressedFabricID(rootPublicKey: rootKey, fabricID: 0x2906_C908_D115_D362) == hex("87e1b004e235a130"))
    }

    @Test func derivesOperationalGroupKeys() {
        #expect(Fabric.operationalGroupKey(epochKey: hex("235bf7e62823d358dca4ba50b1535f4b"), compressedFabricID: hex("87e1b004e235a130"))
            == hex("a6f5306baf6d050af23ba4bd6b9dd960"))
        #expect(Fabric.operationalGroupKey(epochKey: hex("4a71cdd7b2a3ca9024f96f3c96a19dee"), compressedFabricID: hex("87e1b004e235a130"))
            == hex("9bc61cd9c62a2df6d64dfcaa9dc472d4"))
    }

    @Test func derivesTheDestinationIdentifier() {
        let destination = Fabric.destinationID(
            initiatorRandom: hex("7e171231568dfa17206b3accf8faec2f4d21b580113196f47c7c4deb810a73dc"), rootPublicKey: rootKey,
            fabricID: 0x2906_C908_D115_D362, nodeID: 0xCD55_44AA_7B13_EF14, ipk: hex("9bc61cd9c62a2df6d64dfcaa9dc472d4"))
        #expect(destination == hex("dc35dd5fc9134cc5544538c9c3fc4297c1ec3370c839136a80e10796451d4c53"))
    }
}

/// A node and a commissioner on a memory network.
struct CommissioningFixture {
    let network = MemoryNetwork()
    let storage = MemoryStorage()
    let node: MatterNode
    let commissioner: Commissioner
    static let passcode: UInt32 = 20202021

    init(failSafeScale: Double = 0.01) async throws {
        var configuration = NodeConfiguration(passcode: Self.passcode, discriminator: 3840)
        configuration.reliability = .fast
        node = try await MatterNode(configuration: configuration, storage: storage, transport: await network.transport(named: "node"))
        try await node.start()
        let layer = MessageLayer(transport: await network.transport(named: "commissioner"), reliability: .fast)
        commissioner = try Commissioner(layer: layer, fabricID: 0xFAB, nodeID: 0x1122)
        try await commissioner.start()
    }
}

struct CommissioningTests {
    @Test func commissionsAndOperatesOverCASE() async throws {
        let fixture = try await CommissioningFixture()
        #expect(await fixture.node.commissioning.windowStatus == .basic)
        let session = try await fixture.commissioner.commission(.memory("node"), passcode: CommissioningFixture.passcode, nodeID: 0x42)
        #expect(session.kind == .case)

        // The node has the fabric, the window is closed, the PASE session gone.
        let fabrics = await fixture.node.fabrics.all
        #expect(fabrics.map(\.nodeID) == [0x42])
        #expect(fabrics.first?.fabricID == 0xFAB)
        #expect(await fixture.node.commissioning.windowStatus == .closed)
        #expect(await !fixture.node.commissioning.isFailSafeArmed)
        #expect(await fixture.node.layer.sessions.map(\.kind) == [.case])

        // The commissioner reads with its Administer entry; the fabric is listed.
        let label = try await fixture.commissioner.client.read(endpoint: 0, cluster: BasicInformationCluster.id,
                                                               attribute: BasicInformationCluster.Attribute.vendorName, session: session.localSessionID)
        #expect(label == .utf8("swift-matter"))
        let acl = try await fixture.commissioner.client.read(endpoint: 0, cluster: AccessControlCluster.id,
                                                             attribute: AccessControlCluster.Attribute.acl, session: session.localSessionID)
        #expect(acl.elements?.count == 1)
        let current = try await fixture.commissioner.client.read(endpoint: 0, cluster: OperationalCredentialsCluster.id,
                                                                 attribute: OperationalCredentialsCluster.Attribute.currentFabricIndex,
                                                                 session: session.localSessionID)
        #expect(current == .unsigned(1))

        // A second CASE session works from the stored fabric.
        let again = try await CASE.establish(with: .memory("node"), peerNodeID: 0x42, identity: await fixture.commissioner.identity,
                                             layer: fixture.commissioner.layer)
        #expect(again.fabricIndex == nil)
        #expect(await fixture.node.layer.sessions.count == 2)
    }

    @Test func enforcesTheACLOverCASE() async throws {
        let fixture = try await CommissioningFixture()
        let session = try await fixture.commissioner.commission(.memory("node"), passcode: CommissioningFixture.passcode, nodeID: 0x42)
        // Replace the admin entry with View only: writes and admin reads are refused afterwards.
        let viewOnly = AccessControlEntry(fabricIndex: 1, privilege: .view, authMode: .case, subjects: [0x1122])
        let statuses = try await fixture.commissioner.client.write([
            (AttributePath(endpoint: 0, cluster: AccessControlCluster.id, attribute: AccessControlCluster.Attribute.acl),
             .array([TLVElement(viewOnly.tlv)])),
        ], session: session.localSessionID)
        #expect(statuses.map(\.1.status) == [.success])
        await #expect(throws: StatusError(.unsupportedAccess)) {
            try await fixture.commissioner.client.read(endpoint: 0, cluster: AccessControlCluster.id,
                                                       attribute: AccessControlCluster.Attribute.acl, session: session.localSessionID)
        }
        let name = try await fixture.commissioner.client.read(endpoint: 0, cluster: BasicInformationCluster.id,
                                                              attribute: BasicInformationCluster.Attribute.productName, session: session.localSessionID)
        #expect(name == .utf8("Matter Bridge"))
    }

    @Test func rollsBackWhenTheFailSafeExpires() async throws {
        let fixture = try await CommissioningFixture()
        let pase = try await PASE.establish(with: .memory("node"), passcode: CommissioningFixture.passcode, layer: fixture.commissioner.layer)
        let result = try await fixture.commissioner.client.invoke(
            CommandPath(endpoint: 0, cluster: GeneralCommissioningCluster.id, command: GeneralCommissioningCluster.Command.armFailSafe),
            fields: .structure([.field(0, .unsigned(1)), .field(1, .unsigned(7))]), session: pase.localSessionID)
        guard case .response(_, let fields) = result else { Issue.record("Expected ArmFailSafeResponse"); return }
        #expect(fields[0] == .unsigned(0))
        #expect(await fixture.node.commissioning.breadcrumb == 7)
        // One second later the fail-safe expires: the breadcrumb resets and the PASE session stays (the window is open).
        try await eventually(timeout: .seconds(5)) { await !fixture.node.commissioning.isFailSafeArmed }
        #expect(await fixture.node.commissioning.breadcrumb == 0)
        #expect(await fixture.node.fabrics.count == 0)
    }

    @Test func refusesCommissioningWithoutAWindow() async throws {
        let fixture = try await CommissioningFixture()
        _ = try await fixture.commissioner.commission(.memory("node"), passcode: CommissioningFixture.passcode, nodeID: 0x42)
        await #expect(throws: PASEError.rejected(.invalidParameter)) {
            try await PASE.establish(with: .memory("node"), passcode: CommissioningFixture.passcode, layer: fixture.commissioner.layer)
        }
    }

    @Test func opensAnEnhancedWindowForASecondAdmin() async throws {
        let fixture = try await CommissioningFixture()
        let session = try await fixture.commissioner.commission(.memory("node"), passcode: CommissioningFixture.passcode, nodeID: 0x42)

        let salt = MatterCrypto.random(16)
        let verifier = try SPAKE2Plus.verifier(passcode: 11223344, salt: salt, iterations: 1000)
        let admin = AdministratorCommissioningCluster.self
        let opened = try await fixture.commissioner.client.invoke(
            CommandPath(endpoint: 0, cluster: admin.id, command: admin.Command.openCommissioningWindow),
            fields: .structure([.field(0, .unsigned(180)), .field(1, .bytes(verifier.serialized)), .field(2, .unsigned(1234)),
                                .field(3, .unsigned(1000)), .field(4, .bytes(salt))]),
            timed: .seconds(5), session: session.localSessionID)
        guard case .status(let status) = opened else { Issue.record("Expected a status"); return }
        #expect(status.status == .success)
        #expect(await fixture.node.commissioning.windowStatus == .enhanced)

        let layer = MessageLayer(transport: await fixture.network.transport(named: "second"), reliability: .fast)
        let second = try Commissioner(layer: layer, fabricID: 0xBEEF, nodeID: 0x3344)
        try await second.start()
        _ = try await second.commission(.memory("node"), passcode: 11223344, nodeID: 0x77)
        #expect(await fixture.node.fabrics.all.map(\.fabricID) == [0xFAB, 0xBEEF])

        // Each fabric sees only its own ACL entries.
        let acl = try await fixture.commissioner.client.read(endpoint: 0, cluster: AccessControlCluster.id,
                                                             attribute: AccessControlCluster.Attribute.acl, session: session.localSessionID)
        #expect(acl.elements?.count == 1)
    }

    @Test func persistsAcrossRestarts() async throws {
        let fixture = try await CommissioningFixture()
        _ = try await fixture.commissioner.commission(.memory("node"), passcode: CommissioningFixture.passcode, nodeID: 0x42)
        await fixture.node.stop()

        var configuration = NodeConfiguration(passcode: CommissioningFixture.passcode, discriminator: 3840)
        configuration.reliability = .fast
        let restarted = try await MatterNode(configuration: configuration, storage: fixture.storage,
                                             transport: await fixture.network.transport(named: "node"))
        try await restarted.start()
        #expect(await restarted.fabrics.count == 1)
        #expect(await restarted.commissioning.windowStatus == .closed)
        let session = try await CASE.establish(with: .memory("node"), peerNodeID: 0x42, identity: await fixture.commissioner.identity,
                                               layer: fixture.commissioner.layer)
        let value = try await fixture.commissioner.client.read(endpoint: 0, cluster: BasicInformationCluster.id,
                                                               attribute: BasicInformationCluster.Attribute.vendorId, session: session.localSessionID)
        #expect(value == .unsigned(0xFFF1))
    }
}

struct FileStorageTests {
    @Test func storesReplacesAndRemovesValues() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("swift-matter-\(UInt64.random(in: 0...UInt64.max))")
        defer { try? FileManager.default.removeItem(at: directory) }
        let storage = try FileStorage(directory: directory)
        try await storage.setValue([1, 2, 3], for: "fabrics")
        #expect(await storage.value(for: "fabrics") == [1, 2, 3])
        try await storage.setValue([4], for: "fabrics")
        #expect(await storage.value(for: "fabrics") == [4])
        // Keys cannot leave the directory.
        try await storage.setValue([5], for: "../escape")
        #expect(!FileManager.default.fileExists(atPath: directory.deletingLastPathComponent().appendingPathComponent("escape").path))
        #expect(await storage.value(for: "../escape") == [5])
        try await storage.setValue(nil, for: "fabrics")
        #expect(await storage.value(for: "fabrics") == nil)
    }
}

struct ResumptionTests {
    @Test func resumesASessionAndFallsBackWhenTheTicketIsUnknown() async throws {
        let fixture = try await CommissioningFixture()
        _ = try await fixture.commissioner.commission(.memory("node"), passcode: CommissioningFixture.passcode, nodeID: 0x42)
        let identity = await fixture.commissioner.identity
        let layer = fixture.commissioner.layer

        let (first, ticket) = try await CASE.establishResumable(with: .memory("node"), peerNodeID: 0x42, identity: identity, layer: layer)
        let (resumed, next) = try await CASE.establishResumable(with: .memory("node"), peerNodeID: 0x42, identity: identity, layer: layer,
                                                                ticket: ticket)
        #expect(next.id != ticket.id)
        #expect(resumed.localSessionID != first.localSessionID)
        // The resumed session carries reads like any other.
        let value = try await fixture.commissioner.client.read(endpoint: 0, cluster: BasicInformationCluster.id,
                                                               attribute: BasicInformationCluster.Attribute.vendorId, session: resumed.localSessionID)
        #expect(value == .unsigned(0xFFF1))

        // A used ticket is not accepted again: the responder answers with a full Sigma2 instead.
        let (fallback, fresh) = try await CASE.establishResumable(with: .memory("node"), peerNodeID: 0x42, identity: identity, layer: layer,
                                                                  ticket: ticket)
        #expect(fresh.id != next.id)
        _ = try await fixture.commissioner.client.read(endpoint: 0, cluster: BasicInformationCluster.id,
                                                       attribute: BasicInformationCluster.Attribute.vendorId, session: fallback.localSessionID)
    }
}
