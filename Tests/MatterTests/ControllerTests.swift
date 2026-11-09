import Foundation
import Testing
@testable import Matter

/// The controller side: what a commissioner needs to take in a production device and keep reaching it.
struct ControllerTests {
    @Test func takesADeviceWhoseAttestationChainItCannotVerifyOnlyWhenAskedTo() async throws {
        // Without the device's PAA, verification refuses it; checking the signatures alone takes it, and says whose it is.
        let strict = try await CommissioningFixture(trustStore: .registry)
        await #expect(throws: CommissioningError.attestationFailed(.untrustedRoot)) {
            try await strict.commissioner.commission(.memory("node"), passcode: CommissioningFixture.passcode, nodeID: 0x42)
        }
        let lenient = try await CommissioningFixture(trustStore: .registry, attestationPolicy: .signaturesOnly)
        let commissioned = try await lenient.commissioner.commissionNode(.memory("node"), passcode: CommissioningFixture.passcode, nodeID: 0x42)
        #expect(commissioned.session.kind == .case)
        #expect(commissioned.vendorID == 0xFFF1)
    }

    /// A commissioning stopped by attestation expires the fail-safe, so the same window takes the device straight away
    /// once the person agreed (Core §5.5; §11.10.7.2), rather than answering BusyWithOtherAdmin for 60 seconds.
    @Test func aRefusedAttestationLeavesTheWindowFreeForAnotherTry() async throws {
        let fixture = try await CommissioningFixture(trustStore: .registry)
        await #expect(throws: CommissioningError.attestationFailed(.untrustedRoot)) {
            try await fixture.commissioner.commission(.memory("node"), passcode: CommissioningFixture.passcode, nodeID: 0x42)
        }
        let layer = MessageLayer(transport: await fixture.network.transport(named: "again"), reliability: .fast)
        let again = try Commissioner(layer: layer, fabricID: 0xFAB, nodeID: 0x1122, trustStore: .registry, attestationPolicy: .signaturesOnly)
        try await again.start()
        let session = try await again.commission(.memory("node"), passcode: CommissioningFixture.passcode, nodeID: 0x42)
        #expect(session.kind == .case)
        #expect(await fixture.node.fabrics.count == 1)
    }

    /// A commissioner SHALL set its fabric's label during commissioning (Core §5.5, step 13): the next free one.
    @Test func setsItsFabricLabelWhileCommissioning() async throws {
        let fixture = try await CommissioningFixture()
        _ = try await fixture.commissioner.commissionNode(.memory("node"), passcode: CommissioningFixture.passcode, nodeID: 0x42, fabricLabel: "Homeswift")
        let labels = await fixture.node.fabrics.all.map(\.label)
        #expect(labels == ["Homeswift"])
    }

    @Test func aRestoredCommissionerReachesItsNodesAgain() async throws {
        let fixture = try await CommissioningFixture()
        _ = try await fixture.commissioner.commission(.memory("node"), passcode: CommissioningFixture.passcode, nodeID: 0x42)
        let snapshot = try JSONDecoder().decode(Commissioner.Snapshot.self, from: try JSONEncoder().encode(await fixture.commissioner.snapshot))

        let layer = MessageLayer(transport: await fixture.network.transport(named: "restored"), reliability: .fast)
        let restored = try Commissioner(layer: layer, snapshot: snapshot, trustStore: .test)
        try await restored.start()
        #expect(restored.compressedFabricID == fixture.commissioner.compressedFabricID)
        let session = try await CASE.establish(with: .memory("node"), peerNodeID: 0x42, identity: await restored.identity, layer: layer)
        let vendor = try await restored.client.read(endpoint: 0, cluster: BasicInformationCluster.id,
                                                    attribute: BasicInformationCluster.Attribute.vendorName, session: session.localSessionID)
        #expect(vendor == .utf8("swift-matter"))
        // Its node's operational name is the one the node advertises (Core §4.3.2.1).
        let fabric = try #require(await fixture.node.fabrics.all.first)
        #expect(OperationalInstanceName.make(compressedFabricID: restored.compressedFabricID, nodeID: 0x42)
                == OperationalInstanceName.make(compressedFabricID: fabric.compressedFabricID, nodeID: fabric.nodeID))
        // Removing the fabric leaves the node without this controller.
        try await restored.removeFabric(session: session.localSessionID)
        #expect(await fixture.node.fabrics.count == 0)
    }

    @Test func issuesCertificatesThatStartInThePast() async throws {
        let fixture = try await CommissioningFixture()
        let root = await fixture.commissioner.rootCertificate
        #expect(root.notBefore > 0)
        #expect(root.isValid(at: Date()))
        #expect(!root.isValid(at: Date(timeIntervalSince1970: MatterCertificate.epochOffset)))
        #expect(await fixture.commissioner.operationalCertificate.isValid(at: Date()))
    }

    @Test func subscribingAgainFromAnEventNumberSkipsWhatWasDelivered() async throws {
        let fixture = try await CommissioningFixture()
        let bridge = try await MatterBridge(node: fixture.node)
        let session = try await fixture.commissioner.commission(.memory("node"), passcode: CommissioningFixture.passcode, nodeID: 0x42).localSessionID
        let button = try await bridge.add(BridgedDeviceInfo(id: "button", name: "Button"), kind: .genericSwitch)
        await button.press(.single)
        let switchEvents = [EventPath(endpoint: button.endpoint, cluster: SwitchCluster.id)]

        let first = try await fixture.commissioner.client.subscribe([], events: switchEvents, minInterval: 0, maxInterval: 60, session: session)
        var reports = first.reports.makeAsyncIterator()
        let primed = try #require(await reports.next()).events.compactMap(\.record)
        #expect(primed.map(\.event) == [SwitchCluster.Event.initialPress, SwitchCluster.Event.shortRelease, SwitchCluster.Event.multiPressComplete])
        let last = try #require(primed.last?.number)

        await button.press(.single)
        let second = try await fixture.commissioner.client.subscribe([], events: switchEvents, eventMin: last + 1, minInterval: 0,
                                                                     maxInterval: 60, session: session)
        var again = second.reports.makeAsyncIterator()
        let replayed = try #require(await again.next()).events.compactMap(\.record)
        #expect(replayed.count == 3)
        #expect(replayed.allSatisfy { $0.number > last })
    }

    @Test func readsACommissionableNodesRecord() throws {
        let txt = ["D": "1303", "CM": "2", "VP": "4476+32768", "DT": "15", "SII": "9500", "SAI": "2100", "SAT": "5000", "T": "1"]
        let node = try #require(CommissionableNodeInfo(txt: txt))
        #expect(node.discriminator == 1303 && node.shortDiscriminator == 5)
        #expect(node.commissioningMode == 2 && node.isCommissionable)
        #expect(node.vendorID == 4476 && node.productID == 32768 && node.deviceType == 15)
        #expect(node.parameters.idleInterval == .milliseconds(9500) && node.parameters.activeInterval == .milliseconds(2100))
        #expect(node.parameters.activeThreshold == .milliseconds(5000))
        // T's bit 0 is deprecated and ignored.
        #expect(node.parameters.supportedTransports == [])
        #expect(CommissionableNodeInfo(txt: ["CM": "1"]) == nil)
        #expect(CommissionableNodeInfo(txt: ["D": "4096"]) == nil)
        #expect(CommissionableNodeInfo(txt: ["D": "3840", "VP": "65521"])?.productID == nil)
        // CM 3 is Joint Fabric commissioning, which this commissioner does not run.
        #expect(CommissionableNodeInfo(txt: ["D": "3840", "CM": "3"])?.isCommissionable == false)
        // A value beyond its bound is invalid: the default applies (Core §4.3.4).
        #expect(SessionParameters(txt: ["SII": "3600001", "SAT": "70000"]) == .default)
    }

    @Test func matchesAPairingCodeToTheNodeItIsFor() throws {
        // The demo's manual code and QR code: passcode 20202021, discriminator 3840.
        let manual = try PairingCode("3497-011-2332")
        #expect(manual.passcode == 20202021 && manual.discriminator == .short(15))
        let qr = try PairingCode("MT:-24J0AFN00KA0648G00")
        #expect(qr.passcode == 20202021 && qr.discriminator == .long(3840))
        let node = try #require(CommissionableNodeInfo(txt: ["D": "3840", "CM": "1", "VP": "65521+32769"]))
        #expect(!CommissionableNodeInfo(txt: ["D": "3840", "CM": "1", "VP": "65521+32768"])!.matches(qr))
        #expect(node.matches(manual))
        #expect(node.matches(qr))
        let other = try #require(CommissionableNodeInfo(txt: ["D": "1303", "CM": "2"]))
        #expect(!other.matches(manual) && !other.matches(qr))
        #expect(throws: SetupPayloadError.self) { try PairingCode("34970112333") }
    }

    /// Codes connectedhomeip made (SetupPayload.GenerateManualPairingCode and GenerateQrCode, home-assistant-chip-core
    /// 2025.7.0): passcode, vendor, product, discriminator, commissioning flow; then the manual code and the QR code.
    @Test func readsPairingCodesAsConnectedhomeipWritesThem() throws {
        let vectors: [(UInt32, UInt16, UInt16, UInt16, Int, String, String)] = [
            (20202021, 0xFFF1, 0x8001, 3840, 0, "34970112332", "MT:-24J0AFN00KA0648G00"),
            (12345679, 0x117C, 0x8000, 1303, 0, "12491107533", "MT:CUO00SO5278VG46Y900"),
            (69414998, 0x100B, 0x0105, 0x0ABC, 2, "645142423604107002614", "MT:Y5EA16VK14FQH13SH10"),
            (1, 0x1349, 1, 0, 0, "00000100007", "MT:GGAA0CQM00ID0000000"),
            (99999998, 0xFFF4, 0xFFFF, 4095, 2, "757598610365524655354", "MT:6JS18H79271DQ36B420"),
        ]
        for (passcode, vendor, product, discriminator, flow, manualCode, qrCode) in vectors {
            let manual = try PairingCode(manualCode)
            #expect(manual.passcode == passcode && manual.discriminator == .short(UInt8(discriminator >> 8)))
            // The 21-digit form, for a custom commissioning flow, carries the vendor and product (Core §5.1.4.1).
            #expect(manual.vendorID == (flow == 0 ? nil : vendor) && manual.productID == (flow == 0 ? nil : product))
            let qr = try PairingCode(qrCode)
            #expect(qr.passcode == passcode && qr.discriminator == .long(discriminator))
            #expect(qr.vendorID == vendor && qr.productID == product)
        }
    }

    @Test func readsOperationalInstanceNames() throws {
        let fabric: [UInt8] = [0x29, 0x06, 0xC9, 0x08, 0xD1, 0x15, 0xD3, 0x62]
        let name = OperationalInstanceName.make(compressedFabricID: fabric, nodeID: 0x8FC7_7724_01CD_0696)
        #expect(name == "2906C908D115D362-8FC7772401CD0696")
        let parsed = try #require(OperationalInstanceName.parse(name))
        #expect(parsed.compressedFabricID == fabric && parsed.nodeID == 0x8FC7_7724_01CD_0696)
        #expect(OperationalInstanceName.parse("2906C908D115D362") == nil)
        #expect(OperationalInstanceName.parse("2906C908D115D362-XYZ") == nil)
    }

    @Test func readsListsSentAsAppendsAndConvertsLevels() throws {
        let path = AttributePath(endpoint: 1, cluster: DescriptorCluster.id, attribute: DescriptorCluster.Attribute.serverList)
        var append = path
        append.listIndex = .append
        let reports: [AttributeReport] = [.data(path: path, dataVersion: 1, value: .array([])),
                                          .data(path: append, dataVersion: 1, value: .unsigned(6)), .data(path: append, dataVersion: 1, value: .unsigned(8))]
        #expect(reports.values[ConcreteAttribute(1, DescriptorCluster.id, DescriptorCluster.Attribute.serverList)]?.elements?.map(\.value.uint) == [6, 8])
        #expect(LevelControlCluster.level(percent: 50) == 127 && LevelControlCluster.level(percent: 0) == 1)
        #expect(LevelControlCluster.percent(level: 254) == 100 && LevelControlCluster.percent(level: 1) == 1)
        let parameters = SessionParameters(idleInterval: .milliseconds(9500), activeInterval: .milliseconds(2100), activeThreshold: .milliseconds(5000))
        #expect(try JSONDecoder().decode(SessionParameters.self, from: try JSONEncoder().encode(parameters)) == parameters)
    }

    @Test func retransmitsFromTheIdleIntervalOnceThePeerWentQuiet() {
        // Core §4.12.8: active within the active threshold of the last message, idle after it or before any.
        let parameters = SessionParameters(idleInterval: .milliseconds(9500), activeInterval: .milliseconds(2100),
                                           activeThreshold: .milliseconds(5000))
        let now = ContinuousClock.now
        #expect(parameters.retryInterval(lastHeard: now - .milliseconds(100), now: now) == .milliseconds(2100))
        #expect(parameters.retryInterval(lastHeard: now - .seconds(6), now: now) == .milliseconds(9500))
        #expect(parameters.retryInterval(lastHeard: nil, now: now) == .milliseconds(9500))
    }
}

extension EventReport {
    var record: EventRecord? {
        if case .data(let record) = self { return record }
        return nil
    }
}
