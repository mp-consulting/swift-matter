import NIOCore
import Testing
@testable import Matter

struct UDPTests {
    @Test func commissionsOverUDP() async throws {
        let nodeTransport = UDPTransport(port: 0)
        var configuration = NodeConfiguration(passcode: 20202021, discriminator: 3840)
        configuration.reliability = .fast
        let node = try await MatterNode(configuration: configuration, storage: MemoryStorage(), transport: nodeTransport)
        try await node.start()
        let port = try #require(nodeTransport.localPort)

        let controllerLayer = MessageLayer(transport: UDPTransport(port: 0), reliability: .fast)
        let commissioner = try Commissioner(layer: controllerLayer, fabricID: 7, nodeID: 0x99)
        try await commissioner.start()
        // Over IPv4 loopback: the dual-stack socket maps it to ::ffff:127.0.0.1.
        let session = try await commissioner.commission(.socket(try SocketAddress(ipAddress: "127.0.0.1", port: port)),
                                                        passcode: 20202021, nodeID: 0x1234)
        let name = try await commissioner.client.read(endpoint: 0, cluster: BasicInformationCluster.id,
                                                      attribute: BasicInformationCluster.Attribute.productName, session: session.localSessionID)
        #expect(name == .utf8("Matter Bridge"))
        await node.stop()
        await controllerLayer.stop()
    }

    /// At MRP's real timings an exchange that loses nothing never waits for a retransmission: the responder's answer
    /// carries the acknowledgement of the request. A lost piggybacked ack costs at least 330 ms per exchange.
    @Test func acknowledgesWithoutWaitingForRetransmissions() async throws {
        let nodeTransport = UDPTransport(port: 0)
        let node = try await MatterNode(configuration: NodeConfiguration(passcode: 20202021, discriminator: 3840), storage: MemoryStorage(),
                                        transport: nodeTransport)
        try await node.start()
        let controllerLayer = MessageLayer(transport: UDPTransport(port: 0))
        let commissioner = try Commissioner(layer: controllerLayer, fabricID: 7, nodeID: 0x99)
        try await commissioner.start()
        let peer = PeerAddress.socket(try SocketAddress(ipAddress: "127.0.0.1", port: try #require(nodeTransport.localPort)))
        let session = try await commissioner.commission(peer, passcode: 20202021, nodeID: 0x1234)
        let start = ContinuousClock.now
        for _ in 0..<3 {
            _ = try await commissioner.client.read(endpoint: 0, cluster: BasicInformationCluster.id,
                                                   attribute: BasicInformationCluster.Attribute.productName, session: session.localSessionID)
        }
        #expect(ContinuousClock.now - start < .milliseconds(300))
        await node.stop()
        await controllerLayer.stop()
    }
}
