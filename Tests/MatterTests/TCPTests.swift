import NIOCore
import NIOEmbedded
import Testing
@testable import Matter

struct TCPTests {
    @Test func commissionsOverTCPWithoutMRP() async throws {
        let streams = TCPTransport(port: 0)
        var configuration = NodeConfiguration(passcode: 20202021, discriminator: 3840)
        configuration.reliability = .fast
        configuration.tcp = true
        let node = try await MatterNode(configuration: configuration, storage: MemoryStorage(),
                                        transport: CombinedTransport(datagrams: UDPTransport(port: 0), streams: streams))
        try await node.start()
        let port = try #require(streams.localPort)

        let client = TCPTransport(port: nil)
        let controllerLayer = MessageLayer(transport: client, reliability: .fast)
        let commissioner = try Commissioner(layer: controllerLayer, fabricID: 7, nodeID: 0x99)
        try await commissioner.start()
        let peer = try await client.connect(to: try SocketAddress(ipAddress: "127.0.0.1", port: port))
        let session = try await commissioner.commission(peer, passcode: 20202021, nodeID: 0x1234)
        let name = try await commissioner.client.read(endpoint: 0, cluster: BasicInformationCluster.id,
                                                      attribute: BasicInformationCluster.Attribute.productName, session: session.localSessionID)
        #expect(name == .utf8("Matter Bridge"))
        // The node's sessions run over the connection, and it says it serves TCP.
        #expect(await node.layer.sessions.allSatisfy(\.peerAddress.isStream))
        #expect(await node.layer.parameters.supportedTransports == .tcpServer)

        // The connection closing takes its sessions with it (Core §4.15.2.2).
        await controllerLayer.stop()
        try await eventually { await node.layer.sessions.isEmpty }
        await node.stop()
    }

    @Test func framesMessagesByTheirLength() throws {
        let channel = EmbeddedChannel(handler: ByteToMessageHandler(LengthPrefixDecoder(maxMessageSize: 16)))
        var buffer = channel.allocator.buffer(capacity: 16)
        // Two messages in one read, the second split across reads.
        buffer.writeBytes([3, 0, 0, 0, 0xA, 0xB, 0xC, 2, 0, 0])
        try channel.writeInbound(buffer)
        #expect(try channel.readInbound(as: ByteBuffer.self).map { Array($0.readableBytesView) } == [0xA, 0xB, 0xC])
        #expect(try channel.readInbound(as: ByteBuffer.self) == nil)
        try channel.writeInbound(channel.allocator.buffer(bytes: [0, 0xD, 0xE]))
        #expect(try channel.readInbound(as: ByteBuffer.self).map { Array($0.readableBytesView) } == [0xD, 0xE])
        // Longer than the node takes: refused (the transport then closes the connection).
        #expect(throws: (any Error).self) { try channel.writeInbound(channel.allocator.buffer(bytes: [17, 0, 0, 0])) }
    }

    @Test func encodesSupportedTransports() {
        var parameters = SessionParameters.default
        #expect(parameters.tlv[8]?.uint == 0)
        #expect(parameters.tlv[9] == nil)
        parameters.supportedTransports = [.tcpClient, .tcpServer]
        #expect(parameters.tlv[8]?.uint == 6)
        #expect(parameters.tlv[9]?.uint == 64000)
        // The deprecated bit 0 is ignored on the way in.
        #expect(SessionParameters(tlv: .structure([.field(8, .unsigned(7))])).supportedTransports == [.tcpClient, .tcpServer])
        let t = MatterRecords.sessionTXT(parameters).last
        #expect(t?.0 == "T" && t?.1 == "6")
    }
}
