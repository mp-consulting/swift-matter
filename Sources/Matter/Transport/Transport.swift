import NIOConcurrencyHelpers
import NIOCore
import NIOPosix

/// Where a datagram came from or goes to.
public enum PeerAddress: Hashable, Sendable, CustomStringConvertible {
    case socket(SocketAddress)
    /// An endpoint of a `MemoryNetwork`.
    case memory(String)

    public var description: String {
        switch self {
        case .socket(let address): address.description
        case .memory(let name): "memory:\(name)"
        }
    }
}

/// A datagram transport: UDP, or memory in tests.
public protocol MatterTransport: Sendable {
    /// Starts delivering received datagrams to `receive`.
    func start(receive: @escaping @Sendable ([UInt8], PeerAddress) async -> Void) async throws
    func send(_ datagram: [UInt8], to peer: PeerAddress) async throws
    func close() async
}

/// UDP over IPv6 (dual-stack, so IPv4 peers work too) on Matter's port, 5540 by default.
public final class UDPTransport: MatterTransport {
    public let port: Int
    private let group: EventLoopGroup
    private let channel = NIOLockedValueBox<Channel?>(nil)

    public init(port: Int = 5540, group: EventLoopGroup = MultiThreadedEventLoopGroup.singleton) {
        self.port = port
        self.group = group
    }

    /// The bound port; differs from `port` when it was 0.
    public var localPort: Int? { channel.withLockedValue { $0?.localAddress?.port } }

    public func start(receive: @escaping @Sendable ([UInt8], PeerAddress) async -> Void) async throws {
        let bound = try await DatagramBootstrap(group: group)
            .channelOption(.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture { try channel.pipeline.syncOperations.addHandler(Inbound(receive: receive)) }
            }
            .bind(host: "::", port: port)
            .get()
        channel.withLockedValue { $0 = bound }
    }

    public func send(_ datagram: [UInt8], to peer: PeerAddress) async throws {
        guard case .socket(let address) = peer, let channel = channel.withLockedValue({ $0 }) else { return }
        // A dual-stack socket reaches IPv4 peers through their IPv4-mapped IPv6 address.
        let target = address.protocol == .inet ? try Self.mapped(address) : address
        let envelope = AddressedEnvelope(remoteAddress: target, data: channel.allocator.buffer(bytes: datagram))
        try await channel.writeAndFlush(envelope)
    }

    public func close() async {
        let channel = channel.withLockedValue { value in defer { value = nil }; return value }
        try? await channel?.close()
    }

    static func mapped(_ address: SocketAddress) throws -> SocketAddress {
        guard let ip = address.ipAddress, let port = address.port else { return address }
        return try SocketAddress(ipAddress: "::ffff:" + ip, port: port)
    }

    private final class Inbound: ChannelInboundHandler, Sendable {
        typealias InboundIn = AddressedEnvelope<ByteBuffer>
        let receive: @Sendable ([UInt8], PeerAddress) async -> Void

        init(receive: @escaping @Sendable ([UInt8], PeerAddress) async -> Void) { self.receive = receive }

        func channelRead(context: ChannelHandlerContext, data: NIOAny) {
            let envelope = unwrapInboundIn(data)
            let bytes = Array(envelope.data.readableBytesView)
            let peer = PeerAddress.socket(envelope.remoteAddress)
            let receive = receive
            Task { await receive(bytes, peer) }
        }
    }
}

/// An in-memory network for tests: endpoints by name, with an optional filter that drops datagrams.
public actor MemoryNetwork {
    private var endpoints: [String: @Sendable ([UInt8], PeerAddress) async -> Void] = [:]
    /// Returns false to drop a datagram (from, to, bytes).
    private var filter: (@Sendable (String, String, [UInt8]) -> Bool)?

    public init() {}

    public func setFilter(_ filter: (@Sendable (String, String, [UInt8]) -> Bool)?) { self.filter = filter }

    public func transport(named name: String) -> MemoryTransport { MemoryTransport(network: self, name: name) }

    func register(_ name: String, receive: @escaping @Sendable ([UInt8], PeerAddress) async -> Void) {
        endpoints[name] = receive
    }

    func unregister(_ name: String) { endpoints[name] = nil }

    func deliver(_ datagram: [UInt8], from source: String, to destination: String) {
        guard let receive = endpoints[destination], filter?(source, destination, datagram) ?? true else { return }
        Task { await receive(datagram, .memory(source)) }
    }
}

public struct MemoryTransport: MatterTransport {
    let network: MemoryNetwork
    public let name: String

    public var address: PeerAddress { .memory(name) }

    public func start(receive: @escaping @Sendable ([UInt8], PeerAddress) async -> Void) async throws {
        await network.register(name, receive: receive)
    }

    public func send(_ datagram: [UInt8], to peer: PeerAddress) async throws {
        guard case .memory(let destination) = peer else { return }
        await network.deliver(datagram, from: name, to: destination)
    }

    public func close() async { await network.unregister(name) }
}
