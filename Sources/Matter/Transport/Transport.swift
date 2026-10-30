import NIOConcurrencyHelpers
import NIOCore
import NIOPosix

/// Where a datagram came from or goes to.
public enum PeerAddress: Hashable, Sendable, CustomStringConvertible {
    case socket(SocketAddress)
    /// An endpoint of a `MemoryNetwork`.
    case memory(String)
    /// A TCP connection: messages to it go over that connection, without MRP (Core §4.15).
    case stream(id: UInt64, remote: SocketAddress)

    public var description: String {
        switch self {
        case .socket(let address): address.description
        case .memory(let name): "memory:\(name)"
        case .stream(let id, let remote): "tcp:\(remote)#\(id)"
        }
    }

    /// Whether the transport is reliable on its own, so MRP stays off (Core §4.12.4).
    public var isStream: Bool {
        if case .stream = self { return true }
        return false
    }
}

/// Received datagrams, delivered in order by one consumer task rather than a task per datagram.
final class DatagramInbox: Sendable {
    typealias Datagram = (bytes: [UInt8], peer: PeerAddress)
    private let continuation: AsyncStream<Datagram>.Continuation
    private let consumer: Task<Void, Never>

    init(receive: @escaping @Sendable ([UInt8], PeerAddress) async -> Void) {
        let (stream, continuation) = AsyncStream.makeStream(of: Datagram.self, bufferingPolicy: .bufferingNewest(256))
        self.continuation = continuation
        consumer = Task {
            for await datagram in stream { await receive(datagram.bytes, datagram.peer) }
        }
    }

    func post(_ bytes: [UInt8], from peer: PeerAddress) { continuation.yield((bytes, peer)) }

    func close() {
        continuation.finish()
        consumer.cancel()
    }
}

/// A datagram transport: UDP, or memory in tests.
public protocol MatterTransport: Sendable {
    /// Starts delivering received datagrams to `receive`.
    func start(receive: @escaping @Sendable ([UInt8], PeerAddress) async -> Void) async throws
    func send(_ datagram: [UInt8], to peer: PeerAddress) async throws
    func close() async
    /// Called with a stream peer whose connection closed; datagram transports never call it.
    func onDisconnect(_ handler: @escaping @Sendable (PeerAddress) async -> Void) async
}

extension MatterTransport {
    public func onDisconnect(_ handler: @escaping @Sendable (PeerAddress) async -> Void) async {}
}

/// UDP over IPv6 (dual-stack, so IPv4 peers work too) on Matter's port, 5540 by default.
public final class UDPTransport: MatterTransport {
    public let port: Int
    private let group: EventLoopGroup
    private let channel = NIOLockedValueBox<Channel?>(nil)
    private let inbox = NIOLockedValueBox<DatagramInbox?>(nil)

    public init(port: Int = 5540, group: EventLoopGroup = MultiThreadedEventLoopGroup.singleton) {
        self.port = port
        self.group = group
    }

    /// The bound port; differs from `port` when it was 0.
    public var localPort: Int? { channel.withLockedValue { $0?.localAddress?.port } }

    public func start(receive: @escaping @Sendable ([UInt8], PeerAddress) async -> Void) async throws {
        let inbox = DatagramInbox(receive: receive)
        let bound: Channel
        do {
            bound = try await DatagramBootstrap(group: group)
                .channelOption(.socketOption(.so_reuseaddr), value: 1)
                .channelInitializer { channel in
                    channel.eventLoop.makeCompletedFuture { try channel.pipeline.syncOperations.addHandler(Inbound(inbox: inbox)) }
                }
                .bind(host: "::", port: port)
                .get()
        } catch {
            inbox.close()
            throw error
        }
        self.inbox.withLockedValue { $0 = inbox }
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
        inbox.withLockedValue { value in value?.close(); value = nil }
    }

    /// An IPv4 peer as itself, not as the IPv4-mapped IPv6 address a dual-stack socket reports, so replies match the
    /// address an exchange was started with.
    static func unmapped(_ address: SocketAddress) -> SocketAddress {
        guard address.protocol == .inet6, let ip = address.ipAddress, ip.lowercased().hasPrefix("::ffff:"), ip.contains("."),
              let port = address.port, let v4 = try? SocketAddress(ipAddress: String(ip.dropFirst(7)), port: port)
        else { return address }
        return v4
    }

    static func mapped(_ address: SocketAddress) throws -> SocketAddress {
        guard let ip = address.ipAddress, let port = address.port else { return address }
        return try SocketAddress(ipAddress: "::ffff:" + ip, port: port)
    }

    private final class Inbound: ChannelInboundHandler, Sendable {
        typealias InboundIn = AddressedEnvelope<ByteBuffer>
        let inbox: DatagramInbox

        init(inbox: DatagramInbox) { self.inbox = inbox }

        func channelRead(context: ChannelHandlerContext, data: NIOAny) {
            let envelope = unwrapInboundIn(data)
            inbox.post(Array(envelope.data.readableBytesView), from: .socket(UDPTransport.unmapped(envelope.remoteAddress)))
        }
    }
}

/// An in-memory network for tests: endpoints by name, with an optional filter that drops datagrams.
public actor MemoryNetwork {
    private var endpoints: [String: DatagramInbox] = [:]
    /// Returns false to drop a datagram (from, to, bytes).
    private var filter: (@Sendable (String, String, [UInt8]) -> Bool)?

    public init() {}

    public func setFilter(_ filter: (@Sendable (String, String, [UInt8]) -> Bool)?) { self.filter = filter }

    public func transport(named name: String) -> MemoryTransport { MemoryTransport(network: self, name: name) }

    func register(_ name: String, receive: @escaping @Sendable ([UInt8], PeerAddress) async -> Void) {
        endpoints[name] = DatagramInbox(receive: receive)
    }

    func unregister(_ name: String) { endpoints.removeValue(forKey: name)?.close() }

    func deliver(_ datagram: [UInt8], from source: String, to destination: String) {
        guard let inbox = endpoints[destination], filter?(source, destination, datagram) ?? true else { return }
        inbox.post(datagram, from: .memory(source))
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
