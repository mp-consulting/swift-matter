import NIOConcurrencyHelpers
import NIOCore
import NIOPosix

/// Matter over TCP (Core §4.15): each message on a connection is prefixed by its length, 4 bytes little-endian
/// (Core §4.5.1), and MRP stays off because the connection is reliable. A server listens on its port; `connect`
/// opens a connection as a client. Each connection is a peer of its own (`PeerAddress.stream`).
public final class TCPTransport: MatterTransport {
    /// What a listening transport binds to; nil for a client only.
    public let port: Int?
    /// The largest message, without its length, taken from a peer; a longer one closes the connection (Core §4.15.2.3).
    public let maxMessageSize: Int
    private let group: EventLoopGroup
    private let state = NIOLockedValueBox(State())

    private struct State {
        var listener: Channel?
        var connections: [UInt64: Channel] = [:]
        var nextID: UInt64 = 1
        var inbox: DatagramInbox?
        var disconnect: (@Sendable (PeerAddress) async -> Void)?
    }

    public init(port: Int? = 5540, maxMessageSize: Int = SessionParameters.maxTCPMessageSize,
                group: EventLoopGroup = MultiThreadedEventLoopGroup.singleton) {
        self.port = port
        self.maxMessageSize = maxMessageSize
        self.group = group
    }

    /// The bound port; differs from `port` when it was 0.
    public var localPort: Int? { state.withLockedValue { $0.listener?.localAddress?.port } }

    public func onDisconnect(_ handler: @escaping @Sendable (PeerAddress) async -> Void) async {
        state.withLockedValue { $0.disconnect = handler }
    }

    public func start(receive: @escaping @Sendable ([UInt8], PeerAddress) async -> Void) async throws {
        let inbox = DatagramInbox(receive: receive)
        state.withLockedValue { $0.inbox = inbox }
        guard let port else { return }
        let bound: Channel
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelOption(.socketOption(.so_keepalive), value: 1)
            .childChannelInitializer { [self] channel in
                channel.eventLoop.makeCompletedFuture { try self.attach(channel) }
            }
        do {
            bound = try await UDPTransport.bindDualStack(port: port) { try await bootstrap.bind(host: $0, port: $1).get() }
        } catch {
            state.withLockedValue { $0.inbox = nil }
            inbox.close()
            throw error
        }
        state.withLockedValue { $0.listener = bound }
    }

    /// Opens a connection to a TCP server; messages sent to the returned peer go over it.
    public func connect(to address: SocketAddress) async throws -> PeerAddress {
        let peer = NIOLockedValueBox<PeerAddress?>(nil)
        // A connection that cannot be set up fails here, and closes.
        _ = try await ClientBootstrap(group: group)
            .channelOption(.socketOption(.so_keepalive), value: 1)
            .channelInitializer { [self] channel in
                channel.eventLoop.makeCompletedFuture { try peer.withLockedValue { $0 = try self.attach(channel) } }
            }
            .connect(to: address)
            .get()
        guard let connected = peer.withLockedValue({ $0 }) else { throw ChannelError.ioOnClosedChannel }
        return connected
    }

    /// Gives a connection its id and its handlers, and returns its peer.
    @discardableResult
    private func attach(_ channel: Channel) throws -> PeerAddress {
        let id = state.withLockedValue { state in
            defer { state.nextID += 1 }
            return state.nextID
        }
        let remote = try channel.remoteAddress.map(UDPTransport.unmapped) ?? SocketAddress(ipAddress: "::", port: 0)
        let peer = PeerAddress.stream(id: id, remote: remote)
        try channel.pipeline.syncOperations.addHandlers([
            ByteToMessageHandler(LengthPrefixDecoder(maxMessageSize: maxMessageSize)),
            Inbound(transport: self, peer: peer),
        ])
        // Listed once it can be read and its closing is seen.
        state.withLockedValue { $0.connections[id] = channel }
        return peer
    }

    fileprivate func received(_ message: [UInt8], from peer: PeerAddress) {
        state.withLockedValue { $0.inbox }?.post(message, from: peer)
    }

    fileprivate func closed(_ peer: PeerAddress) {
        guard case .stream(let id, _) = peer else { return }
        let disconnect = state.withLockedValue { state in
            state.connections[id] = nil
            return state.disconnect
        }
        if let disconnect { Task { await disconnect(peer) } }
    }

    public func send(_ datagram: [UInt8], to peer: PeerAddress) async throws {
        guard case .stream(let id, _) = peer else { return }
        guard let channel = state.withLockedValue({ $0.connections[id] }) else { throw ChannelError.ioOnClosedChannel }
        var buffer = channel.allocator.buffer(capacity: datagram.count + 4)
        buffer.writeInteger(UInt32(datagram.count), endianness: .little)
        buffer.writeBytes(datagram)
        try await channel.writeAndFlush(buffer)
    }

    public func close() async {
        let (listener, connections, inbox) = state.withLockedValue { state in
            // Connection ids keep counting: a peer of an earlier connection never names a new one.
            defer { state = State(nextID: state.nextID, disconnect: state.disconnect) }
            return (state.listener, Array(state.connections.values), state.inbox)
        }
        try? await listener?.close()
        for connection in connections { try? await connection.close() }
        inbox?.close()
    }

    private final class Inbound: ChannelInboundHandler, Sendable {
        typealias InboundIn = ByteBuffer
        let transport: TCPTransport
        let peer: PeerAddress

        init(transport: TCPTransport, peer: PeerAddress) {
            self.transport = transport
            self.peer = peer
        }

        func channelRead(context: ChannelHandlerContext, data: NIOAny) {
            transport.received(Array(unwrapInboundIn(data).readableBytesView), from: peer)
        }

        func channelInactive(context: ChannelHandlerContext) {
            transport.closed(peer)
            context.fireChannelInactive()
        }

        func errorCaught(context: ChannelHandlerContext, error: Error) {
            // A message too large, or a broken stream: the connection closes (Core §4.15.2.3).
            context.close(promise: nil)
        }
    }
}

/// Splits a TCP stream into Matter messages by their 4-byte little-endian length (Core §4.5.1).
struct LengthPrefixDecoder: ByteToMessageDecoder {
    typealias InboundOut = ByteBuffer
    let maxMessageSize: Int

    struct MessageTooLarge: Error {}

    mutating func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        guard let length = buffer.getInteger(at: buffer.readerIndex, endianness: .little, as: UInt32.self) else { return .needMoreData }
        guard length <= maxMessageSize else { throw MessageTooLarge() }
        guard buffer.readableBytes >= 4 + Int(length) else { return .needMoreData }
        buffer.moveReaderIndex(forwardBy: 4)
        context.fireChannelRead(wrapInboundOut(buffer.readSlice(length: Int(length))!))
        return .continue
    }
}

/// UDP and TCP together: messages to a stream peer go over its connection, the others as datagrams.
public final class CombinedTransport: MatterTransport {
    public let datagrams: any MatterTransport
    public let streams: TCPTransport

    public init(datagrams: any MatterTransport, streams: TCPTransport) {
        self.datagrams = datagrams
        self.streams = streams
    }

    public func start(receive: @escaping @Sendable ([UInt8], PeerAddress) async -> Void) async throws {
        try await datagrams.start(receive: receive)
        do {
            try await streams.start(receive: receive)
        } catch {
            await datagrams.close()
            throw error
        }
    }

    public func send(_ datagram: [UInt8], to peer: PeerAddress) async throws {
        try await peer.isStream ? streams.send(datagram, to: peer) : datagrams.send(datagram, to: peer)
    }

    public func onDisconnect(_ handler: @escaping @Sendable (PeerAddress) async -> Void) async {
        await streams.onDisconnect(handler)
    }

    public func setMulticastGroups(_ addresses: [SocketAddress]) async {
        await datagrams.setMulticastGroups(addresses)
    }

    public func close() async {
        await streams.close()
        await datagrams.close()
    }
}
