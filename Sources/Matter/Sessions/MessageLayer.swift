import Foundation
import Logging

/// Handles exchanges a peer starts for one protocol.
public protocol ProtocolHandler: Sendable {
    /// Called for the first message of an exchange the peer initiated; the exchange is closed when this returns.
    func handle(_ exchange: Exchange, first message: Message) async
    /// Called with an authenticated group message (Core §4.16): there is no exchange, and nothing is answered.
    func handleGroup(_ message: Message, session: SessionInfo) async
}

extension ProtocolHandler {
    public func handleGroup(_ message: Message, session: SessionInfo) async {}
}

public enum ExchangeError: Error, Equatable, Sendable {
    case timeout
    case closed
    case notAcknowledged
    case sessionGone
    case handlerAlreadyRegistered
}

/// MRP constants (Core §4.12.8).
public struct ReliabilityParameters: Sendable {
    public var maxTransmissions = 5
    public var backoffBase = 1.6
    public var backoffJitter = 0.25
    public var backoffMargin = 1.1
    public var backoffThreshold = 1
    public var standaloneAckTimeout: Duration = .milliseconds(200)
    /// Multiplies every timeout: tests run MRP with a small scale rather than waiting it out.
    public var timeScale = 1.0

    /// MRP with its timings scaled: tests pass a small `timeScale` rather than waiting them out.
    public init(timeScale: Double = 1.0) { self.timeScale = timeScale }

    func scaled(_ duration: Duration) -> Duration { duration * timeScale }
}

/// The message layer (Core §4.7-§4.12): decodes and authenticates datagrams, detects duplicates, routes messages to
/// exchanges and keeps reliable messages flowing with acknowledgements and retransmissions.
public actor MessageLayer {
    struct UnsecuredKey: Hashable {
        let peer: PeerAddress
        /// The ephemeral node id the initiator chose, or 0 for messages without a source.
        let peerNodeID: UInt64
    }

    enum SessionRef: Hashable {
        case unsecured(UnsecuredKey)
        case secure(UInt16)
    }

    struct ExchangeKey: Hashable {
        let session: SessionRef
        let exchangeID: UInt16
        let isInitiator: Bool
    }

    struct PendingRetransmission {
        let counter: UInt32
        let task: Task<Void, Never>
    }

    struct ExchangeState {
        let exchange: Exchange
        /// The counter of a received reliable message not yet acknowledged.
        var pendingAck: UInt32?
        var ackTask: Task<Void, Never>?
        var retransmission: PendingRetransmission?
        var closed = false
    }

    struct UnsecuredSession {
        var reception = MessageReceptionState(policy: .rolling)
        /// The node id this node uses toward the peer (an initiator's ephemeral id).
        let localNodeID: UInt64
    }

    public let transport: any MatterTransport
    public let parameters: SessionParameters
    public let reliability: ReliabilityParameters
    let logger: Logger

    private var unsecuredCounter = MessageCounter.initialValue()
    private var unsecuredSessions: [UnsecuredKey: UnsecuredSession] = [:]
    private var secureSessions: [UInt16: SecureSession] = [:]
    private var exchanges: [ExchangeKey: ExchangeState] = [:]
    private var handlers: [ProtocolID: any ProtocolHandler] = [:]
    private var handlerTasks: [UInt64: Task<Void, Never>] = [:]
    private var nextHandlerTask: UInt64 = 0
    private var nextExchangeID = UInt16.random(in: 0...UInt16.max)
    private var sessionCloseObservers: [@Sendable (SessionInfo) async -> Void] = []
    /// The node's groups, to receive group messages; without them group messages are dropped.
    private let groups: Groups?
    /// The group message being handled: group commands run one after another, in the order they came, since
    /// nothing answers them to keep a sender in step.
    private var groupTail: Task<Void, Never>?

    public init(transport: any MatterTransport, parameters: SessionParameters = .default, reliability: ReliabilityParameters = .init(),
                groups: Groups? = nil, logger: Logger = Logger(label: "matter.messages")) {
        self.transport = transport
        self.parameters = parameters
        self.reliability = reliability
        self.groups = groups
        self.logger = logger
    }

    public func start() async throws {
        await transport.onDisconnect { [weak self] peer in await self?.disconnected(peer) }
        try await transport.start { [weak self] bytes, peer in
            await self?.receive(bytes, from: peer)
        }
    }

    /// A TCP connection closed: its sessions and exchanges are unusable (Core §4.15.2.2).
    private func disconnected(_ peer: PeerAddress) async {
        await removeSessions { $0.peerAddress == peer }
        for key in exchanges.keys {
            if case .unsecured(let session) = key.session, session.peer == peer { await tearDown(key, error: .sessionGone) }
        }
        unsecuredSessions = unsecuredSessions.filter { $0.key.peer != peer }
    }

    public func stop() async {
        handlerTasks.values.forEach { $0.cancel() }
        for key in exchanges.keys { await tearDown(key, error: .closed) }
        await transport.close()
    }

    /// Cancels an exchange's timers, forgets it and fails its pending receive.
    private func tearDown(_ key: ExchangeKey, error: ExchangeError) async {
        guard let state = exchanges.removeValue(forKey: key) else { return }
        state.ackTask?.cancel()
        state.retransmission?.task.cancel()
        await state.exchange.fail(error)
    }

    /// Registers the handler of a protocol's unsolicited messages; one per protocol.
    public func register(_ handler: any ProtocolHandler, for protocolID: ProtocolID) throws {
        guard handlers[protocolID] == nil else { throw ExchangeError.handlerAlreadyRegistered }
        handlers[protocolID] = handler
    }

    public func onSessionClosed(_ observer: @escaping @Sendable (SessionInfo) async -> Void) {
        sessionCloseObservers.append(observer)
    }

    // MARK: - Sessions

    /// A new local session id: nonzero and unused (Core §4.13.2.4).
    public func allocateSessionID() -> UInt16 {
        while true {
            let candidate = UInt16.random(in: 1...UInt16.max)
            if secureSessions[candidate] == nil { return candidate }
        }
    }

    /// Installs a secure session; this node encrypts with `encryptKey` and decrypts with `decryptKey`.
    @discardableResult
    func addSecureSession(info: SessionInfo, encryptKey: [UInt8], decryptKey: [UInt8], peerParameters: SessionParameters) throws -> SessionInfo {
        secureSessions[info.localSessionID] = try SecureSession(info: info, encryptKey: encryptKey, decryptKey: decryptKey,
                                                                 peerParameters: peerParameters)
        logger.debug("Session \(info.localSessionID) established (\(info.kind)) with \(info.peerAddress)")
        return info
    }

    public func session(_ localSessionID: UInt16) -> SessionInfo? { secureSessions[localSessionID]?.info }

    public var sessions: [SessionInfo] { secureSessions.values.map(\.info) }

    /// Binds a PASE session to the fabric it commissioned (after AddNOC).
    public func bind(session localSessionID: UInt16, toFabric fabricIndex: UInt8?) {
        secureSessions[localSessionID]?.info.fabricIndex = fabricIndex
    }

    /// Removes sessions, failing their exchanges.
    public func removeSessions(where shouldRemove: (SessionInfo) -> Bool) async {
        let removed = secureSessions.values.filter { shouldRemove($0.info) }
        for session in removed {
            secureSessions[session.info.localSessionID] = nil
            for key in exchanges.keys where key.session == .secure(session.info.localSessionID) {
                await tearDown(key, error: .sessionGone)
            }
            for observer in sessionCloseObservers { await observer(session.info) }
        }
    }

    // MARK: - Exchanges

    /// Starts an exchange over a secure session.
    public func newExchange(session localSessionID: UInt16, protocolID: ProtocolID) throws -> Exchange {
        guard let session = secureSessions[localSessionID] else { throw ExchangeError.sessionGone }
        return makeExchange(key: ExchangeKey(session: .secure(localSessionID), exchangeID: allocateExchangeID(), isInitiator: true),
                            info: session.info, protocolID: protocolID)
    }

    /// Starts an exchange over an unsecured session toward a peer (session establishment as initiator).
    public func newUnsecuredExchange(to peer: PeerAddress, protocolID: ProtocolID) -> Exchange {
        // The initiator's ephemeral node id is random (Core §4.13.2.1); the peer replies to it.
        let localNodeID = UInt64.random(in: 1...0xFFFF_FFEF_FFFF_FFFF)
        let key = UnsecuredKey(peer: peer, peerNodeID: localNodeID)
        unsecuredSessions[key] = UnsecuredSession(localNodeID: localNodeID)
        return makeExchange(key: ExchangeKey(session: .unsecured(key), exchangeID: allocateExchangeID(), isInitiator: true),
                            info: unsecuredInfo(peer), protocolID: protocolID)
    }

    private func allocateExchangeID() -> UInt16 {
        defer { nextExchangeID &+= 1 }
        return nextExchangeID
    }

    private func unsecuredInfo(_ peer: PeerAddress) -> SessionInfo {
        SessionInfo(kind: .unsecured, localSessionID: 0, peerSessionID: 0, peerAddress: peer)
    }

    /// How long to wait for a response on an exchange: the peer's whole retransmission schedule (scaled like MRP)
    /// plus time for it to do the work.
    func responseTimeout(for key: ExchangeKey) -> Duration {
        let interval = retryInterval(for: key.session)
        var schedule: Duration = .zero
        for attempt in 0..<reliability.maxTransmissions {
            schedule += interval * backoff(attempt: attempt, jitter: 1)
        }
        return reliability.scaled(schedule) + .seconds(5)
    }

    /// MRP's backoff factor for a retransmission (Core §4.12.2.1); `jitter` is the random draw in [0, 1].
    private func backoff(attempt: Int, jitter: Double) -> Double {
        let exponent = Double(max(0, attempt - reliability.backoffThreshold))
        return reliability.backoffMargin * pow(reliability.backoffBase, exponent) * (1 + jitter * reliability.backoffJitter)
    }

    /// A new exchange; one the peer opened records its first message's acknowledgement at once, so a reply carries it.
    private func makeExchange(key: ExchangeKey, info: SessionInfo, protocolID: ProtocolID, first message: Message? = nil) -> Exchange {
        let exchange = Exchange(layer: self, key: key, session: info, protocolID: protocolID)
        exchanges[key] = ExchangeState(exchange: exchange)
        if let message { noteReceived(message, key: key) }
        return exchange
    }

    /// Sends a message on an exchange; reliable unless it is a standalone acknowledgement. Over TCP the connection is
    /// reliable, so MRP stays off: no R flag, no retransmission (Core §4.15).
    func send(on key: ExchangeKey, protocolID: ProtocolID, opcode: UInt8, payload: [UInt8], reliable requested: Bool = true) async throws {
        let reliable = requested && !(peer(of: key.session)?.isStream ?? false)
        guard var state = exchanges[key], !state.closed else { throw ExchangeError.closed }
        // One reliable message in flight per exchange (Core §4.12.5.1).
        if reliable, let pending = state.retransmission {
            await waitForAck(of: key, counter: pending.counter)
            guard let refreshed = exchanges[key], !refreshed.closed else { throw ExchangeError.closed }
            state = refreshed
        }
        let ack = state.pendingAck
        state.pendingAck = nil
        state.ackTask?.cancel()
        state.ackTask = nil
        exchanges[key] = state

        let payloadHeader = PayloadHeader(isInitiator: key.isInitiator, needsAck: reliable, ackedCounter: ack, opcode: opcode,
                                          exchangeID: key.exchangeID, protocolID: protocolID)
        let (frame, counter, peer) = try encode(session: key.session, payloadHeader: payloadHeader, payload: payload)
        try await transport.send(frame, to: peer)

        if reliable {
            let interval = retryInterval(for: key.session)
            let task = Task { [weak self] () -> Void in await self?.retransmit(frame, to: peer, key: key, counter: counter, interval: interval) }
            exchanges[key]?.retransmission = PendingRetransmission(counter: counter, task: task)
        }
    }

    /// Waits until the reliable message `counter` is acknowledged or given up on.
    private func waitForAck(of key: ExchangeKey, counter: UInt32) async {
        while let pending = exchanges[key]?.retransmission, pending.counter == counter {
            await pending.task.value
        }
    }

    private func peer(of session: SessionRef) -> PeerAddress? {
        switch session {
        case .secure(let id): secureSessions[id]?.info.peerAddress
        case .unsecured(let key): key.peer
        }
    }

    private func retryInterval(for session: SessionRef) -> Duration {
        switch session {
        case .secure(let id): secureSessions[id]?.peerParameters.activeInterval ?? parameters.activeInterval
        case .unsecured: SessionParameters.default.activeInterval
        }
    }

    /// Retransmits until acknowledged (the task is cancelled) or MRP_MAX_TRANSMISSIONS is reached (Core §4.12.2.1).
    private func retransmit(_ frame: [UInt8], to peer: PeerAddress, key: ExchangeKey, counter: UInt32, interval: Duration) async {
        for attempt in 0..<reliability.maxTransmissions {
            do {
                try await Task.sleep(for: reliability.scaled(interval * backoff(attempt: attempt, jitter: .random(in: 0...1))))
            } catch {
                return
            }
            guard exchanges[key]?.retransmission?.counter == counter else { return }
            if attempt == reliability.maxTransmissions - 1 { break }
            logger.trace("Retransmitting message \(counter) on exchange \(key.exchangeID) to \(peer)")
            try? await transport.send(frame, to: peer)
        }
        guard exchanges[key]?.retransmission?.counter == counter else { return }
        logger.debug("Message \(counter) on exchange \(key.exchangeID) was not acknowledged")
        exchanges[key]?.retransmission = nil
        await exchanges[key]?.exchange.fail(ExchangeError.notAcknowledged)
    }

    /// Closes an exchange: a pending acknowledgement goes out at once; a message in flight keeps being retransmitted
    /// until acknowledged.
    func close(_ key: ExchangeKey) async {
        guard var state = exchanges[key], !state.closed else { return }
        state.closed = true
        state.ackTask?.cancel()
        let ack = state.pendingAck
        state.pendingAck = nil
        exchanges[key] = state
        if let ack { await sendStandaloneAck(key: key, counter: ack) }
        if let pending = state.retransmission {
            await waitForAck(of: key, counter: pending.counter)
        }
        exchanges[key] = nil
        // An unsecured session lives as long as its exchanges.
        if case .unsecured(let session) = key.session, !exchanges.keys.contains(where: { $0.session == key.session }) {
            unsecuredSessions[session] = nil
        }
    }

    private func sendStandaloneAck(key: ExchangeKey, counter: UInt32) async {
        let payloadHeader = PayloadHeader(isInitiator: key.isInitiator, needsAck: false, ackedCounter: counter,
                                          opcode: SecureChannelOpcode.standaloneAck.rawValue, exchangeID: key.exchangeID,
                                          protocolID: .secureChannel)
        guard let (frame, _, peer) = try? encode(session: key.session, payloadHeader: payloadHeader, payload: []) else { return }
        try? await transport.send(frame, to: peer)
    }

    private func scheduleStandaloneAck(_ key: ExchangeKey) {
        exchanges[key]?.ackTask?.cancel()
        let delay = reliability.scaled(reliability.standaloneAckTimeout)
        exchanges[key]?.ackTask = Task { [weak self] in
            guard (try? await Task.sleep(for: delay)) != nil else { return }
            await self?.flushAck(key)
        }
    }

    private func flushAck(_ key: ExchangeKey) async {
        guard let counter = exchanges[key]?.pendingAck else { return }
        exchanges[key]?.pendingAck = nil
        await sendStandaloneAck(key: key, counter: counter)
    }

    // MARK: - Encoding

    private func encode(session: SessionRef, payloadHeader: PayloadHeader, payload: [UInt8]) throws -> ([UInt8], UInt32, PeerAddress) {
        switch session {
        case .unsecured(let key):
            guard let unsecured = unsecuredSessions[key] else { throw ExchangeError.sessionGone }
            let counter = unsecuredCounter
            unsecuredCounter &+= 1
            // The initiator sends its ephemeral id as source; the responder addresses the initiator's id.
            let header = payloadHeader.isInitiator
                ? MessageHeader(sessionID: 0, counter: counter, source: unsecured.localNodeID)
                : MessageHeader(sessionID: 0, counter: counter, destination: key.peerNodeID == 0 ? .none : .node(key.peerNodeID))
            return (Message(header: header, payloadHeader: payloadHeader, payload: payload).unsecuredFrame, counter, key.peer)
        case .secure(let id):
            guard let secure = secureSessions[id] else { throw ExchangeError.sessionGone }
            let counter = secure.localCounter
            secureSessions[id]?.localCounter &+= 1
            let header = MessageHeader(sessionID: secure.info.peerSessionID, counter: counter)
            let frame = try Message(header: header, payloadHeader: payloadHeader, payload: payload)
                .sealedFrame(key: secure.encryptor, nonceSourceNodeID: secure.localNonceNodeID)
            return (frame, counter, secure.info.peerAddress)
        }
    }

    // MARK: - Receiving

    func receive(_ bytes: [UInt8], from peer: PeerAddress) async {
        do {
            let (header, headerLength) = try MessageHeader.decode(bytes)
            if header.sessionType == .group { return await receiveGroup(bytes, header: header, headerLength: headerLength, from: peer) }
            guard !header.privacy else { throw MessageError.privacyUnsupported }

            let session: SessionRef
            let message: Message
            let isDuplicate: Bool
            if header.isUnsecured {
                message = try Message(header: header, plaintext: Array(bytes[headerLength...]))
                // Only session establishment runs unencrypted (Core §4.13.2.1).
                guard message.payloadHeader.protocolID == .secureChannel else { return }
                // A message from an initiator carries its ephemeral id as source; a response is addressed to ours.
                let peerNodeID: UInt64
                if let source = header.source {
                    peerNodeID = source
                } else if case .node(let destination) = header.destination {
                    peerNodeID = destination
                } else {
                    peerNodeID = 0
                }
                let key = UnsecuredKey(peer: peer, peerNodeID: peerNodeID)
                if unsecuredSessions[key] == nil {
                    // Only an initiator's message opens an unsecured session.
                    guard message.payloadHeader.isInitiator else { return }
                    unsecuredSessions[key] = UnsecuredSession(localNodeID: 0)
                }
                isDuplicate = !unsecuredSessions[key]!.reception.accept(header.counter)
                session = .unsecured(key)
            } else {
                guard var secure = secureSessions[header.sessionID] else { throw MessageError.unknownSession(header.sessionID) }
                message = try Message.open(frame: bytes, header: header, headerLength: headerLength, key: secure.decryptor,
                                           nonceSourceNodeID: secure.peerNonceNodeID)
                isDuplicate = !secure.reception.accept(header.counter)
                // The peer may have moved; replies follow its latest authenticated address (Core §4.13.2.2).
                if !isDuplicate { secure.info.peerAddress = peer }
                secureSessions[header.sessionID] = secure
                session = .secure(header.sessionID)
            }
            await dispatch(message, session: session, duplicate: isDuplicate)
        } catch {
            logger.trace("Dropped a \(bytes.count)-byte datagram from \(peer): \(error)")
        }
    }

    private func dispatch(_ message: Message, session: SessionRef, duplicate: Bool) async {
        let payloadHeader = message.payloadHeader
        let key = ExchangeKey(session: session, exchangeID: payloadHeader.exchangeID, isInitiator: !payloadHeader.isInitiator)

        if duplicate {
            // A retransmission of something already received: acknowledge it again, deliver nothing.
            if payloadHeader.needsAck { await sendStandaloneAck(key: key, counter: message.header.counter) }
            return
        }

        if let acked = payloadHeader.ackedCounter, exchanges[key]?.retransmission?.counter == acked {
            exchanges[key]?.retransmission?.task.cancel()
            exchanges[key]?.retransmission = nil
        }

        let isStandaloneAck = payloadHeader.protocolID == .secureChannel
            && payloadHeader.opcode == SecureChannelOpcode.standaloneAck.rawValue

        if exchanges[key] == nil {
            guard !isStandaloneAck, payloadHeader.isInitiator, let handler = handlers[payloadHeader.protocolID] else {
                // An unsolicited message nobody handles; acknowledge it so the peer stops retransmitting.
                if payloadHeader.needsAck { await sendStandaloneAck(key: key, counter: message.header.counter) }
                return
            }
            let info: SessionInfo = switch session {
            case .secure(let id): secureSessions[id]!.info
            case .unsecured(let unsecuredKey): unsecuredInfo(unsecuredKey.peer)
            }
            start(handler, on: makeExchange(key: key, info: info, protocolID: payloadHeader.protocolID, first: message), first: message)
            return
        }

        noteReceived(message, key: key)
        guard !isStandaloneAck, let state = exchanges[key], !state.closed else { return }
        await state.exchange.deliver(message)
    }

    private func start(_ handler: any ProtocolHandler, on exchange: Exchange, first message: Message) {
        let key = exchange.key
        track { [weak self] in
            await handler.handle(exchange, first: message)
            await self?.close(key)
        }
    }

    /// Runs a handler's work as a task `stop` cancels.
    private func track(_ work: @escaping @Sendable () async -> Void) {
        nextHandlerTask += 1
        let taskID = nextHandlerTask
        handlerTasks[taskID] = Task { [weak self] in
            await work()
            await self?.handlerFinished(taskID)
        }
    }

    /// A group message (Core §4.16.3): each operational key its session id points to is tried, privacy removed
    /// first, until one authenticates it for a group mapped to that key; its counter is checked trust-first.
    private func receiveGroup(_ bytes: [UInt8], header: MessageHeader, headerLength: Int, from peer: PeerAddress) async {
        // Group messages are private: the P flag set (Core §4.16.2, §4.18.5).
        guard let groups, header.privacy else { return }
        for candidate in await groups.candidates(sessionID: header.sessionID) {
            // The header's counter, source and destination are readable only once the privacy is removed.
            guard let clear = try? MessageHeader.togglePrivacy(bytes, privacyKey: candidate.privacy),
                  let decoded = try? MessageHeader.decode(clear).0, let source = decoded.source,
                  let message = try? Message.open(frame: clear, header: decoded, headerLength: headerLength, key: candidate.key,
                                                  nonceSourceNodeID: source)
            else { continue }
            switch decoded.destination {
            case .node(let node) where decoded.isControl:
                // MCSP between two nodes under the group key (Core §4.18.5): addressed to this node only.
                guard await groups.nodeID(fabric: candidate.fabric) == node,
                      await groups.check(decoded.counter, fabric: candidate.fabric, source: source, control: true) == .new
                else { return }
                await counterSync(message, from: source, candidate: candidate, sessionID: header.sessionID, peer: peer)
            case .group(let group) where candidate.groups.contains(group) && !decoded.isControl:
                let session = SessionInfo.group(group, fabric: candidate.fabric, source: source, sessionID: header.sessionID, peer: peer)
                switch await groups.check(decoded.counter, fabric: candidate.fabric, source: source, control: false,
                                          cacheAndSync: candidate.cacheAndSync) {
                case .new: dispatchGroup(message, session: session)
                case .duplicate: break
                case .unsynchronized: await awaitSync(message, session: session, candidate: candidate)
                }
            default:
                continue
            }
            return
        }
    }

    /// Hands an authenticated group message to its protocol, after the ones before it (nothing answers them to keep a
    /// sender in step).
    private func dispatchGroup(_ message: Message, session: SessionInfo) {
        guard message.payloadHeader.isInitiator, let handler = handlers[message.payloadHeader.protocolID] else { return }
        let previous = groupTail
        let task = Task {
            await previous?.value
            await handler.handleGroup(message, session: session)
        }
        groupTail = task
        track { await task.value }
    }

    // MARK: - Message counter synchronization (Core §4.18)

    struct SyncKey: Hashable {
        let fabric: FabricIndex
        let peer: NodeID
        let sessionID: UInt16
    }

    /// A MsgCounterSyncReq in flight and the messages waiting on it.
    struct PendingSync {
        let challenge: [UInt8]
        let exchangeID: UInt16
        var queued: [(Message, SessionInfo)]
        let timeout: Task<Void, Never>
    }

    private var pendingSyncs: [SyncKey: PendingSync] = [:]
    /// How many synchronizations are in flight: tests wait on it.
    var pendingSyncCount: Int { pendingSyncs.count }
    static let syncJitter: Duration = .milliseconds(500)
    static let syncTimeout: Duration = .milliseconds(400)
    /// Messages kept per synchronization; older ones give way.
    static let syncQueueLimit = 8

    /// A data message from a peer whose counter a cache-and-sync key must learn first: kept, and the peer asked, after
    /// a random wait, with a MsgCounterSyncReq; the messages are dropped if no answer comes in time (Core §4.18.5).
    private func awaitSync(_ message: Message, session: SessionInfo, candidate: Groups.Candidate) async {
        guard let fabric = session.fabricIndex else { return }
        let key = SyncKey(fabric: fabric, peer: session.peerNodeID, sessionID: session.localSessionID)
        if pendingSyncs[key] != nil {
            pendingSyncs[key]?.queued.append((message, session))
            if let count = pendingSyncs[key]?.queued.count, count > Self.syncQueueLimit { pendingSyncs[key]?.queued.removeFirst() }
            return
        }
        let challenge = MatterCrypto.random(8), exchangeID = allocateExchangeID()
        let jitter = reliability.scaled(Self.syncJitter * Double.random(in: 0...1)), timeout = reliability.scaled(Self.syncTimeout)
        let task = Task { [weak self] in
            guard (try? await Task.sleep(for: jitter)) != nil else { return }
            await self?.sendSync(.messageCounterSyncRequest, challenge, to: session.peerNodeID, exchangeID: exchangeID, initiator: true,
                                 candidate: candidate, peer: session.peerAddress)
            guard (try? await Task.sleep(for: timeout)) != nil else { return }
            // Cancelled when the answer came; otherwise the waiting messages are dropped.
            await self?.dropSync(key)
        }
        pendingSyncs[key] = PendingSync(challenge: challenge, exchangeID: exchangeID, queued: [(message, session)], timeout: task)
    }

    private func dropSync(_ key: SyncKey) { pendingSyncs[key] = nil }

    /// A MsgCounterSyncReq is answered with this node's data counter; a MsgCounterSyncRsp matching the request in
    /// flight teaches the peer's, and the messages that waited on it are processed in order.
    private func counterSync(_ message: Message, from source: NodeID, candidate: Groups.Candidate, sessionID: UInt16, peer: PeerAddress) async {
        guard let groups, message.payloadHeader.protocolID == .secureChannel else { return }
        switch SecureChannelOpcode(rawValue: message.payloadHeader.opcode) {
        case .messageCounterSyncRequest:
            guard message.payloadHeader.isInitiator, message.payload.count == 8 else { return }
            var payload: [UInt8] = []
            payload.appendLittleEndian(await groups.dataCounter)
            await sendSync(.messageCounterSyncResponse, payload + message.payload, to: source, exchangeID: message.payloadHeader.exchangeID,
                           initiator: false, acknowledging: message.header.counter, candidate: candidate, peer: peer)
        case .messageCounterSyncResponse:
            let key = SyncKey(fabric: candidate.fabric, peer: source, sessionID: sessionID)
            guard message.payload.count == 12, let pending = pendingSyncs[key], pending.exchangeID == message.payloadHeader.exchangeID,
                  MatterCrypto.equal(Array(message.payload[4...]), pending.challenge) else { return }
            pending.timeout.cancel()
            pendingSyncs[key] = nil
            var reader = ByteReader(message.payload, truncated: MessageError.truncated)
            guard let counter = try? reader.read(UInt32.self) else { return }
            await groups.synchronize(fabric: candidate.fabric, source: source, counter: counter)
            for (queued, session) in pending.queued
            where await groups.check(queued.header.counter, fabric: candidate.fabric, source: source, control: false) == .new {
                dispatchGroup(queued, session: session)
            }
        default:
            break
        }
    }

    /// An MCSP message to one node, under the group key being synchronized, with the C and P flags (Core §4.18.5).
    private func sendSync(_ opcode: SecureChannelOpcode, _ payload: [UInt8], to destination: NodeID, exchangeID: UInt16, initiator: Bool,
                          acknowledging acked: UInt32? = nil, candidate: Groups.Candidate, peer: PeerAddress) async {
        guard let groups, let source = await groups.nodeID(fabric: candidate.fabric) else { return }
        let payloadHeader = PayloadHeader(isInitiator: initiator, needsAck: true, ackedCounter: acked, opcode: opcode.rawValue,
                                          exchangeID: exchangeID, protocolID: .secureChannel)
        guard let frame = try? Message.groupFrame(payloadHeader: payloadHeader, payload: payload, destination: .node(destination),
                                                  source: source, counter: await groups.nextControlCounter(), control: true,
                                                  operationalKey: candidate.operationalKey) else { return }
        try? await transport.send(frame, to: peer)
    }

    private func handlerFinished(_ id: UInt64) { handlerTasks[id] = nil }

    private func noteReceived(_ message: Message, key: ExchangeKey) {
        guard message.payloadHeader.needsAck else { return }
        if let previous = exchanges[key]?.pendingAck, previous != message.header.counter {
            // Two reliable messages before this node replied: acknowledge the first one now.
            let earlier = previous
            Task { await self.sendStandaloneAck(key: key, counter: earlier) }
        }
        exchanges[key]?.pendingAck = message.header.counter
        scheduleStandaloneAck(key)
    }
}

/// One conversation with a peer (Core §4.10).
public actor Exchange {
    /// The message layer the exchange runs on.
    public nonisolated let layer: MessageLayer
    let key: MessageLayer.ExchangeKey
    /// The session when the exchange started: its kind, ids and peer do not change.
    public nonisolated let initialSession: SessionInfo
    public nonisolated let protocolID: ProtocolID
    private var queue: [Message] = []
    private var waiter: CheckedContinuation<Message, Error>?
    private var timeoutTask: Task<Void, Never>?
    /// Identifies the current wait, so a stale timeout does not end a later one.
    private var waitID: UInt64 = 0
    private var failure: Error?

    init(layer: MessageLayer, key: MessageLayer.ExchangeKey, session: SessionInfo, protocolID: ProtocolID) {
        self.layer = layer
        self.key = key
        initialSession = session
        self.protocolID = protocolID
    }

    public nonisolated var exchangeID: UInt16 { key.exchangeID }
    public nonisolated var isInitiator: Bool { key.isInitiator }

    /// The session as it is now: a PASE session may since have been bound to a fabric.
    public var session: SessionInfo {
        get async { await layer.session(initialSession.localSessionID) ?? initialSession }
    }

    public func send(_ opcode: UInt8, _ payload: [UInt8] = [], protocolID: ProtocolID? = nil) async throws {
        try await layer.send(on: key, protocolID: protocolID ?? self.protocolID, opcode: opcode, payload: payload)
    }

    public func send(_ opcode: SecureChannelOpcode, _ payload: [UInt8] = []) async throws {
        try await send(opcode.rawValue, payload, protocolID: .secureChannel)
    }

    public func sendStatus(_ report: StatusReport) async throws {
        try await send(.statusReport, report.encoded)
    }

    /// The next message, waiting at most `timeout`; by default the peer's retransmission schedule plus time to work.
    public func receive(timeout: Duration? = nil) async throws -> Message {
        // Work out the timeout first: a message delivered during this await lands in the queue checked below.
        let timeout = if let timeout { timeout } else { await layer.responseTimeout(for: key) }
        if !queue.isEmpty { return queue.removeFirst() }
        if let failure { throw failure }
        waitID &+= 1
        let id = waitID
        return try await withCheckedThrowingContinuation { continuation in
            waiter = continuation
            timeoutTask = Task { [weak self] in
                guard (try? await Task.sleep(for: timeout)) != nil else { return }
                await self?.resume(id, with: .failure(ExchangeError.timeout))
            }
        }
    }

    /// Closes the exchange; outstanding acknowledgements are flushed.
    public func close() async {
        await layer.close(key)
        fail(ExchangeError.closed)
    }

    func deliver(_ message: Message) {
        if waiter != nil {
            resume(waitID, with: .success(message))
        } else {
            queue.append(message)
        }
    }

    func fail(_ error: Error) {
        if failure == nil { failure = error }
        resume(waitID, with: .failure(error))
    }

    private func resume(_ id: UInt64, with result: Result<Message, Error>) {
        guard id == waitID, let waiter else { return }
        self.waiter = nil
        timeoutTask?.cancel()
        timeoutTask = nil
        waiter.resume(with: result)
    }
}
