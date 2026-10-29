import Foundation
import Testing
@testable import Matter

struct MessageCodecTests {
    @Test func roundTripsHeaders() throws {
        let header = MessageHeader(sessionID: 0x1234, counter: 0xDEADBEEF, source: 0x0102030405060708, destination: .group(0xABCD))
        let (decoded, length) = try MessageHeader.decode(header.encoded)
        #expect(decoded == header)
        #expect(length == header.encoded.count)

        let payloadHeader = PayloadHeader(isInitiator: true, needsAck: true, ackedCounter: 42, opcode: 0x20, exchangeID: 7,
                                          protocolID: .secureChannel, vendorID: 0xFFF1)
        let (decodedPayload, _) = try PayloadHeader.decode(payloadHeader.encoded)
        #expect(decodedPayload == payloadHeader)
    }

    @Test func sealsAndOpensFrames() throws {
        let key = try AESCCM(key: MatterCrypto.random(16))
        let message = Message(header: MessageHeader(sessionID: 9, counter: 100),
                              payloadHeader: PayloadHeader(isInitiator: false, needsAck: true, opcode: 5, exchangeID: 3, protocolID: .interactionModel),
                              payload: [1, 2, 3])
        var frame = try message.sealedFrame(key: key, nonceSourceNodeID: 77)
        let (header, length) = try MessageHeader.decode(frame)
        let opened = try Message.open(frame: frame, header: header, headerLength: length, key: key, nonceSourceNodeID: 77)
        #expect(opened.payload == [1, 2, 3])
        #expect(opened.payloadHeader == message.payloadHeader)
        #expect(throws: MessageError.authenticationFailed) {
            try Message.open(frame: frame, header: header, headerLength: length, key: key, nonceSourceNodeID: 78)
        }
        // The header is authenticated too.
        frame[4] ^= 1
        let (tampered, _) = try MessageHeader.decode(frame)
        #expect(throws: MessageError.authenticationFailed) {
            try Message.open(frame: frame, header: tampered, headerLength: length, key: key, nonceSourceNodeID: 77)
        }
    }

    @Test func rejectsReservedValues() {
        #expect(throws: MessageError.unsupportedVersion) { try MessageHeader.decode([0x10, 0, 0, 0, 0, 0, 0, 0]) }
        #expect(throws: MessageError.invalidDestination) { try MessageHeader.decode([0x03, 0, 0, 0, 0, 0, 0, 0]) }
        #expect(throws: MessageError.truncated) { try MessageHeader.decode([0x04, 0, 0, 0, 1, 0, 0, 0]) }
    }

    @Test func encodesStatusReports() throws {
        let report = StatusReport.sessionEstablished
        #expect(report.encoded == [0, 0, 0, 0, 0, 0, 0, 0])
        #expect(try StatusReport(decoding: StatusReport.invalidParameter.encoded) == .invalidParameter)
    }
}

struct ReceptionStateTests {
    /// Which of `counters`, in order, the state accepts.
    func accepted(_ counters: [UInt32], by state: MessageReceptionState) -> [Bool] {
        var state = state
        return counters.map { state.accept($0) }
    }

    @Test func strictWindowRejectsDuplicatesAndOldCounters() {
        // 67 is behind the 32-message window of 100; 0 is the synchronized maximum.
        #expect(accepted([1, 1, 5, 3, 3, 100, 68, 67, 0], by: MessageReceptionState(policy: .strict, synchronizedTo: 0))
            == [true, false, true, true, false, true, true, false, false])
    }

    @Test func rollingWindowAcceptsARestartedSender() {
        // Far behind (10) means the sender restarted.
        #expect(accepted([1000, 1000, 999, 999, 10, 11], by: MessageReceptionState(policy: .rolling))
            == [true, false, true, false, true, true])
        // Wrap-around counts as ahead.
        #expect(accepted([UInt32.max, 2], by: MessageReceptionState(policy: .rolling)) == [true, true])
    }
}

/// Echoes every message back on its exchange.
struct EchoHandler: ProtocolHandler {
    static let protocolID = ProtocolID(rawValue: 0xFFF0)

    func handle(_ exchange: Exchange, first message: Message) async {
        try? await exchange.send(message.payloadHeader.opcode, message.payload)
    }
}

/// Two message layers on a memory network: a commissionee with an open window and a commissioner.
struct Pair {
    let network = MemoryNetwork()
    let device: MessageLayer
    let controller: MessageLayer
    let attempts = Recorder<PASEError?>()

    static let passcode: UInt32 = 20202021

    init() async throws {
        device = MessageLayer(transport: await network.transport(named: "device"), reliability: .fast)
        controller = MessageLayer(transport: await network.transport(named: "controller"), reliability: .fast)
        let verifier = try PASEVerifier(passcode: Self.passcode)
        let attempts = attempts
        let context = PASE.ResponderContext(verifier: { verifier }, attempted: { await attempts.append($0) })
        try await device.register(SecureChannelServer(pase: context), for: .secureChannel)
        try await device.register(EchoHandler(), for: EchoHandler.protocolID)
        try await device.start()
        try await controller.start()
    }
}

extension ReliabilityParameters {
    /// MRP at a hundredth of its real timings.
    static var fast: ReliabilityParameters {
        var parameters = ReliabilityParameters()
        parameters.timeScale = 0.01
        return parameters
    }
}

actor Recorder<Value: Sendable> {
    private(set) var values: [Value] = []
    func append(_ value: Value) { values.append(value) }
}

struct PASETests {
    @Test func establishesASessionAndExchangesEncryptedMessages() async throws {
        let pair = try await Pair()
        let session = try await PASE.establish(with: .memory("device"), passcode: Pair.passcode, layer: pair.controller)
        #expect(session.kind == .pase)

        let exchange = try await pair.controller.newExchange(session: session.localSessionID, protocolID: EchoHandler.protocolID)
        try await exchange.send(1, Array("hello".utf8))
        let reply = try await exchange.receive()
        #expect(reply.payload == Array("hello".utf8))
        await exchange.close()

        // Both sides derived the same attestation challenge.
        let deviceSessions = await pair.device.sessions
        #expect(deviceSessions.map(\.attestationChallenge) == [session.attestationChallenge])
        #expect(await pair.attempts.values == [nil])
    }

    @Test func rejectsAWrongPasscode() async throws {
        let pair = try await Pair()
        // The commissioner sees the device's confirmation fail first, and tells the device.
        await #expect(throws: PASEError.confirmationFailed) {
            try await PASE.establish(with: .memory("device"), passcode: 20202022, layer: pair.controller)
        }
        try await eventually { await pair.attempts.values == [.rejected(.invalidParameter)] }
        #expect(await pair.device.sessions.isEmpty)
    }

    @Test func survivesLostDatagrams() async throws {
        let pair = try await Pair()
        // Drop every third datagram in each direction; MRP retransmits.
        let counter = Counter()
        await pair.network.setFilter { _, _, _ in counter.next() % 3 != 0 }
        let session = try await PASE.establish(with: .memory("device"), passcode: Pair.passcode, layer: pair.controller)
        let exchange = try await pair.controller.newExchange(session: session.localSessionID, protocolID: EchoHandler.protocolID)
        try await exchange.send(1, [42])
        #expect(try await exchange.receive().payload == [42])
    }

    @Test func failsAfterTheLastRetransmission() async throws {
        let pair = try await Pair()
        await pair.network.setFilter { from, _, _ in from != "controller" }
        await #expect(throws: ExchangeError.notAcknowledged) {
            try await PASE.establish(with: .memory("device"), passcode: Pair.passcode, layer: pair.controller)
        }
    }

    @Test func closesSessionsOnRequest() async throws {
        let pair = try await Pair()
        let session = try await PASE.establish(with: .memory("device"), passcode: Pair.passcode, layer: pair.controller)
        let exchange = try await pair.controller.newExchange(session: session.localSessionID, protocolID: .secureChannel)
        try await exchange.sendStatus(.closeSession)
        await exchange.close()
        try await eventually { await pair.device.sessions.isEmpty }
    }
}

final class Counter: @unchecked Sendable {
    private var value = 0
    private let lock = NSLock()
    func next() -> Int { lock.withLock { value += 1; return value } }
}

/// Waits for a condition, polling briefly; fails after `timeout`.
func eventually(timeout: Duration = .seconds(5), _ condition: @Sendable () async -> Bool) async throws {
    let deadline = ContinuousClock.now + timeout
    while ContinuousClock.now < deadline {
        if await condition() { return }
        try await Task.sleep(for: .milliseconds(5))
    }
    Issue.record("Condition not met within \(timeout)")
}
