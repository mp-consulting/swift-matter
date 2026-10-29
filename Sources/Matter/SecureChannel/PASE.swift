import Logging

/// The passcode verifier of an open commissioning window, as PASE uses it.
public struct PASEVerifier: Sendable {
    public var verifier: SPAKE2Plus.Verifier
    public var salt: [UInt8]
    public var iterations: Int

    public init(verifier: SPAKE2Plus.Verifier, salt: [UInt8], iterations: Int) {
        self.verifier = verifier
        self.salt = salt
        self.iterations = iterations
    }

    /// A verifier for a passcode, with a random salt.
    public init(passcode: UInt32, iterations: Int = 1000, salt: [UInt8] = MatterCrypto.random(32)) throws {
        self.init(verifier: try SPAKE2Plus.verifier(passcode: passcode, salt: salt, iterations: iterations), salt: salt,
                  iterations: iterations)
    }
}

public enum PASEError: Error, Equatable, Sendable {
    case invalidMessage
    case rejected(StatusReport)
    case confirmationFailed
    case noCommissioningWindow
}

/// Passcode-Authenticated Session Establishment (Core §4.14.1).
public enum PASE {
    static let sessionKeysInfo = Array("SessionKeys".utf8)

    // MARK: - Responder (the commissionee)

    /// What the responder needs from its node.
    public struct ResponderContext: Sendable {
        /// The open window's verifier, or nil when commissioning is closed.
        public var verifier: @Sendable () async -> PASEVerifier?
        /// Called after each failed attempt, and after a success with nil.
        public var attempted: @Sendable (_ failure: PASEError?) async -> Void

        public init(verifier: @escaping @Sendable () async -> PASEVerifier?,
                    attempted: @escaping @Sendable (PASEError?) async -> Void) {
            self.verifier = verifier
            self.attempted = attempted
        }
    }

    /// Runs the responder side on an unsecured exchange whose first message was PBKDFParamRequest.
    static func respond(on exchange: Exchange, request: Message, context: ResponderContext, logger: Logger) async {
        do {
            try await runResponder(exchange, request: request, context: context)
            await context.attempted(nil)
        } catch let error as PASEError {
            logger.debug("PASE with \(exchange.initialSession.peerAddress) failed: \(error)")
            try? await exchange.sendStatus(.invalidParameter)
            await context.attempted(error)
        } catch {
            logger.debug("PASE with \(exchange.initialSession.peerAddress) failed: \(error)")
            await context.attempted(.invalidMessage)
        }
    }

    private static func runResponder(_ exchange: Exchange, request: Message, context: ResponderContext) async throws {
        let layer = exchange.layer
        guard let window = await context.verifier() else { throw PASEError.noCommissioningWindow }
        let fields = try TLVStruct(decoding: request.payload)
        let initiatorRandom = try fields.bytes(1)
        let initiatorSessionID = try fields.uint(2, as: UInt16.self)
        guard initiatorRandom.count == 32, try fields.uint(3) == 0 else { throw PASEError.invalidMessage }
        let hasParameters = try fields.bool(4)
        let peerParameters = SessionParameters(tlv: fields[5])

        let localSessionID = await layer.allocateSessionID()
        let response: [TLVElement] = [
            .field(1, .bytes(initiatorRandom)), .field(2, .bytes(MatterCrypto.random(32))),
            .field(3, .unsigned(UInt64(localSessionID))),
            .field(4, .structure(hasParameters ? [] : [
                .field(1, .unsigned(UInt64(window.iterations))), .field(2, .bytes(window.salt)),
            ])),
            .field(5, layer.parameters.tlv),
        ]
        let responsePayload = TLVEncoder.encode(.structure(response))
        try await exchange.send(.pbkdfParamResponse, responsePayload)

        let pake1 = try await exchange.receive()
        try expect(pake1, .pake1)
        let pA = try TLVStruct(decoding: pake1.payload).bytes(1)
        let spake = try SPAKE2Plus.VerifierSession(context: transcriptContext(request.payload, responsePayload),
                                                   verifier: window.verifier)
        let keys = try spake.keys(proverShare: pA)
        try await exchange.send(.pake2, TLVEncoder.encode(.structure([.field(1, .bytes(spake.share)), .field(2, .bytes(keys.confirmationB))])))

        let pake3 = try await exchange.receive()
        try expect(pake3, .pake3)
        let cA = try TLVStruct(decoding: pake3.payload).bytes(1)
        guard MatterCrypto.equal(cA, keys.confirmationA) else { throw PASEError.confirmationFailed }

        try await installSession(keys.sharedSecret, isInitiator: false, localSessionID: localSessionID, peerSessionID: initiatorSessionID,
                                 peer: exchange.initialSession.peerAddress, peerParameters: peerParameters, layer: layer)
        try await exchange.sendStatus(.sessionEstablished)
    }

    /// Context = Hash(prefix || PBKDFParamRequest || PBKDFParamResponse) (Core §3.10.3).
    static func transcriptContext(_ request: [UInt8], _ response: [UInt8]) -> [UInt8] {
        MatterCrypto.hash(SPAKE2Plus.contextPrefix + request + response)
    }

    /// Derives the session keys from Ke and installs the session, keys in this node's direction (Core §4.14.1.2).
    @discardableResult
    static func installSession(_ sharedSecret: [UInt8], isInitiator: Bool, localSessionID: UInt16, peerSessionID: UInt16,
                               peer: PeerAddress, peerParameters: SessionParameters, layer: MessageLayer) async throws -> SessionInfo {
        let keys = SessionKeys(secret: sharedSecret, salt: [], info: sessionKeysInfo)
        let info = SessionInfo(kind: .pase, localSessionID: localSessionID, peerSessionID: peerSessionID,
                               attestationChallenge: keys.attestationChallenge, peerAddress: peer)
        return try await layer.addSecureSession(
            info: info, encryptKey: isInitiator ? keys.initiatorToResponder : keys.responderToInitiator,
            decryptKey: isInitiator ? keys.responderToInitiator : keys.initiatorToResponder, peerParameters: peerParameters)
    }

    static func expect(_ message: Message, _ opcode: SecureChannelOpcode) throws {
        guard message.payloadHeader.protocolID == .secureChannel else { throw PASEError.invalidMessage }
        if message.payloadHeader.opcode == SecureChannelOpcode.statusReport.rawValue {
            throw PASEError.rejected(try StatusReport(decoding: message.payload))
        }
        guard message.payloadHeader.opcode == opcode.rawValue else { throw PASEError.invalidMessage }
    }

    // MARK: - Initiator (the commissioner)

    /// Establishes a PASE session with a commissionee, returning it.
    public static func establish(with peer: PeerAddress, passcode: UInt32, layer: MessageLayer) async throws -> SessionInfo {
        let exchange = await layer.newUnsecuredExchange(to: peer, protocolID: .secureChannel)
        let localSessionID = await layer.allocateSessionID()
        let requestPayload = TLVEncoder.encode(.structure([
            .field(1, .bytes(MatterCrypto.random(32))), .field(2, .unsigned(UInt64(localSessionID))), .field(3, .unsigned(0)),
            .field(4, .bool(false)), .field(5, layer.parameters.tlv),
        ]))
        do {
            let session = try await initiate(exchange, localSessionID: localSessionID, requestPayload: requestPayload, peer: peer,
                                             passcode: passcode, layer: layer)
            await exchange.close()
            return session
        } catch {
            await exchange.close()
            throw error
        }
    }

    private static func initiate(_ exchange: Exchange, localSessionID: UInt16, requestPayload: [UInt8], peer: PeerAddress,
                                 passcode: UInt32, layer: MessageLayer) async throws -> SessionInfo {
        try await exchange.send(.pbkdfParamRequest, requestPayload)

        let response = try await exchange.receive()
        try expect(response, .pbkdfParamResponse)
        let fields = try TLVStruct(decoding: response.payload)
        let peerSessionID = try fields.uint(3, as: UInt16.self)
        let parameters = try fields.structure(4)
        let iterations = try parameters.uint(1)
        let salt = try parameters.bytes(2)
        guard (16...32).contains(salt.count), let iterationCount = Int(exactly: iterations) else { throw PASEError.invalidMessage }

        let (w0, w1) = try SPAKE2Plus.proverValues(passcode: passcode, salt: salt, iterations: iterationCount)
        let spake = try SPAKE2Plus.Prover(context: transcriptContext(requestPayload, response.payload), w0: w0, w1: w1)
        try await exchange.send(.pake1, TLVEncoder.encode(.structure([.field(1, .bytes(spake.share))])))

        let pake2 = try await exchange.receive()
        try expect(pake2, .pake2)
        let pake2Fields = try TLVStruct(decoding: pake2.payload)
        let keys = try spake.keys(verifierShare: try pake2Fields.bytes(1))
        guard MatterCrypto.equal(try pake2Fields.bytes(2), keys.confirmationB) else {
            try? await exchange.sendStatus(.invalidParameter)
            throw PASEError.confirmationFailed
        }
        try await exchange.send(.pake3, TLVEncoder.encode(.structure([.field(1, .bytes(keys.confirmationA))])))

        let finished = try await exchange.receive()
        guard finished.payloadHeader.opcode == SecureChannelOpcode.statusReport.rawValue else { throw PASEError.invalidMessage }
        let status = try StatusReport(decoding: finished.payload)
        guard status == .sessionEstablished else { throw PASEError.rejected(status) }

        return try await installSession(keys.sharedSecret, isInitiator: true, localSessionID: localSessionID, peerSessionID: peerSessionID,
                                        peer: peer, peerParameters: SessionParameters(tlv: fields[5]), layer: layer)
    }
}

/// The Secure Channel protocol's unsolicited messages: PASE and CASE establishment, and CloseSession.
public struct SecureChannelServer: ProtocolHandler {
    let pase: PASE.ResponderContext
    let caseResponder: (any CASEResponding)?
    let logger: Logger

    public init(pase: PASE.ResponderContext, caseResponder: (any CASEResponding)? = nil,
                logger: Logger = Logger(label: "matter.securechannel")) {
        self.pase = pase
        self.caseResponder = caseResponder
        self.logger = logger
    }

    public func handle(_ exchange: Exchange, first message: Message) async {
        let session = exchange.initialSession
        switch SecureChannelOpcode(rawValue: message.payloadHeader.opcode) {
        case .pbkdfParamRequest where session.kind == .unsecured:
            await PASE.respond(on: exchange, request: message, context: pase, logger: logger)
        case .sigma1 where session.kind == .unsecured:
            await caseResponder?.respond(on: exchange, sigma1: message)
        case .statusReport where session.isSecure:
            // CloseSession (Core §4.11.1.4): the peer ends the session it sent this over.
            if let report = try? StatusReport(decoding: message.payload), report == .closeSession {
                await exchange.layer.removeSessions { $0.localSessionID == session.localSessionID }
            }
        default:
            break
        }
    }
}

/// The CASE responder, implemented with the fabric table.
public protocol CASEResponding: Sendable {
    func respond(on exchange: Exchange, sigma1: Message) async
}
