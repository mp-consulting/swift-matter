import Crypto
import Logging

public enum CASEError: Error, Equatable, Sendable {
    case invalidMessage
    case noSharedRoot
    case invalidCertificate
    case invalidSignature
    case rejected(StatusReport)
}

/// Certificate Authenticated Session Establishment (Core §4.14.2): SIGMA with the fabrics' operational certificates.
public enum CASE {
    static let sigma2Nonce = Array("NCASE_Sigma2N".utf8)
    static let sigma3Nonce = Array("NCASE_Sigma3N".utf8)
    /// The resumption MICs' nonces (Core §4.14.2.3): both spell "Sigma" then "S1" or "S2".
    static let resume1Nonce = Array("NCASE_SigmaS1".utf8)
    static let resume2Nonce = Array("NCASE_SigmaS2".utf8)

    /// What resumes a CASE session (Core §4.14.2.2): its resumption id and shared secret, and whom it was with.
    public struct ResumptionTicket: Sendable, Equatable {
        public var id: [UInt8]
        var sharedSecret: [UInt8]
        public var peerNodeID: NodeID
        public var localNodeID: NodeID
        public var fabricIndex: FabricIndex?
        public var caseAuthenticatedTags: [UInt32]

        init(id: [UInt8], sharedSecret: [UInt8], session: SessionInfo) {
            self.id = id
            self.sharedSecret = sharedSecret
            peerNodeID = session.peerNodeID
            localNodeID = session.localNodeID
            fabricIndex = session.fabricIndex
            caseAuthenticatedTags = session.caseAuthenticatedTags
        }

        /// The same session's ticket under a new resumption id.
        func renewed(_ id: [UInt8]) -> ResumptionTicket {
            var next = self
            next.id = id
            return next
        }

        /// The ticket as the node stores it; a ticket without a fabric leaves field 4 out.
        var tlv: TLVElement {
            var fields: [TLVElement] = [
                .field(0, .bytes(id)), .field(1, .bytes(sharedSecret)), .field(2, .unsigned(peerNodeID)), .field(3, .unsigned(localNodeID)),
                .field(5, .array(caseAuthenticatedTags.map { TLVElement(.unsigned(UInt64($0))) })),
            ]
            if let fabricIndex { fields.append(.field(4, .unsigned(UInt64(fabricIndex)))) }
            return TLVElement(.structure(fields))
        }

        init(tlv: TLVValue) throws {
            let fields = try TLVStruct(tlv)
            id = try fields.bytes(0)
            sharedSecret = try fields.bytes(1)
            peerNodeID = try fields.uint(2)
            localNodeID = try fields.uint(3)
            fabricIndex = fields[4] == nil ? nil : try fields.uint(4, as: FabricIndex.self)
            caseAuthenticatedTags = try fields.elements(5).map { try narrow($0.value) }
        }
    }

    /// Installs a resumed session: its keys come from the ticket's secret and the new resumption id (Core §4.14.2.6.7),
    /// its identity from the ticket.
    static func installResumed(_ ticket: ResumptionTicket, initiatorRandom: [UInt8], newID: [UInt8], localSessionID: UInt16,
                               peerSessionID: UInt16, peer: PeerAddress, isInitiator: Bool, peerParameters: SessionParameters,
                               layer: MessageLayer) async throws -> SessionInfo {
        let keys = SessionKeys(secret: ticket.sharedSecret, salt: initiatorRandom + newID, info: Array("SessionResumptionKeys".utf8))
        let info = SessionInfo(kind: .case, localSessionID: localSessionID, peerSessionID: peerSessionID, fabricIndex: ticket.fabricIndex,
                               peerNodeID: ticket.peerNodeID, localNodeID: ticket.localNodeID, caseAuthenticatedTags: ticket.caseAuthenticatedTags,
                               attestationChallenge: keys.attestationChallenge, peerAddress: peer)
        return try await layer.addSecureSession(
            info: info, encryptKey: isInitiator ? keys.initiatorToResponder : keys.responderToInitiator,
            decryptKey: isInitiator ? keys.responderToInitiator : keys.initiatorToResponder, peerParameters: peerParameters)
    }

    /// A resumption key: S1RK, S2RK or the resumed session keys, from the shared secret, the initiator's random and a
    /// resumption id (Core §4.14.2.6).
    static func resumptionKey(_ ticket: ResumptionTicket, initiatorRandom: [UInt8], id: [UInt8], info: String) -> [UInt8] {
        MatterCrypto.kdf(key: ticket.sharedSecret, salt: initiatorRandom + id, info: Array(info.utf8), length: 16)
    }

    /// What one side presents: its certificates, its operational key, and the fabric's root and IPK.
    public struct Identity: Sendable {
        public var noc: MatterCertificate
        public var icac: MatterCertificate?
        public var rcac: MatterCertificate
        public var operationalKey: P256.Signing.PrivateKey
        public var ipk: [UInt8]
        public var fabricIndex: FabricIndex?

        public init(noc: MatterCertificate, icac: MatterCertificate?, rcac: MatterCertificate, operationalKey: P256.Signing.PrivateKey,
                    ipk: [UInt8], fabricIndex: FabricIndex? = nil) {
            self.noc = noc
            self.icac = icac
            self.rcac = rcac
            self.operationalKey = operationalKey
            self.ipk = ipk
            self.fabricIndex = fabricIndex
        }

        init(fabric: Fabric) throws {
            self.init(noc: fabric.operationalCertificate, icac: fabric.intermediateCertificate, rcac: fabric.rootCertificate,
                      operationalKey: try fabric.signingKey, ipk: fabric.ipk, fabricIndex: fabric.index)
        }
    }

    /// The TBS data both sides sign (sigma-2-tbsdata and sigma-3-tbsdata share their layout).
    static func tbsData(noc: MatterCertificate, icac: MatterCertificate?, ownKey: [UInt8], peerKey: [UInt8]) -> [UInt8] {
        var fields: [TLVElement] = [.field(1, .bytes(noc.tlvEncoded))]
        if let icac { fields.append(.field(2, .bytes(icac.tlvEncoded))) }
        fields += [.field(3, .bytes(ownKey)), .field(4, .bytes(peerKey))]
        return TLVEncoder.encode(.structure(fields))
    }

    /// The encrypted part of Sigma2 and Sigma3: certificates, the signature, and Sigma2's resumption id.
    static func tbeData(_ identity: Identity, signature: [UInt8], resumptionID: [UInt8]? = nil) -> [UInt8] {
        var fields: [TLVElement] = [.field(1, .bytes(identity.noc.tlvEncoded))]
        if let icac = identity.icac { fields.append(.field(2, .bytes(icac.tlvEncoded))) }
        fields.append(.field(3, .bytes(signature)))
        if let resumptionID { fields.append(.field(4, .bytes(resumptionID))) }
        return TLVEncoder.encode(.structure(fields))
    }

    /// S2K = KDF(shared secret, IPK || responder random || responder key || Hash(Msg1), "Sigma2") (Core §4.14.2.6).
    static func sigma2Key(_ shared: [UInt8], ipk: [UInt8], responderRandom: [UInt8], responderKey: [UInt8], msg1: [UInt8]) -> [UInt8] {
        MatterCrypto.kdf(key: shared, salt: ipk + responderRandom + responderKey + MatterCrypto.hash(msg1), info: Array("Sigma2".utf8), length: 16)
    }

    /// S3K = KDF(shared secret, IPK || Hash(Msg1 || Msg2), "Sigma3").
    static func sigma3Key(_ shared: [UInt8], ipk: [UInt8], msg1: [UInt8], msg2: [UInt8]) -> [UInt8] {
        MatterCrypto.kdf(key: shared, salt: ipk + MatterCrypto.hash(msg1 + msg2), info: Array("Sigma3".utf8), length: 16)
    }

    /// Derives the session keys from the transcript and installs the session in this node's direction.
    static func installSession(_ shared: [UInt8], ipk: [UInt8], transcript: [UInt8], isInitiator: Bool, info: SessionInfo,
                               peerParameters: SessionParameters, layer: MessageLayer) async throws -> SessionInfo {
        let keys = SessionKeys(secret: shared, salt: ipk + MatterCrypto.hash(transcript), info: PASE.sessionKeysInfo)
        var info = info
        info.attestationChallenge = keys.attestationChallenge
        return try await layer.addSecureSession(
            info: info, encryptKey: isInitiator ? keys.initiatorToResponder : keys.responderToInitiator,
            decryptKey: isInitiator ? keys.responderToInitiator : keys.initiatorToResponder, peerParameters: peerParameters)
    }

    /// Checks the peer's certificates and its signature over the TBS data; returns the peer's NOC.
    static func verifyPeer(_ tbe: TLVStruct, rcac: MatterCertificate, expectedFabricID: UInt64, ownKey: [UInt8], peerKey: [UInt8]) throws -> MatterCertificate {
        guard let noc = try? MatterCertificate(tlv: try tbe.bytes(1)) else { throw CASEError.invalidCertificate }
        let icac = try tbe[2]?.bytes.map { bytes -> MatterCertificate in
            guard let certificate = try? MatterCertificate(tlv: bytes) else { throw CASEError.invalidCertificate }
            return certificate
        }
        do {
            try CertificateChain.validate(noc: noc, icac: icac, rcac: rcac)
        } catch {
            throw CASEError.invalidCertificate
        }
        guard noc.fabricID == expectedFabricID else { throw CASEError.invalidCertificate }
        let signature = try tbe.bytes(3)
        guard let peerSignature = try? P256.Signing.ECDSASignature(rawRepresentation: signature),
              let peerSigningKey = try? noc.signingKey,
              peerSigningKey.isValidSignature(peerSignature, for: tbsData(noc: noc, icac: icac, ownKey: peerKey, peerKey: ownKey))
        else { throw CASEError.invalidSignature }
        return noc
    }

    static func sharedSecret(_ key: P256.KeyAgreement.PrivateKey, peer: [UInt8]) throws -> [UInt8] {
        let peerKey = try P256.KeyAgreement.PublicKey(x963Representation: peer)
        return try key.sharedSecretFromKeyAgreement(with: peerKey).withUnsafeBytes { Array($0) }
    }

    // MARK: - Responder

    /// Runs the responder on an unsecured exchange whose first message was Sigma1.
    static func respond(on exchange: Exchange, sigma1: Message, fabrics: FabricTable, resumptions: ResumptionStore, logger: Logger) async {
        do {
            try await runResponder(exchange, sigma1: sigma1, fabrics: fabrics, resumptions: resumptions)
        } catch let error as CASEError {
            logger.debug("CASE with \(exchange.initialSession.peerAddress) failed: \(error)")
            try? await exchange.sendStatus(error == .noSharedRoot ? .noSharedTrustRoots : .invalidParameter)
        } catch {
            logger.debug("CASE with \(exchange.initialSession.peerAddress) failed: \(error)")
            try? await exchange.sendStatus(.invalidParameter)
        }
    }

    private static func runResponder(_ exchange: Exchange, sigma1: Message, fabrics: FabricTable, resumptions: ResumptionStore) async throws {
        let layer = exchange.layer
        let msg1 = sigma1.payload
        let fields = try TLVStruct(decoding: msg1)
        let initiatorRandom = try fields.bytes(1)
        let initiatorSessionID = try fields.uint(2, as: UInt16.self)
        let destination = try fields.bytes(3)
        let initiatorKey = try fields.bytes(4)
        guard initiatorRandom.count == 32, initiatorSessionID != 0, destination.count == 32, initiatorKey.count == 65 else {
            throw CASEError.invalidMessage
        }
        // Resumption needs both its fields; a ticket that is unknown or whose MIC fails gets a full Sigma2 (Core §4.14.2.3).
        switch (fields[6]?.bytes, fields[7]?.bytes) {
        case (nil, nil): break
        case (let id?, let mic?):
            // A ticket resumes only while the fabric still has the identity it was issued under.
            if let ticket = await resumptions.take(id), await fabrics.fabric(ticket.fabricIndex ?? 0)?.nodeID == ticket.localNodeID,
               (try? AESCCM(key: resumptionKey(ticket, initiatorRandom: initiatorRandom, id: id, info: "Sigma1_Resume"))
                .open(mic, nonce: resume1Nonce)) != nil {
                try await resume(exchange, ticket: ticket, initiatorRandom: initiatorRandom, initiatorSessionID: initiatorSessionID,
                                 peerParameters: SessionParameters(tlv: fields[5]), resumptions: resumptions)
                return
            }
        default: throw CASEError.invalidMessage
        }
        guard let fabric = await fabrics.fabric(forDestination: destination, initiatorRandom: initiatorRandom) else {
            throw CASEError.noSharedRoot
        }
        let identity = try Identity(fabric: fabric)
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let ephemeralKey = Array(ephemeral.publicKey.x963Representation)
        let shared = try sharedSecret(ephemeral, peer: initiatorKey)
        let responderRandom = MatterCrypto.random(32)
        let localSessionID = await layer.allocateSessionID()

        let tbs2 = tbsData(noc: identity.noc, icac: identity.icac, ownKey: ephemeralKey, peerKey: initiatorKey)
        let signature = Array(try identity.operationalKey.signature(for: tbs2).rawRepresentation)
        let resumptionID = MatterCrypto.random(16)
        let tbe2 = tbeData(identity, signature: signature, resumptionID: resumptionID)
        let s2k = sigma2Key(shared, ipk: identity.ipk, responderRandom: responderRandom, responderKey: ephemeralKey, msg1: msg1)
        let encrypted2 = try AESCCM(key: s2k).seal(tbe2, nonce: sigma2Nonce)
        let msg2 = TLVEncoder.encode(.structure([
            .field(1, .bytes(responderRandom)), .field(2, .unsigned(UInt64(localSessionID))), .field(3, .bytes(ephemeralKey)),
            .field(4, .bytes(encrypted2)), .field(5, layer.parameters.tlv),
        ]))
        try await exchange.send(.sigma2, msg2)

        let sigma3 = try await exchange.receive()
        try PASE.expect(sigma3, .sigma3)
        let msg3 = sigma3.payload
        let encrypted3 = try TLVStruct(decoding: msg3).bytes(1)
        let s3k = sigma3Key(shared, ipk: identity.ipk, msg1: msg1, msg2: msg2)
        guard let tbe3 = try? TLVStruct(decoding: try AESCCM(key: s3k).open(encrypted3, nonce: sigma3Nonce)) else {
            throw CASEError.invalidMessage
        }
        let peer = try verifyPeer(tbe3, rcac: identity.rcac, expectedFabricID: fabric.fabricID, ownKey: ephemeralKey, peerKey: initiatorKey)

        let info = SessionInfo(kind: .case, localSessionID: localSessionID, peerSessionID: initiatorSessionID, fabricIndex: fabric.index,
                               peerNodeID: peer.nodeID ?? 0, localNodeID: fabric.nodeID, caseAuthenticatedTags: peer.caseAuthenticatedTags,
                               peerAddress: exchange.initialSession.peerAddress)
        _ = try await installSession(shared, ipk: identity.ipk, transcript: msg1 + msg2 + msg3, isInitiator: false, info: info,
                                     peerParameters: SessionParameters(tlv: fields[5]), layer: layer)
        await resumptions.put(ResumptionTicket(id: resumptionID, sharedSecret: shared, session: info))
        try await exchange.sendStatus(.sessionEstablished)
    }

    /// Answers a valid resumption with Sigma2_Resume and installs the resumed session once the initiator confirms it.
    private static func resume(_ exchange: Exchange, ticket: ResumptionTicket, initiatorRandom: [UInt8], initiatorSessionID: UInt16,
                               peerParameters: SessionParameters, resumptions: ResumptionStore) async throws {
        let layer = exchange.layer
        let newID = MatterCrypto.random(16)
        let localSessionID = await layer.allocateSessionID()
        let mic = try AESCCM(key: resumptionKey(ticket, initiatorRandom: initiatorRandom, id: newID, info: "Sigma2_Resume"))
            .seal([], nonce: resume2Nonce)
        try await exchange.send(.sigma2Resume, TLVEncoder.encode(.structure([
            .field(1, .bytes(newID)), .field(2, .bytes(mic)), .field(3, .unsigned(UInt64(localSessionID))), .field(4, layer.parameters.tlv),
        ])))
        // SigmaFinished comes from the initiator in a resumption.
        let finished = try await exchange.receive()
        guard finished.payloadHeader.opcode == SecureChannelOpcode.statusReport.rawValue,
              try StatusReport(decoding: finished.payload) == .sessionEstablished
        else { throw CASEError.invalidMessage }
        _ = try await installResumed(ticket, initiatorRandom: initiatorRandom, newID: newID, localSessionID: localSessionID,
                                     peerSessionID: initiatorSessionID, peer: exchange.initialSession.peerAddress, isInitiator: false,
                                     peerParameters: peerParameters, layer: layer)
        await resumptions.put(ticket.renewed(newID))
    }

    // MARK: - Initiator

    /// Establishes a CASE session with a node of the identity's fabric.
    public static func establish(with peer: PeerAddress, peerNodeID: NodeID, identity: Identity, layer: MessageLayer) async throws -> SessionInfo {
        try await establishResumable(with: peer, peerNodeID: peerNodeID, identity: identity, layer: layer).session
    }

    /// Establishes a CASE session, resuming a previous one when `ticket` is given and the peer still knows it; the
    /// returned ticket resumes this one.
    public static func establishResumable(with peer: PeerAddress, peerNodeID: NodeID, identity: Identity, layer: MessageLayer,
                                          ticket: ResumptionTicket? = nil) async throws -> (session: SessionInfo, ticket: ResumptionTicket) {
        let exchange = await layer.newUnsecuredExchange(to: peer, protocolID: .secureChannel)
        do {
            let result = try await initiate(exchange, peer: peer, peerNodeID: peerNodeID, identity: identity, layer: layer, ticket: ticket)
            await exchange.close()
            return result
        } catch {
            await exchange.close()
            throw error
        }
    }

    private static func initiate(_ exchange: Exchange, peer: PeerAddress, peerNodeID: NodeID, identity: Identity,
                                 layer: MessageLayer, ticket: ResumptionTicket?) async throws -> (session: SessionInfo, ticket: ResumptionTicket) {
        guard let fabricID = identity.noc.fabricID else { throw CASEError.invalidCertificate }
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let ephemeralKey = Array(ephemeral.publicKey.x963Representation)
        let initiatorRandom = MatterCrypto.random(32)
        let localSessionID = await layer.allocateSessionID()
        let destination = Fabric.destinationID(initiatorRandom: initiatorRandom, rootPublicKey: identity.rcac.publicKey,
                                               fabricID: fabricID, nodeID: peerNodeID, ipk: identity.ipk)
        var sigma1: [TLVElement] = [
            .field(1, .bytes(initiatorRandom)), .field(2, .unsigned(UInt64(localSessionID))), .field(3, .bytes(destination)),
            .field(4, .bytes(ephemeralKey)), .field(5, layer.parameters.tlv),
        ]
        if let ticket {
            let mic = try AESCCM(key: resumptionKey(ticket, initiatorRandom: initiatorRandom, id: ticket.id, info: "Sigma1_Resume"))
                .seal([], nonce: resume1Nonce)
            sigma1 += [.field(6, .bytes(ticket.id)), .field(7, .bytes(mic))]
        }
        let msg1 = TLVEncoder.encode(.structure(sigma1))
        try await exchange.send(.sigma1, msg1)

        let sigma2 = try await exchange.receive()
        if let ticket, sigma2.payloadHeader.opcode == SecureChannelOpcode.sigma2Resume.rawValue {
            return try await resumed(exchange, sigma2Resume: sigma2, ticket: ticket, initiatorRandom: initiatorRandom,
                                     localSessionID: localSessionID, peer: peer, layer: layer)
        }
        do {
            try PASE.expect(sigma2, .sigma2)
        } catch PASEError.rejected(let report) {
            throw CASEError.rejected(report)
        }
        let msg2 = sigma2.payload
        let fields = try TLVStruct(decoding: msg2)
        let responderRandom = try fields.bytes(1)
        let peerSessionID = try fields.uint(2, as: UInt16.self)
        let responderKey = try fields.bytes(3)
        guard peerSessionID != 0 else { throw CASEError.invalidMessage }
        let shared = try sharedSecret(ephemeral, peer: responderKey)
        let s2k = sigma2Key(shared, ipk: identity.ipk, responderRandom: responderRandom, responderKey: responderKey, msg1: msg1)
        guard let tbe2 = try? TLVStruct(decoding: try AESCCM(key: s2k).open(try fields.bytes(4), nonce: sigma2Nonce)) else {
            throw CASEError.invalidMessage
        }
        let peerNOC = try verifyPeer(tbe2, rcac: identity.rcac, expectedFabricID: fabricID, ownKey: ephemeralKey, peerKey: responderKey)
        guard peerNOC.nodeID == peerNodeID, let resumptionID = tbe2[4]?.bytes, resumptionID.count == 16 else {
            throw CASEError.invalidCertificate
        }

        let tbs3 = tbsData(noc: identity.noc, icac: identity.icac, ownKey: ephemeralKey, peerKey: responderKey)
        let tbe3 = tbeData(identity, signature: Array(try identity.operationalKey.signature(for: tbs3).rawRepresentation))
        let s3k = sigma3Key(shared, ipk: identity.ipk, msg1: msg1, msg2: msg2)
        let msg3 = TLVEncoder.encode(.structure([.field(1, .bytes(try AESCCM(key: s3k).seal(tbe3, nonce: sigma3Nonce)))]))
        try await exchange.send(.sigma3, msg3)

        let finished = try await exchange.receive()
        guard finished.payloadHeader.protocolID == .secureChannel,
              finished.payloadHeader.opcode == SecureChannelOpcode.statusReport.rawValue
        else { throw CASEError.invalidMessage }
        let status = try StatusReport(decoding: finished.payload)
        guard status == .sessionEstablished else { throw CASEError.rejected(status) }

        let info = SessionInfo(kind: .case, localSessionID: localSessionID, peerSessionID: peerSessionID, fabricIndex: identity.fabricIndex,
                               peerNodeID: peerNodeID, localNodeID: identity.noc.nodeID ?? 0,
                               caseAuthenticatedTags: peerNOC.caseAuthenticatedTags, peerAddress: peer)
        let session = try await installSession(shared, ipk: identity.ipk, transcript: msg1 + msg2 + msg3, isInitiator: true, info: info,
                                               peerParameters: SessionParameters(tlv: fields[5]), layer: layer)
        return (session, ResumptionTicket(id: resumptionID, sharedSecret: shared, session: session))
    }

    /// Checks Sigma2_Resume, confirms with SigmaFinished and installs the resumed session.
    private static func resumed(_ exchange: Exchange, sigma2Resume: Message, ticket: ResumptionTicket, initiatorRandom: [UInt8],
                                localSessionID: UInt16, peer: PeerAddress, layer: MessageLayer) async throws -> (session: SessionInfo, ticket: ResumptionTicket) {
        let fields = try TLVStruct(decoding: sigma2Resume.payload)
        let newID = try fields.bytes(1)
        let peerSessionID = try fields.uint(3, as: UInt16.self)
        guard newID.count == 16, peerSessionID != 0,
              (try? AESCCM(key: resumptionKey(ticket, initiatorRandom: initiatorRandom, id: newID, info: "Sigma2_Resume"))
                .open(try fields.bytes(2), nonce: resume2Nonce)) != nil
        else { throw CASEError.invalidMessage }
        try await exchange.sendStatus(.sessionEstablished)
        let session = try await installResumed(ticket, initiatorRandom: initiatorRandom, newID: newID, localSessionID: localSessionID,
                                               peerSessionID: peerSessionID, peer: peer, isInitiator: true,
                                               peerParameters: SessionParameters(tlv: fields[4]), layer: layer)
        return (session, ticket.renewed(newID))
    }
}

/// The resumption tickets a responder keeps, most recent first: one per peer (its latest session), a bounded number of
/// them. With `storage` they outlive a restart, so controllers resume rather than run CASE again (Core §4.14.2.2).
public actor ResumptionStore {
    private var tickets: [CASE.ResumptionTicket] = []
    let capacity: Int
    private let storage: (any MatterStorage)?

    public init(capacity: Int = 32, storage: (any MatterStorage)? = nil) {
        self.capacity = capacity
        self.storage = storage
    }

    /// Reads the stored tickets.
    func load() async {
        guard let data = await storage?.value(for: StorageKey.resumptions), let list = try? TLVDecoder.decode(data).value.elements else { return }
        tickets = list.compactMap { try? CASE.ResumptionTicket(tlv: $0.value) }
    }

    func put(_ ticket: CASE.ResumptionTicket) async {
        // A peer's new session replaces its older ones: a busy controller does not crowd the others out.
        tickets.removeAll { $0.fabricIndex == ticket.fabricIndex && $0.peerNodeID == ticket.peerNodeID }
        tickets.insert(ticket, at: 0)
        if tickets.count > capacity { tickets.removeLast(tickets.count - capacity) }
        await save()
    }

    /// The ticket with this id, removed: a resumption id is used once.
    func take(_ id: [UInt8]) async -> CASE.ResumptionTicket? {
        guard let index = tickets.firstIndex(where: { MatterCrypto.equal($0.id, id) }) else { return nil }
        let ticket = tickets.remove(at: index)
        await save()
        return ticket
    }

    /// Forgets the tickets of a removed fabric.
    public func removeFabric(_ index: FabricIndex) async {
        tickets.removeAll { $0.fabricIndex == index }
        await save()
    }

    private func save() async {
        try? await storage?.setValue(TLVEncoder.encode(.array(tickets.map(\.tlv))), for: StorageKey.resumptions)
    }
}

/// Answers Sigma1 with the node's fabrics.
public struct CASEServer: CASEResponding {
    let fabrics: FabricTable
    let resumptions: ResumptionStore
    let logger: Logger

    public init(fabrics: FabricTable, resumptions: ResumptionStore = ResumptionStore(), logger: Logger = Logger(label: "matter.case")) {
        self.fabrics = fabrics
        self.resumptions = resumptions
        self.logger = logger
    }

    public func respond(on exchange: Exchange, sigma1: Message) async {
        await CASE.respond(on: exchange, sigma1: sigma1, fabrics: fabrics, resumptions: resumptions, logger: logger)
    }
}
