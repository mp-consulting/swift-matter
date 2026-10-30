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
    static func respond(on exchange: Exchange, sigma1: Message, fabrics: FabricTable, logger: Logger) async {
        do {
            try await runResponder(exchange, sigma1: sigma1, fabrics: fabrics)
        } catch let error as CASEError {
            logger.debug("CASE with \(exchange.initialSession.peerAddress) failed: \(error)")
            try? await exchange.sendStatus(error == .noSharedRoot ? .noSharedTrustRoots : .invalidParameter)
        } catch {
            logger.debug("CASE with \(exchange.initialSession.peerAddress) failed: \(error)")
            try? await exchange.sendStatus(.invalidParameter)
        }
    }

    private static func runResponder(_ exchange: Exchange, sigma1: Message, fabrics: FabricTable) async throws {
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
        // Resumption is not offered: a Sigma1 with resumption fields gets a full Sigma2 (Core §4.14.2.3).
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
        let tbe2 = tbeData(identity, signature: signature, resumptionID: MatterCrypto.random(16))
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
        try await exchange.sendStatus(.sessionEstablished)
    }

    // MARK: - Initiator

    /// Establishes a CASE session with a node of the identity's fabric.
    public static func establish(with peer: PeerAddress, peerNodeID: NodeID, identity: Identity, layer: MessageLayer) async throws -> SessionInfo {
        let exchange = await layer.newUnsecuredExchange(to: peer, protocolID: .secureChannel)
        do {
            let session = try await initiate(exchange, peer: peer, peerNodeID: peerNodeID, identity: identity, layer: layer)
            await exchange.close()
            return session
        } catch {
            await exchange.close()
            throw error
        }
    }

    private static func initiate(_ exchange: Exchange, peer: PeerAddress, peerNodeID: NodeID, identity: Identity,
                                 layer: MessageLayer) async throws -> SessionInfo {
        guard let fabricID = identity.noc.fabricID else { throw CASEError.invalidCertificate }
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let ephemeralKey = Array(ephemeral.publicKey.x963Representation)
        let initiatorRandom = MatterCrypto.random(32)
        let localSessionID = await layer.allocateSessionID()
        let destination = Fabric.destinationID(initiatorRandom: initiatorRandom, rootPublicKey: identity.rcac.publicKey,
                                               fabricID: fabricID, nodeID: peerNodeID, ipk: identity.ipk)
        let msg1 = TLVEncoder.encode(.structure([
            .field(1, .bytes(initiatorRandom)), .field(2, .unsigned(UInt64(localSessionID))), .field(3, .bytes(destination)),
            .field(4, .bytes(ephemeralKey)), .field(5, layer.parameters.tlv),
        ]))
        try await exchange.send(.sigma1, msg1)

        let sigma2 = try await exchange.receive()
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
        guard peerNOC.nodeID == peerNodeID else { throw CASEError.invalidCertificate }

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
        return try await installSession(shared, ipk: identity.ipk, transcript: msg1 + msg2 + msg3, isInitiator: true, info: info,
                                        peerParameters: SessionParameters(tlv: fields[5]), layer: layer)
    }
}

/// Answers Sigma1 with the node's fabrics.
public struct CASEServer: CASEResponding {
    let fabrics: FabricTable
    let logger: Logger

    public init(fabrics: FabricTable, logger: Logger = Logger(label: "matter.case")) {
        self.fabrics = fabrics
        self.logger = logger
    }

    public func respond(on exchange: Exchange, sigma1: Message) async {
        await CASE.respond(on: exchange, sigma1: sigma1, fabrics: fabrics, logger: logger)
    }
}
