import Crypto
import Foundation

public enum CommissioningError: Error, Equatable, Sendable {
    case attestationFailed(AttestationFailure)
    case commandFailed(String, UInt8)
    case unexpectedResponse(String)
}

/// A commissioner with its own fabric (Core §5.5): it verifies a commissionee's attestation, issues it an operational
/// certificate and completes commissioning over CASE. Tests and tools use it as a controller.
public actor Commissioner {
    public nonisolated let layer: MessageLayer
    public nonisolated let client: InteractionClient
    public let fabricID: UInt64
    public let nodeID: NodeID
    public let vendorID: UInt16
    let rootKey: P256.Signing.PrivateKey
    public let rootCertificate: MatterCertificate
    let operationalKey: P256.Signing.PrivateKey
    public private(set) var operationalCertificate: MatterCertificate
    let ipkEpochKey: [UInt8]
    let ipk: [UInt8]
    let trustStore: AttestationTrustStore
    private var nextSerial: UInt8 = 2

    /// How a commissionee's attestation is checked. `.verify` runs every check of Core §6.2.3.1 against `trustStore`
    /// (its PAA, the chain, the declaration); `.signaturesOnly` checks the device's own signatures with its DAC but
    /// trusts the chain and the declaration, for a device the person chose to add anyway (§5.5 step 10).
    public enum AttestationPolicy: Sendable { case verify, signaturesOnly }
    public let attestationPolicy: AttestationPolicy
    /// The compressed fabric id (Core §4.3.2.2), the first part of its nodes' operational instance names.
    public nonisolated let compressedFabricID: [UInt8]

    /// A node commissioned, and whose DAC it showed.
    public struct Commissioned: Sendable {
        public var session: SessionInfo
        public var vendorID: UInt16?
        public var productID: UInt16?
    }

    /// Sends AddNOC's ICAC field empty rather than leaving it out, as Apple Home does (`sendEmptyICAC()`, for tests).
    private var sendsEmptyICAC = false
    func sendEmptyICAC() { sendsEmptyICAC = true }

    public init(layer: MessageLayer, fabricID: UInt64 = 1, nodeID: NodeID = 0x0001_0000_0000_0001, vendorID: UInt16 = 0xFFF1,
                ipkEpochKey: [UInt8] = MatterCrypto.random(16), trustStore: AttestationTrustStore = .registry,
                attestationPolicy: AttestationPolicy = .verify) throws {
        self.layer = layer
        self.attestationPolicy = attestationPolicy
        client = InteractionClient(layer: layer)
        self.fabricID = fabricID
        self.nodeID = nodeID
        self.vendorID = vendorID
        self.ipkEpochKey = ipkEpochKey
        self.trustStore = trustStore
        rootKey = P256.Signing.PrivateKey()
        operationalKey = P256.Signing.PrivateKey()
        let rootPublic = Array(rootKey.publicKey.x963Representation)
        var root = MatterCertificate(serialNumber: [1], issuer: [.rcacID(1), .fabricID(fabricID)], notBefore: Self.issueTime, notAfter: 0,
                                     subject: [.rcacID(1), .fabricID(fabricID)], publicKey: rootPublic,
                                     basicConstraints: .init(isCA: true), keyUsage: [.keyCertSign, .crlSign],
                                     subjectKeyID: MatterCertificate.keyIdentifier(rootPublic), authorityKeyID: MatterCertificate.keyIdentifier(rootPublic))
        try root.sign(with: rootKey)
        rootCertificate = root
        operationalCertificate = try Self.noc(publicKey: Array(operationalKey.publicKey.x963Representation), nodeID: nodeID, serial: 1,
                                              fabricID: fabricID, root: root, rootKey: rootKey)
        compressedFabricID = Fabric.compressedFabricID(rootPublicKey: rootPublic, fabricID: fabricID)
        ipk = Fabric.operationalGroupKey(epochKey: ipkEpochKey, compressedFabricID: compressedFabricID)
    }

    /// What a commissioner needs to reach the nodes it commissioned again after a restart. It holds the fabric's root
    /// and operational private keys and its IPK epoch key: store it owner-only.
    public struct Snapshot: Codable, Sendable {
        public var fabricID: UInt64
        public var nodeID: NodeID
        public var vendorID: UInt16
        public var rootKey: [UInt8]
        public var rootCertificate: [UInt8]
        public var operationalKey: [UInt8]
        public var operationalCertificate: [UInt8]
        public var ipkEpochKey: [UInt8]
        public var nextSerial: UInt8
    }

    public var snapshot: Snapshot {
        Snapshot(fabricID: fabricID, nodeID: nodeID, vendorID: vendorID, rootKey: Array(rootKey.rawRepresentation),
                 rootCertificate: rootCertificate.tlvEncoded, operationalKey: Array(operationalKey.rawRepresentation),
                 operationalCertificate: operationalCertificate.tlvEncoded, ipkEpochKey: ipkEpochKey, nextSerial: nextSerial)
    }

    /// A commissioner restored from its snapshot, on the same fabric.
    public init(layer: MessageLayer, snapshot: Snapshot, trustStore: AttestationTrustStore = .registry,
                attestationPolicy: AttestationPolicy = .verify) throws {
        self.layer = layer
        self.attestationPolicy = attestationPolicy
        client = InteractionClient(layer: layer)
        fabricID = snapshot.fabricID
        nodeID = snapshot.nodeID
        vendorID = snapshot.vendorID
        ipkEpochKey = snapshot.ipkEpochKey
        self.trustStore = trustStore
        rootKey = try P256.Signing.PrivateKey(rawRepresentation: snapshot.rootKey)
        operationalKey = try P256.Signing.PrivateKey(rawRepresentation: snapshot.operationalKey)
        rootCertificate = try MatterCertificate(tlv: snapshot.rootCertificate)
        operationalCertificate = try MatterCertificate(tlv: snapshot.operationalCertificate)
        nextSerial = snapshot.nextSerial
        compressedFabricID = Fabric.compressedFabricID(rootPublicKey: Array(rootKey.publicKey.x963Representation), fabricID: snapshot.fabricID)
        ipk = Fabric.operationalGroupKey(epochKey: snapshot.ipkEpochKey, compressedFabricID: compressedFabricID)
    }

    /// The commissioner's CASE identity on its fabric.
    public var identity: CASE.Identity {
        CASE.Identity(noc: operationalCertificate, icac: nil, rcac: rootCertificate, operationalKey: operationalKey, ipk: ipk)
    }

    /// Registers the client for subscription reports.
    public func start() async throws {
        try await layer.register(client, for: .interactionModel)
        try await layer.start()
    }

    /// A NOC for a node of this fabric, signed by the root.
    func issue(publicKey: [UInt8], nodeID: NodeID) throws -> MatterCertificate {
        defer { nextSerial &+= 1 }
        return try Self.noc(publicKey: publicKey, nodeID: nodeID, serial: nextSerial, fabricID: fabricID, root: rootCertificate, rootKey: rootKey)
    }

    /// The certificates' start: a day ago, in Matter's epoch, so a device whose clock is a little behind accepts them.
    static var issueTime: UInt32 { MatterCertificate.matterSeconds(Date().addingTimeInterval(-86_400)) }

    static func noc(publicKey: [UInt8], nodeID: NodeID, serial: UInt8, fabricID: UInt64, root: MatterCertificate,
                    rootKey: P256.Signing.PrivateKey) throws -> MatterCertificate {
        var noc = MatterCertificate(serialNumber: [serial], issuer: root.subject, notBefore: Self.issueTime, notAfter: 0,
                                    subject: [.nodeID(nodeID), .fabricID(fabricID)], publicKey: publicKey,
                                    basicConstraints: .init(isCA: false), keyUsage: .digitalSignature, extendedKeyUsage: [2, 1],
                                    subjectKeyID: MatterCertificate.keyIdentifier(publicKey),
                                    authorityKeyID: MatterCertificate.keyIdentifier(root.publicKey))
        try noc.sign(with: rootKey)
        return noc
    }

    // MARK: - Commissioning

    /// Commissions the node at `peer` with its passcode, giving it `nodeID` on this fabric; returns the CASE session.
    public func commission(_ peer: PeerAddress, passcode: UInt32, nodeID: NodeID, peerParameters: SessionParameters? = nil) async throws -> SessionInfo {
        try await commissionNode(peer, passcode: passcode, nodeID: nodeID, peerParameters: peerParameters).session
    }

    /// Commissions the node at `peer`, as `commission`, and says whose device it is by its DAC. `peerParameters`: the
    /// MRP intervals of its commissionable record, for a sleepy device. `fabricLabel`: the name the person knows this
    /// controller by, which a commissioner SHALL set during commissioning (Core §5.5, step 13; §11.18.6.11); one another
    /// fabric of the node already uses gets a number after it.
    public func commissionNode(_ peer: PeerAddress, passcode: UInt32, nodeID: NodeID, peerParameters: SessionParameters? = nil,
                               fabricLabel: String? = nil) async throws -> Commissioned {
        let pase = try await PASE.establish(with: peer, passcode: passcode, layer: layer, peerParameters: peerParameters).localSessionID
        let general = GeneralCommissioningCluster.self
        let credentials = OperationalCredentialsCluster.self

        let armed = try await command(general.id, general.Command.armFailSafe, [.field(0, .unsigned(60)), .field(1, .unsigned(1))], session: pase)
        try check(armed, "ArmFailSafe")
        do {
            // The location the device can take (Core §11.10.6.4): an indoor-only device refuses IndoorOutdoor.
            let capability = (try? await client.read(endpoint: 0, cluster: general.id, attribute: general.Attribute.locationCapability,
                                                      session: pase))?.uint ?? 2
            let location = capability <= 2 ? capability : 2
            try check(try await command(general.id, general.Command.setRegulatoryConfig,
                                        [.field(0, .unsigned(location)), .field(1, .utf8("XX")), .field(2, .unsigned(2))], session: pase),
                      "SetRegulatoryConfig")

            // Device attestation (Core §6.2.3).
            let info = try await attestationInformation(session: pase)
            do {
                switch attestationPolicy {
                case .verify: try AttestationVerifier.verify(info, trusting: trustStore)
                case .signaturesOnly: try AttestationVerifier.verifySignatures(info)
                }
            } catch {
                throw CommissioningError.attestationFailed(error)
            }
            let challenge = info.challenge
            guard let parsedDAC = try? X509.parse(info.dac) else { throw CommissioningError.attestationFailed(.malformedCertificate("DAC")) }
            let dacKey = parsedDAC.publicKey

            // Operational credentials (Core §6.4.6).
            let csrNonce = MatterCrypto.random(32)
            let csr = try TLVStruct(try responseFields(await command(credentials.id, credentials.Command.csrRequest,
                                                                      [.field(0, .bytes(csrNonce))], session: pase)))
            let nocsrElements = try csr.bytes(0)
            try verify(try csr.bytes(1), of: nocsrElements + challenge, key: dacKey, .csrSignature)
            let nocsr = try TLVStruct(decoding: nocsrElements)
            guard try nocsr.bytes(2) == csrNonce else { throw CommissioningError.attestationFailed(.csrNonce) }
            let operationalKey = try CertificationRequest.publicKey(of: try nocsr.bytes(1))
            let noc = try issue(publicKey: Array(operationalKey.x963Representation), nodeID: nodeID)

            try check(try await command(credentials.id, credentials.Command.addTrustedRootCertificate,
                                        [.field(0, .bytes(rootCertificate.tlvEncoded))], session: pase), "AddTrustedRootCertificate")
            let added = try TLVStruct(try responseFields(await command(credentials.id, credentials.Command.addNoc, [
                .field(0, .bytes(noc.tlvEncoded)), .field(2, .bytes(ipkEpochKey)), .field(3, .unsigned(self.nodeID)),
                .field(4, .unsigned(UInt64(vendorID))),
            ] + (sendsEmptyICAC ? [.field(1, .bytes([]))] : []), session: pase)))
            let status = try added.uint(0, as: UInt8.self)
            guard status == 0 else { throw CommissioningError.commandFailed("AddNOC", status) }
            if let fabricLabel { try await setFabricLabel(fabricLabel, session: pase) }

            // Operational: CASE, then CommissioningComplete over it.
            let operational = try await CASE.establish(with: peer, peerNodeID: nodeID, identity: identity, layer: layer, peerParameters: peerParameters)
            try check(try await command(general.id, general.Command.commissioningComplete, [], session: operational.localSessionID),
                      "CommissioningComplete")
            return Commissioned(session: operational, vendorID: parsedDAC.vendorID, productID: parsedDAC.productID)
        } catch {
            // A commissioning that stops here expires the fail-safe at once (Core §5.5, "Commissioning Flows"; §11.10.7.2):
            // the device rolls back what it took and accepts a new PASE session in its window, rather than answering
            // BusyWithOtherAdmin until the 60 seconds are up.
            _ = try? await command(general.id, general.Command.armFailSafe, [.field(0, .unsigned(0)), .field(1, .unsigned(0))], session: pase)
            throw error
        }
    }

    /// UpdateFabricLabel over the session (its fabric is the accessing one): the label, else with " 2", " 3"… after it
    /// while another fabric of the node has it (LabelConflict, Core §11.18.6.11), at most 32 characters.
    private func setFabricLabel(_ label: String, session: UInt16) async throws {
        let credentials = OperationalCredentialsCluster.self
        for attempt in 1...9 {
            let suffix = attempt == 1 ? "" : " \(attempt)"
            let text = String(label.prefix(32 - suffix.count)) + suffix
            let result = try await command(credentials.id, credentials.Command.updateFabricLabel, [.field(0, .utf8(text))], session: session)
            if case .response(_, let fields) = result, fields[0]?.uint == OperationalCredentialsCluster.NodeOperationalCertStatusEnum.labelConflict {
                continue
            }
            return try check(result, "UpdateFabricLabel")
        }
        throw CommissioningError.commandFailed("UpdateFabricLabel", UInt8(OperationalCredentialsCluster.NodeOperationalCertStatusEnum.labelConflict))
    }

    /// Takes this fabric off a node over a CASE session with it (Operational Credentials' RemoveFabric, Core
    /// §11.18.6.12): the node forgets this controller and keeps every other. The node closes the session after it.
    public func removeFabric(session: UInt16) async throws {
        let credentials = OperationalCredentialsCluster.self
        let index = try await client.read(endpoint: 0, cluster: credentials.id, attribute: credentials.Attribute.currentFabricIndex, session: session)
        guard let fabricIndex = index.uint else { throw CommissioningError.unexpectedResponse("CurrentFabricIndex") }
        // NOCResponse: StatusCode 0 is OK (Core §11.18.6.10).
        try check(try await command(credentials.id, credentials.Command.removeFabric, [.field(0, .unsigned(fabricIndex))], session: session),
                  "RemoveFabric")
    }

    private func command(_ cluster: ClusterID, _ command: CommandID, _ fields: [TLVElement], session: UInt16) async throws -> InvokeResult {
        try await client.invoke(CommandPath(endpoint: 0, cluster: cluster, command: command), fields: .structure(fields), session: session)
    }

    private func responseFields(_ result: InvokeResult) throws -> TLVValue {
        switch result {
        case .response(_, let fields): return fields
        case .status(let status): throw CommissioningError.commandFailed("command", status.status.rawValue)
        }
    }

    /// Checks a command's success: a status, or a response whose ErrorCode (field 0) is 0.
    private func check(_ result: InvokeResult, _ name: String) throws {
        switch result {
        case .status(let status) where status.status == .success: return
        case .status(let status): throw CommissioningError.commandFailed(name, status.status.rawValue)
        case .response(_, let fields):
            let code = fields[0]?.uint ?? 0
            guard code == 0 else { throw CommissioningError.commandFailed(name, UInt8(truncatingIfNeeded: code)) }
        }
    }

    /// What a node answers for its attestation over `session` (PASE while commissioning, or CASE later, Core §6.2.3):
    /// its DAC and PAI, attestation elements and signature for a fresh nonce, and Basic Information's vendor and product.
    public func attestationInformation(session: UInt16) async throws -> AttestationInformation {
        let basic = BasicInformationCluster.self
        let credentials = OperationalCredentialsCluster.self
        let (reports, _) = try await client.read([basic.Attribute.vendorId, basic.Attribute.productId].map {
            AttributePath(endpoint: 0, cluster: basic.id, attribute: $0)
        }, session: session)
        func identifier(_ attribute: AttributeID) -> UInt16 {
            reports.values[ConcreteAttribute(0, basic.id, attribute)]?.uint.flatMap { UInt16(exactly: $0) } ?? 0
        }
        let dac = try await certificate(1, session: session)
        let pai = try await certificate(2, session: session)
        let nonce = MatterCrypto.random(32)
        let attestation = try TLVStruct(try responseFields(await command(credentials.id, credentials.Command.attestationRequest,
                                                                          [.field(0, .bytes(nonce))], session: session)))
        return AttestationInformation(dac: dac, pai: pai, elements: try attestation.bytes(0), signature: try attestation.bytes(1),
                                      challenge: await layer.session(session)?.attestationChallenge ?? [], nonce: nonce,
                                      vendorID: identifier(basic.Attribute.vendorId), productID: identifier(basic.Attribute.productId))
    }

    private func certificate(_ type: UInt64, session: UInt16) async throws -> [UInt8] {
        let credentials = OperationalCredentialsCluster.self
        let result = try await command(credentials.id, credentials.Command.certificateChainRequest, [.field(0, .unsigned(type))], session: session)
        return try TLVStruct(try responseFields(result)).bytes(0)
    }

    private func verify(_ signature: [UInt8], of message: [UInt8], key: P256.Signing.PublicKey, _ failure: AttestationFailure) throws {
        guard let parsed = try? P256.Signing.ECDSASignature(rawRepresentation: signature), key.isValidSignature(parsed, for: message) else {
            throw CommissioningError.attestationFailed(failure)
        }
    }
}
