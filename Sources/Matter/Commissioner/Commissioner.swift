import Crypto
import Foundation

public enum CommissioningError: Error, Equatable, Sendable {
    case attestationFailed(String)
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
    let operationalKey = P256.Signing.PrivateKey()
    public private(set) var operationalCertificate: MatterCertificate
    let ipkEpochKey: [UInt8]
    let ipk: [UInt8]
    let trustedPAAs: [[UInt8]]
    private var nextSerial: UInt8 = 2

    /// Sends AddNOC's ICAC field empty rather than leaving it out, as Apple Home does (`sendEmptyICAC()`, for tests).
    private var sendsEmptyICAC = false
    func sendEmptyICAC() { sendsEmptyICAC = true }

    public init(layer: MessageLayer, fabricID: UInt64 = 1, nodeID: NodeID = 0x0001_0000_0000_0001, vendorID: UInt16 = 0xFFF1,
                ipkEpochKey: [UInt8] = MatterCrypto.random(16), trustedPAAs: [[UInt8]] = [TestCredentials.paaCertificate]) throws {
        self.layer = layer
        client = InteractionClient(layer: layer)
        self.fabricID = fabricID
        self.nodeID = nodeID
        self.vendorID = vendorID
        self.ipkEpochKey = ipkEpochKey
        self.trustedPAAs = trustedPAAs
        rootKey = P256.Signing.PrivateKey()
        let rootPublic = Array(rootKey.publicKey.x963Representation)
        var root = MatterCertificate(serialNumber: [1], issuer: [.rcacID(1), .fabricID(fabricID)], notBefore: 0, notAfter: 0,
                                     subject: [.rcacID(1), .fabricID(fabricID)], publicKey: rootPublic,
                                     basicConstraints: .init(isCA: true), keyUsage: [.keyCertSign, .crlSign],
                                     subjectKeyID: MatterCertificate.keyIdentifier(rootPublic), authorityKeyID: MatterCertificate.keyIdentifier(rootPublic))
        try root.sign(with: rootKey)
        rootCertificate = root
        operationalCertificate = try Self.noc(publicKey: Array(operationalKey.publicKey.x963Representation), nodeID: nodeID, serial: 1,
                                              fabricID: fabricID, root: root, rootKey: rootKey)
        ipk = Fabric.operationalGroupKey(epochKey: ipkEpochKey,
                                         compressedFabricID: Fabric.compressedFabricID(rootPublicKey: rootPublic, fabricID: fabricID))
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

    static func noc(publicKey: [UInt8], nodeID: NodeID, serial: UInt8, fabricID: UInt64, root: MatterCertificate,
                    rootKey: P256.Signing.PrivateKey) throws -> MatterCertificate {
        var noc = MatterCertificate(serialNumber: [serial], issuer: root.subject, notBefore: 0, notAfter: 0,
                                    subject: [.nodeID(nodeID), .fabricID(fabricID)], publicKey: publicKey,
                                    basicConstraints: .init(isCA: false), keyUsage: .digitalSignature, extendedKeyUsage: [2, 1],
                                    subjectKeyID: MatterCertificate.keyIdentifier(publicKey),
                                    authorityKeyID: MatterCertificate.keyIdentifier(root.publicKey))
        try noc.sign(with: rootKey)
        return noc
    }

    // MARK: - Commissioning

    /// Commissions the node at `peer` with its passcode, giving it `nodeID` on this fabric; returns the CASE session.
    public func commission(_ peer: PeerAddress, passcode: UInt32, nodeID: NodeID) async throws -> SessionInfo {
        let pase = try await PASE.establish(with: peer, passcode: passcode, layer: layer).localSessionID
        let general = GeneralCommissioningCluster.self
        let credentials = OperationalCredentialsCluster.self

        let armed = try await command(general.id, general.Command.armFailSafe, [.field(0, .unsigned(60)), .field(1, .unsigned(1))], session: pase)
        try check(armed, "ArmFailSafe")
        try check(try await command(general.id, general.Command.setRegulatoryConfig,
                                    [.field(0, .unsigned(2)), .field(1, .utf8("XX")), .field(2, .unsigned(2))], session: pase), "SetRegulatoryConfig")

        // Device attestation (Core §6.2.3).
        let challenge = await layer.session(pase)?.attestationChallenge ?? []
        let dac = try await certificate(1, session: pase)
        let pai = try await certificate(2, session: pase)
        try verifyChain(dac: dac, pai: pai)
        let nonce = MatterCrypto.random(32)
        let attestation = try TLVStruct(try responseFields(await command(credentials.id, credentials.Command.attestationRequest,
                                                                          [.field(0, .bytes(nonce))], session: pase)))
        let elements = try attestation.bytes(0)
        let dacKey = try X509.parse(dac).publicKey
        try verify(try attestation.bytes(1), of: elements + challenge, key: dacKey, "attestation signature")
        let attestationElements = try TLVStruct(decoding: elements)
        guard try attestationElements.bytes(2) == nonce else { throw CommissioningError.attestationFailed("nonce") }
        let cdKey = try X509.parse(TestCredentials.cdSigningCertificate).publicKey
        guard let declaration = try? CertificationDeclaration.verify(try attestationElements.bytes(1), key: cdKey),
              let cdFields = try? TLVStruct(decoding: declaration)
        else { throw CommissioningError.attestationFailed("certification declaration") }
        // The declaration covers the DAC's vendor and product (Core §6.2.3.1).
        let parsedDAC = try X509.parse(dac)
        guard try cdFields.uint(1) == UInt64(parsedDAC.vendorID ?? 0),
              try cdFields.elements(2).contains(where: { $0.value.uint == UInt64(parsedDAC.productID ?? 0) })
        else { throw CommissioningError.attestationFailed("declaration does not cover the device") }

        // Operational credentials (Core §6.4.6).
        let csrNonce = MatterCrypto.random(32)
        let csr = try TLVStruct(try responseFields(await command(credentials.id, credentials.Command.csrRequest,
                                                                  [.field(0, .bytes(csrNonce))], session: pase)))
        let nocsrElements = try csr.bytes(0)
        try verify(try csr.bytes(1), of: nocsrElements + challenge, key: dacKey, "CSR signature")
        let nocsr = try TLVStruct(decoding: nocsrElements)
        guard try nocsr.bytes(2) == csrNonce else { throw CommissioningError.attestationFailed("CSR nonce") }
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

        // Operational: CASE, then CommissioningComplete over it.
        let operational = try await CASE.establish(with: peer, peerNodeID: nodeID, identity: identity, layer: layer)
        try check(try await command(general.id, general.Command.commissioningComplete, [], session: operational.localSessionID),
                  "CommissioningComplete")
        return operational
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

    private func certificate(_ type: UInt64, session: UInt16) async throws -> [UInt8] {
        let credentials = OperationalCredentialsCluster.self
        let result = try await command(credentials.id, credentials.Command.certificateChainRequest, [.field(0, .unsigned(type))], session: session)
        return try TLVStruct(try responseFields(result)).bytes(0)
    }

    /// DAC ← PAI ← a trusted PAA, vendor ids consistent (Core §6.2.3.1).
    private func verifyChain(dac: [UInt8], pai: [UInt8]) throws {
        guard X509.isSigned(dac, by: pai), trustedPAAs.contains(where: { X509.isSigned(pai, by: $0) }) else {
            throw CommissioningError.attestationFailed("certificate chain")
        }
        let dacVendor = try X509.parse(dac).vendorID, paiVendor = try X509.parse(pai).vendorID
        guard dacVendor != nil, paiVendor == nil || paiVendor == dacVendor else { throw CommissioningError.attestationFailed("vendor") }
    }

    private func verify(_ signature: [UInt8], of message: [UInt8], key: P256.Signing.PublicKey, _ what: String) throws {
        guard let parsed = try? P256.Signing.ECDSASignature(rawRepresentation: signature), key.isValidSignature(parsed, for: message) else {
            throw CommissioningError.attestationFailed(what)
        }
    }
}
