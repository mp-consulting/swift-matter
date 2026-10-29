import Crypto

/// A fabric this node belongs to (Core §2.5): its root of trust, this node's operational identity in it, and the
/// Identity Protection Key.
public struct Fabric: Sendable {
    public var index: FabricIndex
    public var rootCertificate: MatterCertificate
    public var intermediateCertificate: MatterCertificate?
    public var operationalCertificate: MatterCertificate
    /// The node's operational private key, raw.
    var operationalKey: [UInt8]
    /// The IPK epoch key from AddNOC; the operational IPK is derived from it.
    var ipkEpochKey: [UInt8]
    public var vendorID: UInt16
    public var label: String
    /// The CASE admin subject from AddNOC: the node id or CAT the commissioner gave Administer.
    public var caseAdminSubject: UInt64

    public var fabricID: UInt64 { operationalCertificate.fabricID ?? 0 }
    public var nodeID: NodeID { operationalCertificate.nodeID ?? 0 }
    public var rootPublicKey: [UInt8] { rootCertificate.publicKey }
    public var compressedFabricID: [UInt8] { Fabric.compressedFabricID(rootPublicKey: rootPublicKey, fabricID: fabricID) }
    /// The operational group key of IPK epoch key 0 (Core §4.14.2.6.1).
    public var ipk: [UInt8] { Fabric.operationalGroupKey(epochKey: ipkEpochKey, compressedFabricID: compressedFabricID) }

    var signingKey: P256.Signing.PrivateKey { get throws { try P256.Signing.PrivateKey(rawRepresentation: operationalKey) } }

    /// CompressedFabricIdentifier = KDF(root public key without its 0x04, fabric id big-endian, "CompressedFabric") (Core §4.3.2.2).
    public static func compressedFabricID(rootPublicKey: [UInt8], fabricID: UInt64) -> [UInt8] {
        var salt: [UInt8] = []
        salt.appendBigEndian(fabricID)
        return MatterCrypto.kdf(key: Array(rootPublicKey.dropFirst()), salt: salt, info: Array("CompressedFabric".utf8), length: 8)
    }

    /// OperationalGroupKey = KDF(epoch key, compressed fabric id, "GroupKey v1.0") (Core §4.17.2).
    public static func operationalGroupKey(epochKey: [UInt8], compressedFabricID: [UInt8]) -> [UInt8] {
        MatterCrypto.kdf(key: epochKey, salt: compressedFabricID, info: Array("GroupKey v1.0".utf8), length: 16)
    }

    /// destinationIdentifier = HMAC(IPK, initiatorRandom || root public key || fabric id LE || node id LE) (Core §4.14.2.4).
    public static func destinationID(initiatorRandom: [UInt8], rootPublicKey: [UInt8], fabricID: UInt64, nodeID: NodeID, ipk: [UInt8]) -> [UInt8] {
        var message = initiatorRandom + rootPublicKey
        message.appendLittleEndian(fabricID)
        message.appendLittleEndian(nodeID)
        return MatterCrypto.hmac(key: ipk, message: message)
    }

    func destinationID(initiatorRandom: [UInt8]) -> [UInt8] {
        Fabric.destinationID(initiatorRandom: initiatorRandom, rootPublicKey: rootPublicKey, fabricID: fabricID, nodeID: nodeID, ipk: ipk)
    }

    // MARK: - Storage

    var tlv: TLVValue {
        var fields: [TLVElement] = [
            .field(1, .unsigned(UInt64(index))), .field(2, .bytes(rootCertificate.tlvEncoded)),
            .field(4, .bytes(operationalCertificate.tlvEncoded)), .field(5, .bytes(operationalKey)), .field(6, .bytes(ipkEpochKey)),
            .field(7, .unsigned(UInt64(vendorID))), .field(8, .utf8(label)), .field(9, .unsigned(caseAdminSubject)),
        ]
        if let intermediateCertificate { fields.append(.field(3, .bytes(intermediateCertificate.tlvEncoded))) }
        return .structure(fields)
    }

    init(tlv value: TLVValue) throws {
        let fields = try TLVStruct(value)
        index = try fields.uint(1, as: UInt8.self)
        rootCertificate = try MatterCertificate(tlv: try fields.bytes(2))
        intermediateCertificate = try fields[3]?.bytes.map { try MatterCertificate(tlv: $0) }
        operationalCertificate = try MatterCertificate(tlv: try fields.bytes(4))
        operationalKey = try fields.bytes(5)
        ipkEpochKey = try fields.bytes(6)
        vendorID = try fields.uint(7, as: UInt16.self)
        label = try fields.string(8)
        caseAdminSubject = try fields.uint(9)
    }

    init(index: FabricIndex, rootCertificate: MatterCertificate, intermediateCertificate: MatterCertificate?,
         operationalCertificate: MatterCertificate, operationalKey: [UInt8], ipkEpochKey: [UInt8], vendorID: UInt16, label: String,
         caseAdminSubject: UInt64) {
        self.index = index
        self.rootCertificate = rootCertificate
        self.intermediateCertificate = intermediateCertificate
        self.operationalCertificate = operationalCertificate
        self.operationalKey = operationalKey
        self.ipkEpochKey = ipkEpochKey
        self.vendorID = vendorID
        self.label = label
        self.caseAdminSubject = caseAdminSubject
    }
}

/// Operational certificate chain checks (Core §6.5): NOC ← ICAC ← RCAC, fabric ids consistent, roles right.
public enum CertificateChain {
    public static func validate(noc: MatterCertificate, icac: MatterCertificate?, rcac: MatterCertificate) throws {
        func fail(_ reason: String) -> CertificateError { .invalidChain(reason) }
        guard rcac.rcacID != nil, rcac.basicConstraints?.isCA == true, rcac.isSigned(by: rcac),
              rcac.keyUsage?.contains(.keyCertSign) == true
        else { throw fail("root") }
        guard let nodeID = noc.nodeID, let fabricID = noc.fabricID, fabricID != 0,
              (1...0xFFFF_FFEF_FFFF_FFFF).contains(nodeID), noc.basicConstraints?.isCA == false,
              noc.keyUsage?.contains(.digitalSignature) == true
        else { throw fail("operational certificate") }
        if let rootFabric = rcac.fabricID, rootFabric != fabricID { throw fail("fabric") }
        if let icac {
            guard icac.icacID != nil, icac.basicConstraints?.isCA == true, icac.keyUsage?.contains(.keyCertSign) == true,
                  icac.isSigned(by: rcac), noc.isSigned(by: icac)
            else { throw fail("intermediate") }
            if let intermediateFabric = icac.fabricID, intermediateFabric != fabricID { throw fail("fabric") }
        } else {
            guard noc.isSigned(by: rcac) else { throw fail("signature") }
        }
    }
}

public enum FabricError: Error, Equatable, Sendable {
    case tableFull
    case exists
    case unknown(FabricIndex)
}

/// The fabrics this node is commissioned into, persisted in storage.
public actor FabricTable {
    public static let supportedFabrics = 5
    private var fabrics: [FabricIndex: Fabric] = [:]
    private let storage: any MatterStorage
    private var observers: [@Sendable ([Fabric]) async -> Void] = []

    public init(storage: any MatterStorage) async {
        self.storage = storage
        if let data = await storage.value(for: "fabrics"), let list = try? TLVDecoder.decode(data).value.elements {
            for element in list {
                if let fabric = try? Fabric(tlv: element.value) { fabrics[fabric.index] = fabric }
            }
        }
    }

    public var all: [Fabric] { fabrics.values.sorted { $0.index < $1.index } }
    public var count: Int { fabrics.count }
    public func fabric(_ index: FabricIndex) -> Fabric? { fabrics[index] }

    /// The next free index, 1...254 (Core §7.5.2).
    public func nextIndex() throws -> FabricIndex {
        guard fabrics.count < Self.supportedFabrics, let free = (1...254).first(where: { fabrics[FabricIndex($0)] == nil }) else {
            throw FabricError.tableFull
        }
        return FabricIndex(free)
    }

    public func onChange(_ observer: @escaping @Sendable ([Fabric]) async -> Void) { observers.append(observer) }

    func add(_ fabric: Fabric) async throws {
        // One fabric per root and fabric id (Core §11.18.6.8).
        guard !fabrics.values.contains(where: { $0.rootPublicKey == fabric.rootPublicKey && $0.fabricID == fabric.fabricID && $0.index != fabric.index })
        else { throw FabricError.exists }
        fabrics[fabric.index] = fabric
        try await save()
    }

    func update(_ fabric: Fabric) async throws {
        guard fabrics[fabric.index] != nil else { throw FabricError.unknown(fabric.index) }
        fabrics[fabric.index] = fabric
        try await save()
    }

    func remove(_ index: FabricIndex) async throws {
        guard fabrics.removeValue(forKey: index) != nil else { throw FabricError.unknown(index) }
        try await save()
    }

    /// The fabric a CASE Sigma1's destination identifier names (Core §4.14.2.3).
    func fabric(forDestination destination: [UInt8], initiatorRandom: [UInt8]) -> Fabric? {
        fabrics.values.first { MatterCrypto.equal($0.destinationID(initiatorRandom: initiatorRandom), destination) }
    }

    private func save() async throws {
        try await storage.setValue(TLVEncoder.encode(.array(all.map { TLVElement($0.tlv) })), for: "fabrics")
        let snapshot = all
        for observer in observers { await observer(snapshot) }
    }
}
