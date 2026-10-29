/// Session contexts (Core §4.13).

/// MRP intervals a node advertises and uses (Core §4.12.8, §2.11.2).
public struct SessionParameters: Hashable, Sendable {
    /// SII: the retry interval while the peer is idle.
    public var idleInterval: Duration
    /// SAI: the retry interval while the peer is active.
    public var activeInterval: Duration
    /// SAT: how long a node stays active after network activity.
    public var activeThreshold: Duration

    public static let `default` = SessionParameters(idleInterval: .milliseconds(500), activeInterval: .milliseconds(300),
                                                    activeThreshold: .milliseconds(4000))

    public init(idleInterval: Duration, activeInterval: Duration, activeThreshold: Duration) {
        self.idleInterval = idleInterval
        self.activeInterval = activeInterval
        self.activeThreshold = activeThreshold
    }

    /// The session-parameter-struct (Core §4.12.8).
    public var tlv: TLVValue {
        .structure([
            .field(1, .unsigned(UInt64(idleInterval.milliseconds))),
            .field(2, .unsigned(UInt64(activeInterval.milliseconds))),
            .field(3, .unsigned(UInt64(activeThreshold.milliseconds))),
            .field(4, .unsigned(UInt64(SpecificationVersion.dataModelRevision))),
            .field(5, .unsigned(UInt64(SpecificationVersion.interactionModelRevision))),
            .field(6, .unsigned(UInt64(SpecificationVersion.specificationVersion))),
            .field(7, .unsigned(1)),
            .field(8, .unsigned(0)),
        ])
    }

    /// The peer's parameters, falling back to defaults for those it leaves out.
    public init(tlv value: TLVValue?) {
        self = .default
        guard let value else { return }
        if let idle = value[1]?.uint { idleInterval = .milliseconds(Int64(min(idle, 3_600_000))) }
        if let active = value[2]?.uint { activeInterval = .milliseconds(Int64(min(active, 3_600_000))) }
        if let threshold = value[3]?.uint { activeThreshold = .milliseconds(Int64(min(threshold, 65_535))) }
    }
}

/// The revisions this implementation reports.
public enum SpecificationVersion {
    /// Matter 1.6.1: 0x01060100 (Basic Information's SpecificationVersion encoding).
    public static let specificationVersion: UInt32 = 0x0106_0100
    public static let dataModelRevision: UInt16 = 21
    public static let interactionModelRevision: UInt16 = 13
}

extension Duration {
    var milliseconds: Int64 {
        let (seconds, attoseconds) = components
        return seconds * 1000 + attoseconds / 1_000_000_000_000_000
    }
}

/// What protocol handlers know about the session a message came over.
public struct SessionInfo: Hashable, Sendable {
    public enum Kind: Hashable, Sendable {
        case unsecured
        case pase
        case `case`
    }

    public var kind: Kind
    public var localSessionID: UInt16
    public var peerSessionID: UInt16
    /// The fabric the session belongs to: CASE sessions always, a PASE session once AddNOC binds it.
    public var fabricIndex: UInt8?
    public var peerNodeID: UInt64
    public var localNodeID: UInt64
    /// The peer's CASE Authenticated Tags.
    public var caseAuthenticatedTags: [UInt32]
    /// The attestation challenge of a PASE or CASE session (Core §6.2.3).
    public var attestationChallenge: [UInt8]
    public var peerAddress: PeerAddress

    public var isSecure: Bool { kind != .unsecured }

    public init(kind: Kind, localSessionID: UInt16, peerSessionID: UInt16, fabricIndex: UInt8? = nil, peerNodeID: UInt64 = 0,
                localNodeID: UInt64 = 0, caseAuthenticatedTags: [UInt32] = [], attestationChallenge: [UInt8] = [],
                peerAddress: PeerAddress) {
        self.kind = kind
        self.localSessionID = localSessionID
        self.peerSessionID = peerSessionID
        self.fabricIndex = fabricIndex
        self.peerNodeID = peerNodeID
        self.localNodeID = localNodeID
        self.caseAuthenticatedTags = caseAuthenticatedTags
        self.attestationChallenge = attestationChallenge
        self.peerAddress = peerAddress
    }
}

/// Keys and counters of one secure unicast session.
struct SecureSession {
    var info: SessionInfo
    let encryptor: AESCCM
    let decryptor: AESCCM
    var localCounter: UInt32
    var reception: MessageReceptionState
    var peerParameters: SessionParameters

    init(info: SessionInfo, encryptKey: [UInt8], decryptKey: [UInt8], peerParameters: SessionParameters) throws {
        self.info = info
        encryptor = try AESCCM(key: encryptKey)
        decryptor = try AESCCM(key: decryptKey)
        localCounter = MessageCounter.initialValue()
        reception = MessageReceptionState(policy: .strict, synchronizedTo: 0)
        self.peerParameters = peerParameters
    }

    /// The nonce source node id of messages this node sends: its operational node id, or 0 for PASE.
    var localNonceNodeID: UInt64 { info.kind == .case ? info.localNodeID : 0 }
    var peerNonceNodeID: UInt64 { info.kind == .case ? info.peerNodeID : 0 }
}

/// The keys a session establishment produces.
public struct SessionKeys: Sendable {
    public var initiatorToResponder: [UInt8]
    public var responderToInitiator: [UInt8]
    public var attestationChallenge: [UInt8]

    /// I2RKey || R2IKey || AttestationChallenge = KDF(secret, salt, info) (Core §4.14.1.2, §4.14.2.6).
    public init(secret: [UInt8], salt: [UInt8], info: [UInt8]) {
        let keys = MatterCrypto.kdf(key: secret, salt: salt, info: info, length: 48)
        initiatorToResponder = Array(keys[0..<16])
        responderToInitiator = Array(keys[16..<32])
        attestationChallenge = Array(keys[32..<48])
    }
}
