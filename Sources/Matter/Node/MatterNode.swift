import Foundation
import Logging

/// How a node presents itself and what it starts with.
public struct NodeConfiguration: Sendable {
    public var information: NodeInformation
    /// The setup passcode; generated once and stored when nil.
    public var passcode: UInt32?
    /// The 12-bit discriminator; generated once and stored when nil.
    public var discriminator: UInt16?
    public var port: Int
    /// The primary device type, for the Certification Declaration and discovery (Aggregator for a bridge).
    public var deviceType: UInt32
    /// Attestation credentials; test credentials are generated once and stored when nil.
    public var attestation: DeviceAttestation?
    public var reliability: ReliabilityParameters
    /// How long the initial commissioning window stays open; nil keeps it open until the node is commissioned.
    public var initialWindowTimeout: Duration?

    public init(information: NodeInformation = NodeInformation(), passcode: UInt32? = nil, discriminator: UInt16? = nil,
                port: Int = 5540, deviceType: UInt32 = DeviceTypes.aggregator.id, attestation: DeviceAttestation? = nil,
                reliability: ReliabilityParameters = .init(), initialWindowTimeout: Duration? = nil) {
        self.information = information
        self.passcode = passcode
        self.discriminator = discriminator
        self.port = port
        self.deviceType = deviceType
        self.attestation = attestation
        self.reliability = reliability
        self.initialWindowTimeout = initialWindowTimeout
    }
}

/// What a node announces over DNS-SD (Core §4.3).
public protocol NodeAdvertiser: Sendable {
    /// Advertises the commissionable service, or stops it with nil.
    func advertiseCommissionable(_ advertisement: CommissionableAdvertisement?) async
    /// Advertises one operational instance per fabric.
    func advertiseOperational(_ advertisements: [OperationalAdvertisement]) async
    func stop() async
}

public struct CommissionableAdvertisement: Hashable, Sendable {
    public var discriminator: UInt16
    public var vendorID: UInt16
    public var productID: UInt16
    /// 1: basic commissioning window, 2: enhanced.
    public var commissioningMode: UInt8
    public var deviceType: UInt32
    public var deviceName: String
    public var port: Int
    public var parameters: SessionParameters
}

public struct OperationalAdvertisement: Hashable, Sendable {
    public var compressedFabricID: [UInt8]
    public var nodeID: NodeID
    public var port: Int
    public var parameters: SessionParameters
}

/// A Matter node: a root endpoint with the commissioning clusters, the endpoints an application adds, and the
/// protocols that serve them.
public actor MatterNode {
    public nonisolated let configuration: NodeConfiguration
    public nonisolated let storage: any MatterStorage
    public nonisolated let dataModel: DataModel
    public nonisolated let fabrics: FabricTable
    public nonisolated let accessControl: AccessControlEntries
    public nonisolated let commissioning: Commissioning
    public nonisolated let layer: MessageLayer
    public nonisolated let interactionServer: InteractionServer
    public nonisolated let setupPayload: SetupPayload
    let advertiser: (any NodeAdvertiser)?
    let logger: Logger
    private let verifier: PASEVerifier
    private var started = false

    /// Loads or creates the node's identity from storage. `transport` defaults to UDP on the configured port.
    public init(configuration: NodeConfiguration, storage: any MatterStorage, transport: (any MatterTransport)? = nil,
                advertiser: (any NodeAdvertiser)? = nil, logger: Logger = Logger(label: "matter.node")) async throws {
        self.configuration = configuration
        self.storage = storage
        self.advertiser = advertiser
        self.logger = logger

        let attestation = try await Self.loadAttestation(configuration, storage: storage)
        let setup = try await Self.loadSetup(configuration, storage: storage)
        verifier = setup.verifier
        setupPayload = SetupPayload(vendorID: configuration.information.vendorID, productID: configuration.information.productID,
                                    discriminator: setup.discriminator, passcode: setup.passcode)

        var information = configuration.information
        if information.uniqueID.isEmpty { information.uniqueID = await Self.uniqueID(storage: storage) }

        fabrics = await FabricTable(storage: storage)
        accessControl = await AccessControlEntries(storage: storage)
        commissioning = Commissioning(fabrics: fabrics, accessControl: accessControl, attestation: attestation, logger: logger)
        layer = MessageLayer(transport: transport ?? UDPTransport(port: configuration.port), reliability: configuration.reliability)
        dataModel = DataModel()
        interactionServer = InteractionServer(dataModel: dataModel, accessControl: accessControl)

        let root = await RootClusters.make(information: information, commissioning: commissioning, fabrics: fabrics,
                                           accessControl: accessControl, attestation: attestation, startTime: .now, storage: storage)
        try await dataModel.add(Endpoint(number: 0, deviceTypes: [DeviceTypes.rootNode], clusters: root))
    }

    public func start() async throws {
        guard !started else { return }
        started = true
        await commissioning.setLayer(layer)
        let commissioning = commissioning
        let pase = PASE.ResponderContext(verifier: { await commissioning.paseVerifier() },
                                         attempted: { await commissioning.paseAttempted($0) })
        try await layer.register(SecureChannelServer(pase: pase, caseResponder: CASEServer(fabrics: fabrics)), for: .secureChannel)
        try await interactionServer.serve(on: layer)
        try await layer.start()

        // Advertising follows the window and the fabrics.
        let advertiser = advertiser
        let advertisement = commissionableAdvertisement
        await commissioning.onWindowChange { kind, discriminator in
            guard let discriminator, kind != .closed else { await advertiser?.advertiseCommissionable(nil); return }
            var current = advertisement
            current.discriminator = discriminator
            current.commissioningMode = kind == .enhanced ? 2 : 1
            await advertiser?.advertiseCommissionable(current)
        }
        let port = configuration.port, parameters = layer.parameters
        @Sendable func advertise(_ fabrics: [Fabric]) async {
            await advertiser?.advertiseOperational(fabrics.map {
                OperationalAdvertisement(compressedFabricID: $0.compressedFabricID, nodeID: $0.nodeID, port: port, parameters: parameters)
            })
        }
        await fabrics.onChange { await advertise($0) }
        let layer = layer
        await commissioning.onFabricRemoved { index in await layer.removeSessions { $0.fabricIndex == index } }
        await advertise(await fabrics.all)

        if await fabrics.count == 0 {
            await commissioning.open(.basic, verifier: verifier, discriminator: setupPayload.discriminator,
                                     timeout: configuration.initialWindowTimeout)
            // The setup code is never logged (it is the passcode); applications show `setupPayload` themselves.
            logger.info("Not commissioned: commissioning window open, discriminator \(setupPayload.discriminator)")
        }
    }

    public func stop() async {
        await advertiser?.stop()
        await layer.stop()
    }

    public var isCommissioned: Bool { get async { await fabrics.count > 0 } }

    /// Opens a basic commissioning window with the onboarding payload's passcode, for another ecosystem to join.
    public func openCommissioningWindow(timeout: Duration = .seconds(900)) async {
        await commissioning.open(.basic, verifier: verifier, discriminator: setupPayload.discriminator, timeout: timeout)
    }

    // MARK: - Endpoints

    public func add(_ endpoint: Endpoint) async throws { try await dataModel.add(endpoint) }
    public func remove(endpoint: EndpointNumber) async throws { try await dataModel.remove(endpoint) }

    // MARK: - Identity

    private var commissionableAdvertisement: CommissionableAdvertisement {
        CommissionableAdvertisement(discriminator: setupPayload.discriminator, vendorID: configuration.information.vendorID,
                                    productID: configuration.information.productID, commissioningMode: 1,
                                    deviceType: configuration.deviceType, deviceName: configuration.information.productName,
                                    port: configuration.port, parameters: layer.parameters)
    }

    struct Setup {
        var passcode: UInt32
        var discriminator: UInt16
        var verifier: PASEVerifier
    }

    /// The passcode, discriminator and verifier; generated values are kept so the QR code stays the same.
    private static func loadSetup(_ configuration: NodeConfiguration, storage: any MatterStorage) async throws -> Setup {
        if let data = await storage.value(for: StorageKey.setup), let fields = try? TLVStruct(decoding: data),
           let passcode = try? fields.uint(1, as: UInt32.self), let discriminator = try? fields.uint(2, as: UInt16.self),
           let salt = try? fields.bytes(3), let iterations = try? fields.uint(4), let serialized = try? fields.bytes(5),
           let verifier = try? SPAKE2Plus.Verifier(serialized: serialized),
           configuration.passcode == nil || configuration.passcode == passcode,
           configuration.discriminator == nil || configuration.discriminator == discriminator {
            return Setup(passcode: passcode, discriminator: discriminator,
                         verifier: PASEVerifier(verifier: verifier, salt: salt, iterations: Int(iterations)))
        }
        let passcode = configuration.passcode ?? SetupPayload.randomPasscode()
        guard SetupPayload.isValid(passcode: passcode) else { throw SetupPayloadError.invalidPasscode }
        let discriminator = configuration.discriminator ?? SetupPayload.randomDiscriminator()
        let verifier = try PASEVerifier(passcode: passcode)
        try await storage.setValue(TLVEncoder.encode(.structure([
            .field(1, .unsigned(UInt64(passcode))), .field(2, .unsigned(UInt64(discriminator))), .field(3, .bytes(verifier.salt)),
            .field(4, .unsigned(UInt64(verifier.iterations))), .field(5, .bytes(verifier.verifier.serialized)),
        ])), for: StorageKey.setup)
        return Setup(passcode: passcode, discriminator: discriminator, verifier: verifier)
    }

    private static func loadAttestation(_ configuration: NodeConfiguration, storage: any MatterStorage) async throws -> DeviceAttestation {
        if let attestation = configuration.attestation { return attestation }
        if let data = await storage.value(for: StorageKey.attestation), let fields = try? TLVStruct(decoding: data),
           let dac = try? fields.bytes(1), let pai = try? fields.bytes(2), let cd = try? fields.bytes(3), let key = try? fields.bytes(4) {
            return DeviceAttestation(dacCertificate: dac, paiCertificate: pai, certificationDeclaration: cd, dacPrivateKey: key)
        }
        let attestation = try DeviceAttestation.test(vendorID: configuration.information.vendorID,
                                                     productID: configuration.information.productID, deviceType: configuration.deviceType)
        try await storage.setValue(TLVEncoder.encode(.structure([
            .field(1, .bytes(attestation.dacCertificate)), .field(2, .bytes(attestation.paiCertificate)),
            .field(3, .bytes(attestation.certificationDeclaration)), .field(4, .bytes(attestation.dacPrivateKey)),
        ])), for: StorageKey.attestation)
        return attestation
    }

    private static func uniqueID(storage: any MatterStorage) async -> String {
        if let data = await storage.value(for: StorageKey.uniqueID), let id = String(bytes: data, encoding: .utf8) { return id }
        let id = hexString(MatterCrypto.random(16))
        try? await storage.setValue(Array(id.utf8), for: StorageKey.uniqueID)
        return id
    }
}
