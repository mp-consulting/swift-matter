import Crypto
import Logging

/// The commissioning window (Core §5.4.2) and the fail-safe context (Core §11.10.7.2): what a commissioner adds is
/// pending until CommissioningComplete, and rolled back when the fail-safe expires.
public actor Commissioning {
    public enum Window: Equatable, Sendable {
        case closed
        /// Opened with the onboarding payload's passcode.
        case basic
        /// Opened by an administrator with a new verifier.
        case enhanced
    }

    /// How a commissioning window was opened, for AdministratorCommissioning.
    struct WindowState {
        var kind: Window
        var verifier: PASEVerifier
        var discriminator: UInt16
        var adminFabric: FabricIndex?
        var adminVendor: UInt16?
        var expiry: Task<Void, Never>?
    }

    /// What is pending while the fail-safe is armed.
    struct FailSafe {
        var deadline: ContinuousClock.Instant
        var cumulativeDeadline: ContinuousClock.Instant
        /// The session that armed it, and its fabric (nil over PASE before AddNOC).
        var sessionID: UInt16
        var fabricIndex: FabricIndex?
        var pendingRoot: MatterCertificate?
        var pendingKey: P256.Signing.PrivateKey?
        var keyForUpdate = false
        var addedFabric: FabricIndex?
        var updatedFabric: Fabric?
        var expiry: Task<Void, Never>?
    }

    public static let failSafeExpiryLength: UInt16 = 60
    public static let maxCumulativeFailSafe: UInt16 = 900
    public static let maxPASEFailures = 20

    let fabrics: FabricTable
    let accessControl: AccessControlEntries
    let attestation: DeviceAttestation
    let logger: Logger
    private(set) var window: WindowState?
    private var failSafe: FailSafe?
    private var paseFailures = 0
    public private(set) var breadcrumb: UInt64 = 0
    /// Told when the window opens or closes, so advertising follows.
    private var windowObservers: [@Sendable (Window, UInt16?) async -> Void] = []
    /// Told when the fail-safe rolls back a fabric, so its sessions close.
    private var rollbackObservers: [@Sendable (FabricIndex) async -> Void] = []
    weak var layer: MessageLayer?

    init(fabrics: FabricTable, accessControl: AccessControlEntries, attestation: DeviceAttestation, logger: Logger) {
        self.fabrics = fabrics
        self.accessControl = accessControl
        self.attestation = attestation
        self.logger = logger
    }

    func setLayer(_ layer: MessageLayer) { self.layer = layer }

    func onWindowChange(_ observer: @escaping @Sendable (Window, UInt16?) async -> Void) { windowObservers.append(observer) }
    func onRollback(_ observer: @escaping @Sendable (FabricIndex) async -> Void) { rollbackObservers.append(observer) }

    // MARK: - Window

    public var windowStatus: Window { window?.kind ?? .closed }
    public var windowAdmin: (fabric: FabricIndex?, vendor: UInt16?) { (window?.adminFabric, window?.adminVendor) }

    /// Opens the window; `timeout` nil keeps it open until commissioning succeeds (the initial window of an
    /// uncommissioned node).
    func open(_ kind: Window, verifier: PASEVerifier, discriminator: UInt16, timeout: Duration?, adminFabric: FabricIndex? = nil,
              adminVendor: UInt16? = nil) async {
        window?.expiry?.cancel()
        paseFailures = 0
        var state = WindowState(kind: kind, verifier: verifier, discriminator: discriminator, adminFabric: adminFabric, adminVendor: adminVendor)
        if let timeout {
            state.expiry = Task { [weak self] in
                guard (try? await Task.sleep(for: timeout)) != nil else { return }
                await self?.close()
            }
        }
        window = state
        for observer in windowObservers { await observer(kind, discriminator) }
    }

    func close() async {
        guard let state = window else { return }
        state.expiry?.cancel()
        window = nil
        for observer in windowObservers { await observer(.closed, nil) }
        // A PASE session that is not commissioning anything ends with the window.
        if failSafe == nil { await layer?.removeSessions { $0.kind == .pase } }
    }

    /// The verifier PASE uses, while the window is open.
    func paseVerifier() -> PASEVerifier? { window?.verifier }

    /// Counts PASE failures; too many close the window (Core §5.4.2.2).
    func paseAttempted(_ failure: PASEError?) async {
        guard failure != nil else { return }
        paseFailures += 1
        if paseFailures >= Self.maxPASEFailures {
            logger.notice("Commissioning window closed after \(paseFailures) failed PASE attempts")
            await close()
        }
    }

    // MARK: - Fail-safe

    public var isFailSafeArmed: Bool { failSafe != nil }

    func setBreadcrumb(_ value: UInt64) { breadcrumb = value }

    /// ArmFailSafe (Core §11.10.7.2); nil means success, otherwise the CommissioningErrorEnum value.
    func arm(expiry seconds: UInt16, breadcrumb: UInt64, session: SessionInfo) async -> UInt8? {
        if let failSafe {
            // Only the session (or fabric) that armed it may extend or disarm it.
            let sameFabric = failSafe.fabricIndex != nil && failSafe.fabricIndex == session.fabricIndex
            guard failSafe.sessionID == session.localSessionID || sameFabric else { return 4 } // BusyWithOtherAdmin
        } else {
            // Over CASE while an enhanced window waits for another commissioner, the node is busy (§11.10.7.2.1).
            if window?.kind == .enhanced, session.kind == .case { return 4 }
            if seconds == 0 { self.breadcrumb = breadcrumb; return nil }
        }
        if seconds == 0 {
            await expire()
            self.breadcrumb = breadcrumb
            return nil
        }
        let now = ContinuousClock.now
        var state = failSafe ?? FailSafe(deadline: now, cumulativeDeadline: now + .seconds(Int(Self.maxCumulativeFailSafe)),
                                         sessionID: session.localSessionID, fabricIndex: session.fabricIndex)
        state.deadline = min(now + .seconds(Int(seconds)), state.cumulativeDeadline)
        state.expiry?.cancel()
        let deadline = state.deadline
        state.expiry = Task { [weak self] in
            guard (try? await Task.sleep(until: deadline, clock: .continuous)) != nil else { return }
            await self?.expire()
        }
        failSafe = state
        self.breadcrumb = breadcrumb
        return nil
    }

    /// Rolls back everything added under the fail-safe (Core §11.10.7.2.2).
    func expire() async {
        guard let state = failSafe else { return }
        state.expiry?.cancel()
        failSafe = nil
        breadcrumb = 0
        if let added = state.addedFabric {
            logger.info("Fail-safe expired: removing fabric \(added)")
            try? await fabrics.remove(added)
            await accessControl.removeFabric(added)
            for observer in rollbackObservers { await observer(added) }
        }
        if let updated = state.updatedFabric { try? await fabrics.update(updated) }
        if window == nil { await layer?.removeSessions { $0.kind == .pase } }
    }

    /// CommissioningComplete (Core §11.10.7.6): over CASE on the new fabric. Nil is success.
    func complete(session: SessionInfo) async -> UInt8? {
        guard let state = failSafe else { return 3 } // NoFailSafe
        guard session.kind == .case, session.fabricIndex == (state.addedFabric ?? state.fabricIndex) else { return 2 } // InvalidAuthentication
        state.expiry?.cancel()
        failSafe = nil
        breadcrumb = 0
        await close()
        // The commissioning PASE session has served its purpose.
        await layer?.removeSessions { $0.kind == .pase }
        return nil
    }

    // MARK: - Operational credentials

    /// CSRRequest (Core §11.18.6.5): a new operational key, pending until AddNOC or UpdateNOC.
    func csr(nonce: [UInt8], forUpdate: Bool, challenge: [UInt8]) throws -> (elements: [UInt8], signature: [UInt8]) {
        guard failSafe != nil else { throw StatusError(.failsafeRequired) }
        guard nonce.count == 32 else { throw StatusError(.invalidCommand) }
        let key = P256.Signing.PrivateKey()
        failSafe?.pendingKey = key
        failSafe?.keyForUpdate = forUpdate
        let elements = TLVEncoder.encode(.structure([.field(1, .bytes(try CertificationRequest.create(key: key))), .field(2, .bytes(nonce))]))
        return (elements, try attestation.sign(elements, challenge: challenge))
    }

    /// AddTrustedRootCertificate (Core §11.18.6.13).
    func addTrustedRoot(_ bytes: [UInt8]) throws {
        guard failSafe != nil else { throw StatusError(.failsafeRequired) }
        guard failSafe?.pendingRoot == nil, failSafe?.addedFabric == nil else { throw StatusError(.constraintError) }
        guard let root = try? MatterCertificate(tlv: bytes), root.rcacID != nil, root.basicConstraints?.isCA == true,
              root.isSigned(by: root)
        else { throw StatusError(.invalidCommand) }
        failSafe?.pendingRoot = root
    }

    /// NodeOperationalCertStatusEnum values.
    enum NOCStatus: UInt8 {
        case ok = 0, invalidPublicKey = 1, invalidNodeOpID = 2, invalidNOC = 3, missingCSR = 4, tableFull = 5,
             invalidAdminSubject = 6, fabricConflict = 9, labelConflict = 10, invalidFabricIndex = 11
    }

    /// AddNOC (Core §11.18.6.8): the new fabric, with an Administer entry for the commissioner's subject.
    func addNOC(noc nocBytes: [UInt8], icac icacBytes: [UInt8]?, ipk: [UInt8], adminSubject: UInt64, adminVendor: UInt16,
                session: SessionInfo) async throws -> (NOCStatus, FabricIndex?) {
        guard let state = failSafe else { throw StatusError(.failsafeRequired) }
        guard state.addedFabric == nil, state.updatedFabric == nil else { throw StatusError(.constraintError) }
        guard let key = state.pendingKey, !state.keyForUpdate, let root = state.pendingRoot else { return (.missingCSR, nil) }
        guard ipk.count == 16 else { throw StatusError(.invalidCommand) }
        guard let noc = try? MatterCertificate(tlv: nocBytes) else { return (.invalidNOC, nil) }
        let icac = try icacBytes.map { bytes -> MatterCertificate in
            guard let certificate = try? MatterCertificate(tlv: bytes) else { throw NOCError.invalid }
            return certificate
        }
        guard noc.publicKey == Array(key.publicKey.x963Representation) else { return (.invalidPublicKey, nil) }
        do { try CertificateChain.validate(noc: noc, icac: icac, rcac: root) } catch { return (.invalidNOC, nil) }
        // The admin subject is a node id or a CAT, never a group or a PAKE id (Core §11.18.6.8).
        guard adminSubject >> 32 == 0xFFFF_FFFD || (1...0xFFFF_FFEF_FFFF_FFFF).contains(adminSubject) else {
            return (.invalidAdminSubject, nil)
        }
        let index: FabricIndex
        do { index = try await fabrics.nextIndex() } catch { return (.tableFull, nil) }
        let fabric = Fabric(index: index, rootCertificate: root, intermediateCertificate: icac, operationalCertificate: noc,
                            operationalKey: Array(key.rawRepresentation), ipkEpochKey: ipk, vendorID: adminVendor, label: "",
                            caseAdminSubject: adminSubject)
        do { try await fabrics.add(fabric) } catch { return (.fabricConflict, nil) }
        await accessControl.replace(fabric: index, with: [
            AccessControlEntry(fabricIndex: index, privilege: .administer, authMode: .case, subjects: [adminSubject]),
        ])
        failSafe?.addedFabric = index
        failSafe?.pendingKey = nil
        failSafe?.pendingRoot = nil
        // The commissioning session now belongs to the new fabric (Core §11.18.6.8).
        await layer?.bind(session: session.localSessionID, toFabric: index)
        return (.ok, index)
    }

    /// UpdateNOC (Core §11.18.6.9): a new NOC for the accessing fabric, with the key from the last CSRRequest.
    func updateNOC(noc nocBytes: [UInt8], icac icacBytes: [UInt8]?, fabricIndex: FabricIndex) async throws -> NOCStatus {
        guard let state = failSafe else { throw StatusError(.failsafeRequired) }
        guard let key = state.pendingKey, state.keyForUpdate else { return .missingCSR }
        guard let fabric = await fabrics.fabric(fabricIndex) else { return .invalidFabricIndex }
        guard let noc = try? MatterCertificate(tlv: nocBytes) else { return .invalidNOC }
        let icac = icacBytes.flatMap { try? MatterCertificate(tlv: $0) }
        guard noc.publicKey == Array(key.publicKey.x963Representation) else { return .invalidPublicKey }
        do { try CertificateChain.validate(noc: noc, icac: icac, rcac: fabric.rootCertificate) } catch { return .invalidNOC }
        guard noc.fabricID == fabric.fabricID else { return .invalidNOC }
        var updated = fabric
        updated.operationalCertificate = noc
        updated.intermediateCertificate = icac
        updated.operationalKey = Array(key.rawRepresentation)
        try await fabrics.update(updated)
        failSafe?.updatedFabric = fabric
        failSafe?.pendingKey = nil
        return .ok
    }

    enum NOCError: Error { case invalid }
}

/// The ACL entries of every fabric, persisted; the AccessControl cluster reads and writes them per fabric.
public actor AccessControlEntries: AccessController {
    private var entries: [AccessControlEntry] = []
    private let storage: any MatterStorage
    private var observers: [@Sendable () -> Void] = []

    public init(storage: any MatterStorage) async {
        self.storage = storage
        if let data = await storage.value(for: "acl"), let list = try? TLVDecoder.decode(data).value.elements {
            entries = list.compactMap { try? AccessControlEntry(tlv: $0.value) }
        }
    }

    public var all: [AccessControlEntry] { entries }

    func onChange(_ observer: @escaping @Sendable () -> Void) { observers.append(observer) }

    public func entries(fabric: FabricIndex) -> [AccessControlEntry] { entries.filter { $0.fabricIndex == fabric } }

    public func replace(fabric: FabricIndex, with newEntries: [AccessControlEntry]) async {
        entries = entries.filter { $0.fabricIndex != fabric } + newEntries.map { entry in
            var stamped = entry
            stamped.fabricIndex = fabric
            return stamped
        }
        await save()
    }

    public func removeFabric(_ fabric: FabricIndex) async { await replace(fabric: fabric, with: []) }

    public func privilege(of session: SessionInfo, endpoint: EndpointNumber, cluster: ClusterID, deviceTypes: [UInt32]) -> Privilege? {
        // A PASE session commissions the node: it holds Administer implicitly (Core §6.6.2.9).
        if session.kind == .pase { return .administer }
        return entries.filter { $0.grants(session, endpoint: endpoint, cluster: cluster, deviceTypes: deviceTypes) }.map(\.privilege).max()
    }

    private func save() async {
        try? await storage.setValue(TLVEncoder.encode(.array(entries.map { TLVElement($0.tlv) })), for: "acl")
        for observer in observers { observer() }
    }
}
