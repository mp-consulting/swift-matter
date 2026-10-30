import Foundation
import NIOCore
import NIOPosix

/// What the Basic Information cluster says about the node.
public struct NodeInformation: Sendable {
    public var vendorName: String
    public var vendorID: UInt16
    public var productName: String
    public var productID: UInt16
    public var nodeLabel: String
    public var hardwareVersion: UInt16
    public var hardwareVersionString: String
    public var softwareVersion: UInt32
    public var softwareVersionString: String
    public var serialNumber: String
    /// A persistent random identifier (Core §11.1.5.21).
    public var uniqueID: String

    public init(vendorName: String = "swift-matter", vendorID: UInt16 = 0xFFF1, productName: String = "Matter Bridge",
                productID: UInt16 = 0x8000, nodeLabel: String = "", hardwareVersion: UInt16 = 1, hardwareVersionString: String = "1",
                softwareVersion: UInt32 = 1, softwareVersionString: String = "1.0", serialNumber: String = "", uniqueID: String = "") {
        self.vendorName = vendorName
        self.vendorID = vendorID
        self.productName = productName
        self.productID = productID
        self.nodeLabel = nodeLabel
        self.hardwareVersion = hardwareVersion
        self.hardwareVersionString = hardwareVersionString
        self.softwareVersion = softwareVersion
        self.softwareVersionString = softwareVersionString
        self.serialNumber = serialNumber
        self.uniqueID = uniqueID
    }
}

/// The clusters of the root endpoint (Device Library §2.1): what commissioning and administration use.
enum RootClusters {
    static func make(information: NodeInformation, commissioning: Commissioning, fabrics: FabricTable,
                     accessControl: AccessControlEntries, attestation: DeviceAttestation, startTime: ContinuousClock.Instant,
                     storage: any MatterStorage, groups: Groups) async -> [any ClusterHandler] {
        [
            await basicInformation(information, storage: storage),
            await generalCommissioning(commissioning),
            await operationalCredentials(commissioning: commissioning, fabrics: fabrics, accessControl: accessControl,
                                         attestation: attestation),
            await accessControlCluster(accessControl),
            await groupKeyManagement(groups),
            await networkCommissioning(),
            await generalDiagnostics(startTime: startTime),
            await administratorCommissioning(commissioning),
        ]
    }

    // MARK: - Basic Information (Core §11.1)

    static func basicInformation(_ info: NodeInformation, storage: any MatterStorage) async -> AttributeCluster {
        typealias A = BasicInformationCluster.Attribute
        typealias Minima = BasicInformationCluster.CapabilityMinimaStruct
        // NodeLabel and Location are written by controllers and survive restarts.
        let stored = await storage.value(for: StorageKey.basicInformation).flatMap { try? TLVStruct(decoding: $0) }
        let cluster = AttributeCluster(BasicInformationCluster.definition, attributes: [
            A.dataModelRevision: .unsigned(UInt64(SpecificationVersion.dataModelRevision)),
            A.vendorName: .utf8(info.vendorName), A.vendorId: .unsigned(UInt64(info.vendorID)),
            A.productName: .utf8(info.productName), A.productId: .unsigned(UInt64(info.productID)),
            A.nodeLabel: .utf8(stored?[1]?.string ?? info.nodeLabel), A.location: .utf8(stored?[2]?.string ?? "XX"),
            A.hardwareVersion: .unsigned(UInt64(info.hardwareVersion)), A.hardwareVersionString: .utf8(info.hardwareVersionString),
            A.softwareVersion: .unsigned(UInt64(info.softwareVersion)), A.softwareVersionString: .utf8(info.softwareVersionString),
            A.serialNumber: .utf8(info.serialNumber), A.uniqueId: .utf8(info.uniqueID),
            A.capabilityMinima: .structure([.field(Minima.caseSessionsPerFabric, .unsigned(3)), .field(Minima.subscriptionsPerFabric, .unsigned(3))]),
            A.specificationVersion: .unsigned(UInt64(SpecificationVersion.specificationVersion)),
            A.maxPathsPerInvoke: .unsigned(1), A.configurationVersion: .unsigned(1),
        ])
        await cluster.onWrite { cluster, attribute, value, _ in
            guard let text = value.string else { throw StatusError(.constraintError) }
            var label = await cluster.value(A.nodeLabel)?.string ?? ""
            var location = await cluster.value(A.location)?.string ?? "XX"
            switch attribute {
            case A.nodeLabel:
                guard text.utf8.count <= 32 else { throw StatusError(.constraintError) }
                label = text
            case A.location:
                // An ISO 3166-1 alpha-2 code, or XX (Core §11.1.5.7).
                guard text.utf8.count == 2 else { throw StatusError(.constraintError) }
                location = text
            default:
                throw StatusError(.unsupportedWrite)
            }
            try? await storage.setValue(TLVEncoder.encode(.structure([.field(1, .utf8(label)), .field(2, .utf8(location))])),
                                        for: StorageKey.basicInformation)
        }
        return cluster
    }

    // MARK: - General Commissioning (Core §11.10)

    static func generalCommissioning(_ commissioning: Commissioning) async -> AttributeCluster {
        typealias A = GeneralCommissioningCluster.Attribute
        typealias C = GeneralCommissioningCluster.Command
        let cluster = AttributeCluster(GeneralCommissioningCluster.definition, attributes: [
            A.basicCommissioningInfo: .structure([
                .field(GeneralCommissioningCluster.BasicCommissioningInfo.failSafeExpiryLengthSeconds, .unsigned(UInt64(Commissioning.failSafeExpiryLength))),
                .field(GeneralCommissioningCluster.BasicCommissioningInfo.maxCumulativeFailsafeSeconds, .unsigned(UInt64(Commissioning.maxCumulativeFailSafe))),
            ]),
            A.regulatoryConfig: .unsigned(2), A.locationCapability: .unsigned(2), A.supportsConcurrentConnection: .bool(true),
        ])
        await cluster.provide(A.breadcrumb) { _ in .unsigned(await commissioning.breadcrumb) }
        await cluster.onWrite { _, attribute, value, _ in
            guard attribute == A.breadcrumb, let breadcrumb = value.uint else { throw StatusError(.constraintError) }
            await commissioning.setBreadcrumb(breadcrumb)
        }
        @Sendable func response(_ command: CommandID, _ error: UInt8?) -> InvokeResult {
            .response(command, .structure([.field(0, .unsigned(UInt64(error ?? 0))), .field(1, .utf8(""))]))
        }
        await cluster.handle(C.armFailSafe) { _, fields, context in
            let request = try TLVStruct(fields)
            let error = await commissioning.arm(expiry: try request.uint(0, as: UInt16.self), breadcrumb: try request.uint(1),
                                                session: context.session)
            return response(C.armFailSafeResponse, error)
        }
        await cluster.handle(C.setRegulatoryConfig) { cluster, fields, _ in
            let request = try TLVStruct(fields)
            let config = try request.uint(0)
            // Indoor (0), outdoor (1) or both (2); the node supports both.
            guard config <= 2 else { return response(C.setRegulatoryConfigResponse, 1) } // ValueOutsideRange
            await cluster.set(A.regulatoryConfig, .unsigned(config))
            await commissioning.setBreadcrumb(try request.uint(2))
            return response(C.setRegulatoryConfigResponse, nil)
        }
        await cluster.handle(C.commissioningComplete) { _, _, context in
            response(C.commissioningCompleteResponse, await commissioning.complete(session: context.session))
        }
        return cluster
    }

    // MARK: - Operational Credentials (Core §11.18)

    static func operationalCredentials(commissioning: Commissioning, fabrics: FabricTable, accessControl: AccessControlEntries,
                                       attestation: DeviceAttestation) async -> AttributeCluster {
        typealias A = OperationalCredentialsCluster.Attribute
        typealias C = OperationalCredentialsCluster.Command
        typealias Descriptor = OperationalCredentialsCluster.FabricDescriptorStruct
        typealias NOC = OperationalCredentialsCluster.NOCStruct
        let cluster = AttributeCluster(OperationalCredentialsCluster.definition, attributes: [
            A.supportedFabrics: .unsigned(UInt64(FabricTable.supportedFabrics)),
        ])
        await cluster.provide(A.nocs) { context in
            let entries = await fabrics.all.map { fabric in
                var fields: [TLVElement] = [.field(NOC.noc, .bytes(fabric.operationalCertificate.tlvEncoded))]
                fields.append(.field(NOC.icac, fabric.intermediateCertificate.map { .bytes($0.tlvEncoded) } ?? .null))
                fields.append(.field(NOC.fabricIndex, .unsigned(UInt64(fabric.index))))
                return TLVElement(.structure(fields))
            }
            return FabricScopedList.read(.array(entries), context: context)
        }
        await cluster.provide(A.fabrics) { context in
            let entries = await fabrics.all.map { fabric in
                TLVElement(.structure([
                    .field(Descriptor.rootPublicKey, .bytes(fabric.rootPublicKey)), .field(Descriptor.vendorId, .unsigned(UInt64(fabric.vendorID))),
                    .field(Descriptor.fabricId, .unsigned(fabric.fabricID)), .field(Descriptor.nodeId, .unsigned(fabric.nodeID)),
                    .field(Descriptor.label, .utf8(fabric.label)), .field(Descriptor.fabricIndex, .unsigned(UInt64(fabric.index))),
                ]))
            }
            // Fabric descriptors are not fabric-sensitive: an unfiltered read sees them all (Core §11.18.5.2).
            guard context.isFabricFiltered else { return .array(entries) }
            return FabricScopedList.read(.array(entries), context: context)
        }
        await cluster.provide(A.commissionedFabrics) { _ in .unsigned(UInt64(await fabrics.count)) }
        await cluster.provide(A.trustedRootCertificates) { _ in
            .array(await fabrics.all.map { TLVElement(.bytes($0.rootCertificate.tlvEncoded)) })
        }
        await cluster.provide(A.currentFabricIndex) { context in .unsigned(UInt64(context.fabricIndex ?? 0)) }
        // Fabric changes are reported to subscriptions.
        await fabrics.onChange { [weak cluster] _ in
            await cluster?.changed([A.nocs, A.fabrics, A.commissionedFabrics, A.trustedRootCertificates])
        }

        await cluster.handle(C.attestationRequest) { _, fields, context in
            let nonce = try TLVStruct(fields).bytes(0)
            guard nonce.count == 32 else { throw StatusError(.invalidCommand) }
            let elements = TLVEncoder.encode(.structure([
                .field(1, .bytes(attestation.certificationDeclaration)), .field(2, .bytes(nonce)),
                .field(3, .unsigned(UInt64(MatterCertificate.matterSeconds(Date())))),
            ]))
            let signature = try attestation.sign(elements, challenge: context.session.attestationChallenge)
            return .response(C.attestationResponse, .structure([.field(0, .bytes(elements)), .field(1, .bytes(signature))]))
        }
        await cluster.handle(C.certificateChainRequest) { _, fields, _ in
            let certificate: [UInt8]
            switch try TLVStruct(fields).uint(0) {
            case 1: certificate = attestation.dacCertificate
            case 2: certificate = attestation.paiCertificate
            default: throw StatusError(.invalidCommand)
            }
            return .response(C.certificateChainResponse, .structure([.field(0, .bytes(certificate))]))
        }
        await cluster.handle(C.csrRequest) { _, fields, context in
            let request = try TLVStruct(fields)
            let (elements, signature) = try await commissioning.csr(nonce: try request.bytes(0), forUpdate: request[1]?.bool ?? false,
                                                                    challenge: context.session.attestationChallenge, session: context.session)
            return .response(C.csrResponse, .structure([.field(0, .bytes(elements)), .field(1, .bytes(signature))]))
        }
        @Sendable func nocResponse(_ status: Commissioning.NOCStatus, _ index: FabricIndex? = nil) -> InvokeResult {
            var fields: [TLVElement] = [.field(0, .unsigned(UInt64(status.rawValue)))]
            if let index { fields.append(.field(1, .unsigned(UInt64(index)))) }
            return .response(C.nocResponse, .structure(fields))
        }
        await cluster.handle(C.addTrustedRootCertificate) { _, fields, context in
            try await commissioning.addTrustedRoot(try TLVStruct(fields).bytes(0), session: context.session)
            return .success
        }
        await cluster.handle(C.addNoc) { _, fields, context in
            let request = try TLVStruct(fields)
            let (status, index) = try await commissioning.addNOC(
                noc: try request.bytes(0), icac: request[1]?.bytes, ipk: try request.bytes(2), adminSubject: try request.uint(3),
                adminVendor: try request.uint(4, as: UInt16.self), session: context.session)
            return nocResponse(status, index)
        }
        await cluster.handle(C.updateNoc) { _, fields, context in
            guard let fabric = context.fabricIndex else { throw StatusError(.unsupportedAccess) }
            let request = try TLVStruct(fields)
            let status = try await commissioning.updateNOC(noc: try request.bytes(0), icac: request[1]?.bytes, session: context.session)
            return nocResponse(status, status == .ok ? fabric : nil)
        }
        await cluster.handle(C.updateFabricLabel) { _, fields, context in
            guard let index = context.fabricIndex, var fabric = await fabrics.fabric(index) else { throw StatusError(.unsupportedAccess) }
            let label = try TLVStruct(fields).string(0)
            guard label.utf8.count <= 32 else { throw StatusError(.constraintError) }
            // Labels are unique across fabrics, the empty one aside (Core §11.18.6.11).
            if !label.isEmpty, await fabrics.all.contains(where: { $0.label == label && $0.index != index }) { return nocResponse(.labelConflict) }
            fabric.label = label
            try await fabrics.update(fabric)
            return nocResponse(.ok, index)
        }
        await cluster.handle(C.removeFabric) { _, fields, _ in
            let index = try TLVStruct(fields).uint(0, as: UInt8.self)
            guard await fabrics.fabric(index) != nil else { return nocResponse(.invalidFabricIndex) }
            // The fabric's sessions end once this response is out.
            try await commissioning.removeFabric(index, closingSessionsAfter: .milliseconds(500))
            return nocResponse(.ok, index)
        }
        return cluster
    }

    // MARK: - Access Control (Core §9.10)

    static func accessControlCluster(_ entries: AccessControlEntries) async -> AttributeCluster {
        typealias A = AccessControlCluster.Attribute
        let subjectsLimit = 4, targetsLimit = 3, entriesLimit = 4
        let cluster = AttributeCluster(AccessControlCluster.definition, attributes: [
            A.subjectsPerAccessControlEntry: .unsigned(UInt64(subjectsLimit)), A.targetsPerAccessControlEntry: .unsigned(UInt64(targetsLimit)),
            A.accessControlEntriesPerFabric: .unsigned(UInt64(entriesLimit)),
        ])
        await cluster.provide(A.acl) { context in
            FabricScopedList.read(.array(await entries.all.map { TLVElement($0.tlv) }), context: context)
        }
        await cluster.onWrite { cluster, attribute, value, context in
            guard attribute == A.acl, let fabric = context.fabricIndex else { throw StatusError(.unsupportedAccess) }
            // The accessing fabric's entries, stamped by the merge whatever FabricIndex the writer gave (or left out).
            let written = FabricScopedList.entries(value, fabric: fabric)
            guard written.count <= entriesLimit else { throw StatusError(.resourceExhausted) }
            let parsed = try written.map { try AccessControlEntry(tlv: $0.value) }
            guard parsed.allSatisfy({ ($0.subjects?.count ?? 0) <= subjectsLimit && ($0.targets?.count ?? 0) <= targetsLimit }) else {
                throw StatusError(.resourceExhausted)
            }
            await entries.replace(fabric: fabric, with: parsed)
            await cluster.changed([A.acl])
        }
        return cluster
    }

    // MARK: - Group Key Management (Core §11.2)

    static func groupKeyManagement(_ groups: Groups) async -> AttributeCluster {
        typealias A = GroupKeyManagementCluster.Attribute
        typealias C = GroupKeyManagementCluster.Command
        let cluster = AttributeCluster(GroupKeyManagementCluster.definition, attributes: [
            A.maxGroupsPerFabric: .unsigned(UInt64(Groups.maxGroupsPerFabric)),
            // The IPK's set and the others (Core §11.2.6.4).
            A.maxGroupKeysPerFabric: .unsigned(UInt64(1 + Groups.maxKeySetsPerFabric)),
        ])
        await cluster.provide(A.groupKeyMap) { context in FabricScopedList.read(await groups.keyMap, context: context) }
        await cluster.provide(A.groupTable) { context in FabricScopedList.read(await groups.groupTable, context: context) }
        await cluster.onWrite { cluster, attribute, value, context in
            guard attribute == A.groupKeyMap, let fabric = context.fabricIndex else { throw StatusError(.unsupportedWrite) }
            try await groups.setKeyMap(FabricScopedList.entries(value, fabric: fabric), fabric: fabric)
            await cluster.changed([A.groupKeyMap])
        }
        @Sendable func fabric(_ context: AccessContext) throws -> FabricIndex {
            guard let fabric = context.fabricIndex else { throw StatusError(.unsupportedAccess) }
            return fabric
        }
        @Sendable func keySetID(_ fields: TLVValue) throws -> UInt16 {
            guard let value = fields[0]?.uint, let id = UInt16(exactly: value) else { throw StatusError(.invalidCommand) }
            return id
        }
        await cluster.handle(C.keySetWrite) { _, fields, context in
            guard let set = fields[0] else { throw StatusError(.invalidCommand) }
            try await groups.writeKeySet(set, fabric: try fabric(context))
            return .success
        }
        await cluster.handle(C.keySetRead) { _, fields, context in
            let id = try keySetID(fields)
            // The IPK's set (0) is read with its keys and times left out; the others as stored.
            let set = id == 0 ? .structure([
                .field(0, .unsigned(0)), .field(1, .unsigned(0)), .field(2, .null), .field(3, .null), .field(4, .null),
                .field(5, .null), .field(6, .null), .field(7, .null),
            ]) : await groups.keySetResponse(id, fabric: try fabric(context))
            guard let set else { throw StatusError(.notFound) }
            return .response(C.keySetReadResponse, .structure([.field(0, set)]))
        }
        await cluster.handle(C.keySetRemove) { cluster, fields, context in
            try await groups.removeKeySet(try keySetID(fields), fabric: try fabric(context))
            await cluster.changed([A.groupKeyMap])
            return .success
        }
        await cluster.handle(C.keySetReadAllIndices) { _, _, context in
            let ids = [0] + (await groups.keySetIDs(fabric: try fabric(context)))
            return .response(C.keySetReadAllIndicesResponse, .structure([.field(0, .array(ids.map { TLVElement(.unsigned(UInt64($0))) }))]))
        }
        return cluster
    }

    // MARK: - Network Commissioning (Core §11.9), Ethernet

    static func networkCommissioning() async -> AttributeCluster {
        typealias A = NetworkCommissioningCluster.Attribute
        typealias Info = NetworkCommissioningCluster.NetworkInfoStruct
        let cluster = AttributeCluster(NetworkCommissioningCluster.definition,
                                       featureMap: NetworkCommissioningCluster.Feature.ethernetNetworkInterface.rawValue, attributes: [
            A.maxNetworks: .unsigned(1),
            A.networks: .array([TLVElement(.structure([.field(Info.networkId, .bytes(Array("en0".utf8))), .field(Info.connected, .bool(true))]))]),
            A.interfaceEnabled: .bool(true), A.lastNetworkingStatus: .null, A.lastNetworkId: .null, A.lastConnectErrorValue: .null,
        ])
        await cluster.onWrite { _, attribute, value, _ in
            // The interface stays enabled: disabling it would cut the node off.
            guard attribute == A.interfaceEnabled, value == .bool(true) else { throw StatusError(.constraintError) }
        }
        return cluster
    }

    // MARK: - General Diagnostics (Core §11.12)

    static func generalDiagnostics(startTime: ContinuousClock.Instant) async -> AttributeCluster {
        typealias A = GeneralDiagnosticsCluster.Attribute
        typealias C = GeneralDiagnosticsCluster.Command
        let cluster = AttributeCluster(GeneralDiagnosticsCluster.definition, attributes: [
            A.rebootCount: .unsigned(0), A.bootReason: .unsigned(0), A.testEventTriggersEnabled: .bool(false),
        ])
        await cluster.provide(A.networkInterfaces) { _ in networkInterfaces() }
        await cluster.provide(A.upTime) { _ in .unsigned(UInt64((ContinuousClock.now - startTime).components.seconds)) }
        await cluster.handle(C.testEventTrigger) { _, _, _ in throw StatusError(.constraintError) }
        await cluster.handle(C.timeSnapshot) { _, _, _ in
            let system = UInt64((ContinuousClock.now - startTime) / .milliseconds(1))
            return .response(C.timeSnapshotResponse, .structure([.field(0, .unsigned(system)), .field(1, .unsigned(currentMilliseconds()))]))
        }
        return cluster
    }

    /// NetworkInterface structs (Core §11.12.6.4) of the host's multicast-capable interfaces.
    static func networkInterfaces() -> TLVValue {
        let devices = (try? System.enumerateDevices()) ?? []
        let names = Set(devices.filter { $0.multicastSupported && $0.address?.ipAddress.map(MDNSAdvertiser.isRoutable) == true }.map(\.name))
        return .array(names.sorted().map { name in
            let addresses = devices.filter { $0.name == name }.compactMap(\.address)
            func bytes(_ family: NIOBSDSocket.ProtocolFamily) -> [TLVElement] {
                addresses.filter { $0.protocol == family }.compactMap { address -> TLVElement? in
                    switch address {
                    case .v4(let v4): TLVElement(.bytes(withUnsafeBytes(of: v4.address.sin_addr) { Array($0) }))
                    case .v6(let v6): TLVElement(.bytes(withUnsafeBytes(of: v6.address.sin6_addr) { Array($0) }))
                    default: nil
                    }
                }
            }
            return TLVElement(.structure([
                .field(0, .utf8(String(name.prefix(32)))), .field(1, .bool(true)), .field(2, .null), .field(3, .null),
                .field(4, .bytes([UInt8](repeating: 0, count: 6))), .field(5, .array(bytes(.inet))), .field(6, .array(bytes(.inet6))),
                .field(7, .unsigned(2)), // Ethernet
            ]))
        })
    }

    // MARK: - Administrator Commissioning (Core §11.19)

    static func administratorCommissioning(_ commissioning: Commissioning) async -> AttributeCluster {
        typealias A = AdministratorCommissioningCluster.Attribute
        typealias C = AdministratorCommissioningCluster.Command
        let cluster = AttributeCluster(AdministratorCommissioningCluster.definition)
        await cluster.provide(A.windowStatus) { _ in
            switch await commissioning.windowStatus {
            case .closed: .unsigned(0)
            case .enhanced: .unsigned(1)
            case .basic: .unsigned(2)
            }
        }
        await cluster.provide(A.adminFabricIndex) { _ in await commissioning.windowAdmin.fabric.map { .unsigned(UInt64($0)) } ?? .null }
        await cluster.provide(A.adminVendorId) { _ in await commissioning.windowAdmin.vendor.map { .unsigned(UInt64($0)) } ?? .null }
        await commissioning.onWindowChange { [weak cluster] _, _ in
            await cluster?.changed([A.windowStatus, A.adminFabricIndex, A.adminVendorId])
        }
        await cluster.handle(C.openCommissioningWindow) { _, fields, context in
            let request = try TLVStruct(fields)
            let timeout = try request.uint(0, as: UInt16.self)
            let verifierBytes = try request.bytes(1)
            let discriminator = try request.uint(2, as: UInt16.self)
            let iterations = try request.uint(3)
            let salt = try request.bytes(4)
            // Busy: a window is open or a fail-safe is armed (cluster status 2, Core §11.19.7.1).
            guard await commissioning.windowStatus == .closed, await !commissioning.isFailSafeArmed else {
                throw StatusError(.failure, clusterStatus: 2)
            }
            guard (180...900).contains(timeout), discriminator <= 0x0FFF, let iterationCount = Int(exactly: iterations),
                  PBKDF2.iterationRange.contains(iterationCount),
                  (16...32).contains(salt.count), let verifier = try? SPAKE2Plus.Verifier(serialized: verifierBytes)
            else { throw StatusError(.failure, clusterStatus: 3) } // PAKEParameterError
            var vendor: UInt16?
            if let index = context.fabricIndex { vendor = await commissioning.fabrics.fabric(index)?.vendorID }
            await commissioning.open(.enhanced, verifier: PASEVerifier(verifier: verifier, salt: salt, iterations: iterationCount),
                                     discriminator: discriminator, timeout: .seconds(Int(timeout)), adminFabric: context.fabricIndex,
                                     adminVendor: vendor)
            return .success
        }
        await cluster.handle(C.revokeCommissioning) { _, _, _ in
            guard await commissioning.windowStatus != .closed else { throw StatusError(.failure, clusterStatus: 4) } // WindowNotOpen
            await commissioning.expire()
            await commissioning.close()
            return .success
        }
        return cluster
    }
}
