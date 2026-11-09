import Crypto
import Foundation
import Testing
@testable import Matter

/// Device attestation as a commissioner validates it (Core §6.2.3.1), against connectedhomeip's test PKI and the
/// Matter registry's roots.
struct AttestationVerifierTests {
    static let nonce = MatterCrypto.random(32)
    static let challenge = MatterCrypto.random(16)

    /// What a device with `attestation` answers, as swift-matter's node does (Core §11.18.4.6).
    static func information(_ attestation: DeviceAttestation, vendorID: UInt16 = 0xFFF1, productID: UInt16 = 0x8000,
                            nonce: [UInt8] = nonce) throws -> AttestationInformation {
        let elements = TLVEncoder.encode(.structure([
            .field(1, .bytes(attestation.certificationDeclaration)), .field(2, .bytes(nonce)), .field(3, .unsigned(0)),
        ]))
        return AttestationInformation(dac: attestation.dacCertificate, pai: attestation.paiCertificate, elements: elements,
                                      signature: try attestation.sign(elements, challenge: challenge), challenge: challenge,
                                      nonce: Self.nonce, vendorID: vendorID, productID: productID)
    }

    /// The test device with its declaration replaced by `declaration`, signed with the test key.
    static func device(_ declaration: CertificationDeclaration) throws -> DeviceAttestation {
        var attestation = try DeviceAttestation.test()
        attestation.certificationDeclaration = try declaration.signed(
            with: P256.Signing.PrivateKey(rawRepresentation: TestCredentials.cdSigningPrivateKey), keyIdentifier: TestCredentials.cdSigningKeyIdentifier)
        return attestation
    }

    static func declaration(type: UInt8 = 0) -> CertificationDeclaration {
        CertificationDeclaration(vendorID: 0xFFF1, productIDs: [0x8000], deviceType: 0x000E, certificateID: "ZIG20142ZB330003-24",
                                 versionNumber: 0x2694, certificationType: type)
    }

    static func expect(_ failure: AttestationFailure, _ info: AttestationInformation, _ store: AttestationTrustStore = .test) {
        #expect(throws: failure) { try AttestationVerifier.verify(info, trusting: store) }
    }

    @Test func verifiesATestDeviceAgainstTheTestPKI() throws {
        let ids = try AttestationVerifier.verify(try Self.information(.test()), trusting: .test)
        #expect(ids.vendorID == 0xFFF1 && ids.productID == 0x8000)
    }

    @Test func refusesATestDeviceAgainstTheRegistry() throws {
        Self.expect(.untrustedRoot, try Self.information(.test()), .registry)
        // The registry and the test PKI together take it.
        try AttestationVerifier.verify(try Self.information(.test()), trusting: .registry.adding(.test))
    }

    @Test func refusesAWrongNonceOrSignature() throws {
        Self.expect(.nonceMismatch, try Self.information(.test(), nonce: MatterCrypto.random(32)))
        var info = try Self.information(.test())
        info.challenge = MatterCrypto.random(16)
        Self.expect(.attestationSignature, info)
    }

    @Test func refusesADeclarationThatDoesNotCoverTheDevice() throws {
        // Basic Information's vendor and product SHALL be the declaration's.
        Self.expect(.declarationVendor, try Self.information(.test(), vendorID: 0xFFF2))
        Self.expect(.declarationProduct, try Self.information(.test(), productID: 0x8001))
    }

    @Test func takesTheTestKeyOnlyForDevelopmentDeclarations() throws {
        Self.expect(.unknownDeclarationSigner, try Self.information(Self.device(Self.declaration(type: 2))))
        Self.expect(.unknownDeclarationSigner, try Self.information(Self.device(Self.declaration(type: 1))))
        var store = AttestationTrustStore.test
        store.allowsTestDeclarations = false
        Self.expect(.unknownDeclarationSigner, try Self.information(.test()), store)
    }

    @Test func checksTheDACOriginAndTheAuthorizedPAAs() throws {
        var declaration = Self.declaration()
        declaration.dacOriginVendorID = 0xFFF1
        Self.expect(.malformedDeclaration, try Self.information(Self.device(declaration)))   // one without the other
        declaration.dacOriginProductID = 0x8000
        try AttestationVerifier.verify(try Self.information(Self.device(declaration)), trusting: .test)
        declaration.dacOriginProductID = 0x8001
        Self.expect(.declarationProduct, try Self.information(Self.device(declaration)))

        let paaKeyID = MatterCertificate.keyIdentifier(Array(try P256.Signing.PrivateKey(rawRepresentation: TestCredentials.paaPrivateKey)
            .publicKey.x963Representation))
        declaration = Self.declaration()
        declaration.authorizedPAAs = [MatterCrypto.random(20), paaKeyID]
        try AttestationVerifier.verify(try Self.information(Self.device(declaration)), trusting: .test)
        declaration.authorizedPAAs = [MatterCrypto.random(20)]
        Self.expect(.declarationPAA, try Self.information(Self.device(declaration)))
    }

    @Test func refusesAPAIThatIsNotTheDACsIssuer() throws {
        var info = try Self.information(.test())
        info.pai = try DeviceAttestation.test().paiCertificate
        Self.expect(.invalidChain, info)
        info.pai = info.dac
        Self.expect(.malformedCertificate("PAI"), info)
    }

    // MARK: - Trust store

    @Test func theRegistryRootsAreSelfSignedPAAs() throws {
        let roots = AttestationTrustStore.registry.paaCertificates
        #expect(roots.count == AttestationTrustStore.registryPAAs.count && roots.count >= 70)
        for root in roots {
            let paa = try X509.parse(root)
            #expect(paa.isCA == true && paa.subjectKeyID?.count == 20 && paa.productID == nil)
            #expect(X509.isSigned(root, by: root))
        }
        // IKEA's (vendor 0x117C), which roots the BILRESA's chain.
        #expect(try roots.contains { try X509.parse($0).vendorID == 0x117C })
    }

    @Test func theCSADeclarationKeysAreIssuedByItsCA() throws {
        let ca = try #require(Data(base64Encoded: AttestationTrustStore.csaCertificationCA)).map { $0 }
        let signers = AttestationTrustStore.registry.declarationSigners
        #expect(signers.count == 5)
        #expect(signers.allSatisfy { X509.isSigned($0, by: ca) })
        // "Signing Key 001", as connectedhomeip lists it.
        #expect(try X509.parse(signers[0]).subjectKeyID == [0xFE, 0x34, 0x3F, 0x95, 0x99, 0x47, 0x76, 0x3B, 0x61, 0xEE,
                                                            0x45, 0x39, 0x13, 0x13, 0x38, 0x49, 0x4F, 0xE6, 0x7D, 0x8E])
    }

    // MARK: - Certificate fields

    static func subject(_ commonName: String, vendor: String? = nil) -> DER {
        var rdns: [DER] = [.set([.sequence([.objectIdentifier(OID.commonName), .utf8String(commonName)])])]
        if let vendor { rdns.append(.set([.sequence([.objectIdentifier(OID.matterVendorID), .utf8String(vendor)])])) }
        return .sequence(rdns)
    }

    /// Vendor and product ids in the common name, the fallback of Core §6.2.2.2, and the strict four-digit form.
    @Test func readsVendorAndProductIDsAsTheSpecificationEncodesThem() throws {
        let fallback = try X509.identifiers(Self.subject("ACME Matter Devel DAC 5CDA9899 Mvid:FFF1 Mpid:00B1"))
        #expect(fallback.vendorID == 0xFFF1 && fallback.productID == 0x00B1)
        // The leftmost well-formed match counts.
        #expect(try X509.identifiers(Self.subject("Mvid:12 Mvid:FFF2 Mvid:FFF3")).vendorID == 0xFFF2)
        #expect(throws: AttestationError.malformedCertificate) { try X509.identifiers(Self.subject("Mvid:fff1")) }
        #expect(throws: AttestationError.malformedCertificate) { try X509.identifiers(Self.subject("DAC", vendor: "FFF")) }
        #expect(throws: AttestationError.malformedCertificate) { try X509.identifiers(Self.subject("Mvid:FFF1", vendor: "FFF1")) }
        #expect(try X509.identifiers(Self.subject("DAC", vendor: "FFF1")).vendorID == 0xFFF1)
    }

    @Test func readsBothTimeEncodings() throws {
        let utc = try #require(X509.time(.utcTime("490101000000Z")))
        #expect(utc == Date(timeIntervalSince1970: 2_493_072_000))
        #expect(X509.time(.utcTime("500101000000Z")) == Date(timeIntervalSince1970: -631_152_000))
        #expect(X509.time(.generalizedTime("99991231235959Z")) == Date(timeIntervalSince1970: 253_402_300_799))
        #expect(X509.time(.generalizedTime("20221301000000Z")) == nil)
    }
}
