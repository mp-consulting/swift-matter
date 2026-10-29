import Crypto
import Testing
@testable import Matter

struct AttestationTests {
    /// Core Appendix F.1's first Certification Declaration.
    let vectorContent = hex("152400012501f1ff360205008018250334122c04135a494732303134315a423333303030312d32342405002406002507942624080018")
    let vectorCMS = hex("""
        3081e806092a864886f70d010702a081da3081d7020103310d300b0609608648016503040201304506092a864886f70d010701a038043615\
        2400012501f1ff360205008018250334122c04135a494732303134315a423333303030312d32342405002406002507942624080018317c30\
        7a020103801462fa823359acfaa9963e1cfa140addf504f37160300b0609608648016503040201300a06082a8648ce3d0403020446304402\
        2043a63f2b943df33c38b3e02fcaa75fe3532aebbf5e63f5bbdbc0b1f01d3c4f6002204c1abf5f1807b81894b1576c47e4724e4d966c612e\
        d3fa25c118c3f2b3f90369
        """)

    var declaration: CertificationDeclaration {
        CertificationDeclaration(vendorID: 0xFFF1, productIDs: [0x8000], deviceType: 0x1234, certificateID: "ZIG20141ZB330001-24",
                                 versionNumber: 0x2694, certificationType: 0)
    }

    @Test func encodesTheSpecificationsDeclaration() throws {
        #expect(declaration.content == vectorContent)
        let key = try P256.Signing.PrivateKey(rawRepresentation: TestCredentials.cdSigningPrivateKey)
        #expect(try CertificationDeclaration.verify(vectorCMS, key: key.publicKey) == vectorContent)

        // Ours has the same layout; only the (randomized) signature differs.
        let ours = try declaration.signed(with: key, keyIdentifier: TestCredentials.cdSigningKeyIdentifier)
        #expect(try CertificationDeclaration.verify(ours, key: key.publicKey) == vectorContent)
        #expect(Array(ours.prefix(0x6D).dropFirst(3)) == Array(vectorCMS.prefix(0x6D).dropFirst(3)) || ours.count != vectorCMS.count)
        #expect(throws: AttestationError.invalidSignature) {
            try CertificationDeclaration.verify(ours, key: P256.Signing.PrivateKey().publicKey)
        }
    }

    @Test func chainsTheDACToTheTestPAA() throws {
        let attestation = try DeviceAttestation.test(vendorID: 0xFFF1, productID: 0x8001)
        #expect(X509.isSigned(attestation.dacCertificate, by: attestation.paiCertificate))
        #expect(X509.isSigned(attestation.paiCertificate, by: TestCredentials.paaCertificate))
        #expect(!X509.isSigned(attestation.dacCertificate, by: TestCredentials.paaCertificate))
        let dac = try X509.parse(attestation.dacCertificate)
        #expect(dac.vendorID == 0xFFF1)
        #expect(dac.productID == 0x8001)
        #expect(Array(dac.publicKey.x963Representation) == Array(try attestation.dacKey.publicKey.x963Representation))
        #expect(try X509.parse(TestCredentials.paaCertificate).vendorID == 0xFFF1)
    }

    @Test func createsVerifiableCSRs() throws {
        let key = P256.Signing.PrivateKey()
        let csr = try CertificationRequest.create(key: key)
        #expect(try CertificationRequest.publicKey(of: csr).x963Representation == key.publicKey.x963Representation)
        var tampered = csr
        tampered[tampered.count - 5] ^= 1
        #expect(throws: (any Error).self) { try CertificationRequest.publicKey(of: tampered) }
    }
}
