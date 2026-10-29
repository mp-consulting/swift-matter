import Crypto
import Foundation
import Testing
@testable import Matter

/// Core §6.5.15.3: the same NOC in Matter TLV and in X.509.
struct CertificateTests {
    static let nocTLV = hex("""
        153001083efcff1702b9a17a24020137032713030000 00cacacaca18260 4ef171b272605 6eb5b94c370627110100010 0dededede27151d0000000000b0fa18240701240801300941\
        049a2a216fb39dd6b6fa211b835c89e3e6afb66c14f75831954f9ff4f7a3f0112c8a0d8eaf29c653294d48eee0708a03\
        2cca39393c3a7b46f181aea078fead8383370a350128011824020136030402040118300414 9f55a26b7e4303e60883e9\
        13bf94f4fb5e2a6161300514 5352d7059e9c15a50890686286 4801a29f1f41d318300b40 7955c202630b4ba4d5912526\
        322fdf28f89edfe5af9c0e572bd8a14aaabb4d12b83ca17c7b05fb164b77d79c529613316bcfd17895e4b2a4f2404b98\
        1732715918
        """.filter(\.isHexDigit))

    static let nocPEM = """
        MIIB4DCCAYagAwIBAgIIPvz/FwK5oXowCgYIKoZIzj0EAwIwIjEgMB4GCisGAQQB
        gqJ8AQMMEENBQ0FDQUNBMDAwMDAwMDMwHhcNMjAxMDE1MTQyMzQzWhcNNDAxMDE1
        MTQyMzQyWjBEMSAwHgYKKwYBBAGConwBAQwQREVERURFREUwMDAxMDAwMTEgMB4G
        CisGAQQBgqJ8AQUMEEZBQjAwMDAwMDAwMDAwMUQwWTATBgcqhkjOPQIBBggqhkjO
        PQMBBwNCAASaKiFvs53WtvohG4NciePmr7ZsFPdYMZVPn/T3o/ARLIoNjq8pxlMp
        TUju4HCKAyzKOTk8OntG8YGuoHj+rYODo4GDMIGAMAwGA1UdEwEB/wQCMAAwDgYD
        VR0PAQH/BAQDAgeAMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAd
        BgNVHQ4EFgQUn1Wia35DA+YIg+kTv5T0+14qYWEwHwYDVR0jBBgwFoAUU1LXBZ6c
        FaUIkGhihkgBop8fQdMwCgYIKoZIzj0EAwIDSAAwRQIgeVXCAmMLS6TVkSUmMi/f
        KPie3+WvnA5XK9ihSqq7TRICIQC4PKF8ewX7Fkt315xSlhMxa8/ReJXksqTyQEuY
        FzJxWQ==
        """

    @Test func decodesTheSpecificationsNOC() throws {
        let noc = try MatterCertificate(tlv: Self.nocTLV)
        #expect(noc.nodeID == 0xDEDE_DEDE_0001_0001)
        #expect(noc.fabricID == 0xFAB0_0000_0000_001D)
        #expect(noc.issuer == [.icacID(0xCACA_CACA_0000_0003)])
        #expect(noc.basicConstraints == .init(isCA: false))
        #expect(noc.keyUsage == .digitalSignature)
        #expect(noc.extendedKeyUsage == [2, 1])
        #expect(noc.tlvEncoded == Self.nocTLV)
    }

    @Test func convertsTheSpecificationsNOCToX509() throws {
        let noc = try MatterCertificate(tlv: Self.nocTLV)
        let der = Data(base64Encoded: Self.nocPEM.filter { !$0.isWhitespace })!
        #expect(try noc.x509 == Array(der))
    }

    @Test func signsAndVerifiesAChain() throws {
        let rootKey = P256.Signing.PrivateKey(), nodeKey = P256.Signing.PrivateKey()
        let rootPublic = Array(rootKey.publicKey.x963Representation)
        let rootVerifier = rootKey.publicKey
        var root = MatterCertificate(
            serialNumber: [1], issuer: [.rcacID(1)], notBefore: 0, notAfter: 0, subject: [.rcacID(1)], publicKey: rootPublic,
            basicConstraints: .init(isCA: true), keyUsage: [.keyCertSign, .crlSign],
            subjectKeyID: MatterCertificate.keyIdentifier(rootPublic), authorityKeyID: MatterCertificate.keyIdentifier(rootPublic))
        try root.sign(with: rootKey)
        #expect(root.isSigned(by: rootVerifier))
        #expect(root.isValid(at: Date()))

        var noc = MatterCertificate(
            serialNumber: [0x80, 2], issuer: [.rcacID(1)], notBefore: 1000, notAfter: 2_000_000_000,
            subject: [.nodeID(5), .fabricID(1), .caseAuthenticatedTag(0x0001_0001)], publicKey: Array(nodeKey.publicKey.x963Representation),
            basicConstraints: .init(isCA: false), keyUsage: .digitalSignature, extendedKeyUsage: [2, 1])
        try noc.sign(with: rootKey)
        #expect(noc.isSigned(by: root))
        #expect(!noc.isSigned(by: nodeKey.publicKey))
        #expect(!noc.isValid(at: Date(timeIntervalSince1970: MatterCertificate.epochOffset + 2_000_000_001)))
        // The TLV form round-trips, signature included.
        #expect(try MatterCertificate(tlv: noc.tlvEncoded) == noc)
        #expect(noc.caseAuthenticatedTags == [0x0001_0001])
        // The X.509 form parses as DER.
        #expect(try DER.parse(noc.x509).members?.count == 3)
    }

    @Test func rejectsMalformedCertificates() throws {
        var fields = try TLVDecoder.decode(Self.nocTLV).value.elements!
        fields[8] = .field(9, .bytes([4, 1, 2]))
        #expect(throws: CertificateError.invalidPublicKey) { try MatterCertificate(tlv: TLVValue.structure(fields)) }
    }

    @Test func encodesTimes() {
        #expect(MatterCertificate.time(0x271B17EF, isNotAfter: false) == .utcTime("201015142343Z"))
        #expect(MatterCertificate.time(0, isNotAfter: true) == .generalizedTime("99991231235959Z"))
        #expect(MatterCertificate.time(UInt32.max, isNotAfter: true) == .generalizedTime("21360207062815Z"))
    }

    @Test func encodesObjectIdentifiers() throws {
        let oid = DER.ObjectIdentifier("1.3.6.1.4.1.37244.1.1")
        #expect(DER.objectIdentifier(oid).encoded == hex("060a2b0601040182a27c0101"))
        #expect(try DER.parse(DER.objectIdentifier(oid).encoded) == .objectIdentifier(oid))
    }
}

extension CertificateTests {
    @Test func rejectsKnownExtensionsDisguisedAsFutureOnes() throws {
        var fields = try TLVDecoder.decode(Self.nocTLV).value.elements!
        let basicConstraints = DER.sequence([.objectIdentifier(OID.basicConstraints), .boolean(true), .octetString(DER.sequence([]).encoded)])
        fields[9] = .field(10, .list([.field(6, .bytes(basicConstraints.encoded))]))
        #expect(throws: CertificateError.invalidExtension) { try MatterCertificate(tlv: TLVValue.structure(fields)) }
    }
}
