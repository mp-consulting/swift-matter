import Testing
@testable import Matter

/// Core specification, Appendix A.12.
struct TLVTests {
    static let primitives: [(TLVValue, String)] = [
        (.bool(false), "08"),
        (.bool(true), "09"),
        (.signed(42), "002a"),
        (.signed(-17), "00ef"),
        (.unsigned(42), "042a"),
        (.signed(-170000), "02f067fdff"),
        (.signed(40000000000), "0300902f5009000000"),
        (.utf8("Hello!"), "0c0648656c6c6f21"),
        (.utf8("Tschüs"), "0c0754736368c3bc73"),
        (.bytes([0, 1, 2, 3, 4]), "10050001020304"),
        (.null, "14"),
        (.float(0), "0a00000000"),
        (.float(1.0 / 3.0), "0aabaaaa3e"),
        (.float(17.9), "0a33338f41"),
        (.float(.infinity), "0a0000807f"),
        (.double(1.0 / 3.0), "0b555555555555d53f"),
        (.double(17.9), "0b6666666666e63140"),
        (.double(-.infinity), "0b000000000000f0ff"),
        (.structure([]), "1518"),
        (.array([]), "1618"),
        (.list([]), "1718"),
        (.structure([.field(0, .signed(42)), .field(1, .signed(-17))]), "1520002a2001ef18"),
        (.array((0...4).map { TLVElement(.signed($0)) }), "1600000001000200030004 18"),
        (.list([TLVElement(.signed(1)), .field(0, .signed(42)), TLVElement(.signed(2)), TLVElement(.signed(3)), .field(0, .signed(-17))]),
         "17000120002a000200032000ef18"),
        (.array([TLVElement(.signed(42)), TLVElement(.signed(-170000)), TLVElement(.structure([])), TLVElement(.float(17.9)), TLVElement(.utf8("Hello!"))]),
         "16002a02f067fdff15180a33338f410c0648656c6c6f2118"),
    ]

    @Test(arguments: primitives)
    func encodesAndDecodes(value: TLVValue, encoding: String) throws {
        let bytes = hex(encoding.replacingOccurrences(of: " ", with: ""))
        #expect(TLVEncoder.encode(value) == bytes)
        #expect(try TLVDecoder.decode(bytes) == TLVElement(value))
    }

    static let tags: [(TLVTag, String)] = [
        (.anonymous, "042a"),
        (.context(1), "24012a"),
        (.commonProfile(1), "4401002a"),
        (.commonProfile(100000), "64a086010 02a"),
        (.fullyQualified(vendor: 0xFFF1, profile: 0xDEED, tag: 1), "c4f1ffedde01002a"),
        (.fullyQualified(vendor: 0xFFF1, profile: 0xDEED, tag: 0xAA55FEED), "e4f1ffeddeedfe55aa2a"),
    ]

    @Test(arguments: tags)
    func encodesTags(tag: TLVTag, encoding: String) throws {
        let bytes = hex(encoding.replacingOccurrences(of: " ", with: ""))
        #expect(TLVEncoder.encode(TLVElement(tag, .unsigned(42))) == bytes)
        #expect(try TLVDecoder.decode(bytes) == TLVElement(tag, .unsigned(42)))
    }

    @Test func decodesWiderIntegersThanNeeded() throws {
        #expect(try TLVDecoder.decode(hex("012a00")).value == .signed(42))
    }

    @Test func rejectsMalformedInput() {
        #expect(throws: TLVError.truncated) { try TLVDecoder.decode(hex("0c0548656c")) }
        #expect(throws: TLVError.missingEndOfContainer) { try TLVDecoder.decode(hex("1520002a")) }
        #expect(throws: TLVError.unexpectedEndOfContainer) { try TLVDecoder.decode(hex("18")) }
        #expect(throws: TLVError.reservedElementType(0x19)) { try TLVDecoder.decode(hex("19")) }
        #expect(throws: TLVError.trailingBytes) { try TLVDecoder.decode(hex("0808")) }
        #expect(throws: TLVError.invalidUTF8) { try TLVDecoder.decode(hex("0c01ff")) }
        #expect(throws: TLVError.tooDeep) { try TLVDecoder.decode([UInt8](repeating: 0x16, count: 40) + [UInt8](repeating: 0x18, count: 40)) }
        // A length larger than the input never allocates.
        #expect(throws: TLVError.truncated) { try TLVDecoder.decode(hex("12ffffffff")) }
    }

    @Test func readsStructureFields() throws {
        let fields = try TLVStruct(.structure([.field(1, .unsigned(7)), .field(2, .bytes([1, 2]))]))
        #expect(try fields.uint(1) == 7)
        #expect(try fields.bytes(2) == [1, 2])
        #expect(throws: TLVError.field(3)) { try fields.uint(3) }
        #expect(throws: TLVError.field(2)) { try fields.uint(2) }
    }
}
