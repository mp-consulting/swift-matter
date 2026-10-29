import Testing
@testable import Matter

/// Vectors from matter.js's pairing code tests and connectedhomeip's default test device.
struct OnboardingTests {
    @Test func encodesAndDecodesTheQRCode() throws {
        let payload = SetupPayload(vendorID: 9050, productID: 65279, capabilities: .ble, discriminator: 2976, passcode: 34567890)
        #expect(payload.qrCode == "MT:YNJV7VSC00CMVH7SR00")
        #expect(try SetupPayload(qrCode: "MT:YNJV7VSC00CMVH7SR00") == payload)
        // With optional TLV data after the packed structure.
        #expect(try SetupPayload(qrCode: "MT:YNJV7VSC00CMVH7E4810AK00") == payload)
    }

    @Test func rejectsInvalidQRCodes() {
        #expect(throws: SetupPayloadError.invalidPasscode) { try SetupPayload(qrCode: "MT:YNJV7VSC00ANG46Y900") }
        #expect(throws: SetupPayloadError.unsupportedVersion) { try SetupPayload(qrCode: "MT:ZNJV7VSC00CMVH7SR00") }
        #expect(throws: SetupPayloadError.invalidPrefix) { try SetupPayload(qrCode: "YNJV7VSC00CMVH7SR00") }
        #expect(throws: SetupPayloadError.invalidCharacter) { try SetupPayload(qrCode: "MT:YNJV7VSC00CMVH7SR0a") }
    }

    @Test(arguments: [
        (UInt16(2976), UInt32(34567890), "26318621095"),
        (10, 23456780, "01127614316"),
        (2001, 23456789, "16043714310"),
        (3840, 20202021, "34970112332"),
    ])
    func encodesTheManualCode(discriminator: UInt16, passcode: UInt32, code: String) throws {
        let payload = SetupPayload(vendorID: 0xFFF1, productID: 0x8000, discriminator: discriminator, passcode: passcode)
        #expect(payload.manualCode == code)
        let parsed = try SetupPayload.parse(manualCode: code)
        #expect(parsed.passcode == passcode)
        #expect(parsed.shortDiscriminator == payload.shortDiscriminator)
    }

    @Test func includesTheIDsForANonStandardFlow() throws {
        let payload = SetupPayload(vendorID: 9050, productID: 65279, flow: .custom, discriminator: 2976, passcode: 34567890)
        #expect(payload.manualCode.count == 21)
        #expect(try SetupPayload.parse(manualCode: payload.manualCode).passcode == 34567890)
        let long = try SetupPayload.parse(manualCode: "749701123365524327693")
        #expect(long.passcode == 20202021)
        #expect(long.vendorID == 0xFFF4)
    }

    @Test func rejectsInvalidManualCodes() {
        #expect(throws: SetupPayloadError.invalidCheckDigit) { try SetupPayload.parse(manualCode: "34970112333") }
        #expect(throws: SetupPayloadError.invalidLength) { try SetupPayload.parse(manualCode: "3497011233") }
        // Dashes and spaces are ignored.
        #expect(throws: Never.self) { try SetupPayload.parse(manualCode: "3497-011-2332") }
    }

    @Test func generatesValidPasscodes() {
        for _ in 0..<100 { #expect(SetupPayload.isValid(passcode: SetupPayload.randomPasscode())) }
        #expect(!SetupPayload.isValid(passcode: 12345678))
        #expect(!SetupPayload.isValid(passcode: 99999999))
        #expect(!SetupPayload.isValid(passcode: 0))
    }
}
