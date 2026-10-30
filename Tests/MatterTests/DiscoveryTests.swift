import Testing
@testable import Matter

struct DiscoveryTests {
    /// A host with IPv4 only is told controllers will not reach it; one IPv6 address, link-local included, is enough.
    @Test func warnsWhenNoIPv6AddressIsAdvertised() {
        #expect(MDNSAdvertiser.ipv6Warning([.a([192, 168, 2, 85])])?.contains("no IPv6 address") == true)
        #expect(MDNSAdvertiser.ipv6Warning([.a([192, 168, 2, 85]), .aaaa([0xFE, 0x80] + Array(repeating: 0, count: 13) + [1])]) == nil)
    }

    var records: MatterRecords {
        var records = MatterRecords(host: DNSName(["AABBCCDDEEFF", "local"]), addresses: [.aaaa(Array(repeating: 1, count: 16))],
                                    commissionableInstance: "DD200C20D25AE5F7")
        records.commissionable = CommissionableAdvertisement(discriminator: 3840, vendorID: 0xFFF1, productID: 0x8000, commissioningMode: 1,
                                                             deviceType: 14, deviceName: "Bridge", port: 5540, parameters: .default)
        records.operational = [OperationalAdvertisement(compressedFabricID: hex("87e1b004e235a130"), nodeID: 0x42, port: 5540,
                                                        parameters: .default)]
        return records
    }

    @Test func answersCommissionableBrowses() throws {
        // Browsing by long discriminator (Core §4.3.1.3): the PTR, then SRV, TXT and the host's address as additionals.
        let (answers, additionals) = records.answer([DNSQuestion(name: DNSName(dotted: "_L3840._sub._matterc._udp.local"), type: DNSType.ptr)])
        #expect(answers.map(\.data) == [.ptr(DNSName(dotted: "DD200C20D25AE5F7._matterc._udp.local"))])
        #expect(Set(additionals.map(\.type)) == [DNSType.srv, DNSType.txt, DNSType.aaaa])
        guard case .txt(let txt)? = additionals.first(where: { $0.type == DNSType.txt })?.data else { Issue.record("No TXT"); return }
        let entries = parseTXT(txt)
        #expect(entries["D"] == "3840")
        #expect(entries["CM"] == "1")
        #expect(entries["VP"] == "65521+32768")
        #expect(entries["SII"] == "500")
        for subtype in ["_S15", "_V65521", "_T14", "_CM"] {
            let (subtypeAnswers, _) = records.answer([DNSQuestion(name: DNSName(dotted: "\(subtype)._sub._matterc._udp.local"), type: DNSType.ptr)])
            #expect(subtypeAnswers.count == 1)
        }
    }

    @Test func answersOperationalQueries() {
        let instance = DNSName(dotted: "87E1B004E235A130-0000000000000042._matter._tcp.local")
        let (answers, _) = records.answer([DNSQuestion(name: DNSName(dotted: "_matter._tcp.local"), type: DNSType.ptr)])
        #expect(answers.map(\.data) == [.ptr(instance)])
        let (srv, _) = records.answer([DNSQuestion(name: instance, type: DNSType.srv)])
        #expect(srv.map(\.data) == [.srv(priority: 0, weight: 0, port: 5540, target: DNSName(dotted: "AABBCCDDEEFF.local"))])
        let (filtered, _) = records.answer([DNSQuestion(name: DNSName(dotted: "_I87E1B004E235A130._sub._matter._tcp.local"), type: DNSType.ptr)])
        #expect(filtered.count == 1)
    }

    @Test func encodesAndParsesMessages() throws {
        let message = DNSMessage(isResponse: true, answers: records.all)
        let parsed = try DNSMessage(bytes: message.encode())
        #expect(parsed.answers.count == records.all.count)
        #expect(Set(parsed.answers.map(\.name)) == Set(records.all.map(\.name)))
    }

    func parseTXT(_ bytes: [UInt8]) -> [String: String] {
        var entries: [String: String] = [:]
        var index = 0
        while index < bytes.count {
            let length = Int(bytes[index])
            let entry = String(decoding: bytes[(index + 1)..<(index + 1 + length)], as: UTF8.self)
            let parts = entry.split(separator: "=", maxSplits: 1)
            entries[String(parts[0])] = parts.count > 1 ? String(parts[1]) : ""
            index += 1 + length
        }
        return entries
    }

    /// A link-local address is answered only on its own link, and the loopback interface's not at all (RFC 6762 §6.2):
    /// a controller hearing lo0's fe80::1 on en5 would scope it to en5, where it is no one.
    @Test func keepsLinkLocalAddressesOnTheirLink() {
        #expect(MDNSAdvertiser.isLinkLocal([0xFE, 0x80] + Array(repeating: 0, count: 13) + [1]))
        #expect(MDNSAdvertiser.isLinkLocal([0xFE, 0xBF] + Array(repeating: 0, count: 14)))
        #expect(!MDNSAdvertiser.isLinkLocal([0xFD, 0x48] + Array(repeating: 0, count: 14)))
        #expect(!MDNSAdvertiser.isLinkLocal([0xFE, 0xC0] + Array(repeating: 0, count: 14)))
    }
}
