import Logging
import NIOCore
import NIOPosix

/// The DNS-SD records a node advertises (Core §4.3): the commissionable service while a window is open, and one
/// operational instance per fabric, on the host's addresses.
struct MatterRecords: Sendable {
    static let ttl: UInt32 = 120
    static let commissionableService = DNSName(dotted: "_matterc._udp.local")
    static let operationalService = DNSName(dotted: "_matter._tcp.local")
    static let serviceEnumeration = DNSName(dotted: "_services._dns-sd._udp.local")

    var host: DNSName
    var addresses: [DNSRecord.Data]
    var commissionable: CommissionableAdvertisement?
    /// The commissionable instance name: 64 random bits, new for each window (Core §4.3.1.1).
    var commissionableInstance: String
    var operational: [OperationalAdvertisement] = []

    static func subtype(_ label: String, of service: DNSName) -> DNSName { DNSName([label, "_sub"] + service.labels) }

    static func txt(_ entries: [(String, String)]) -> [UInt8] {
        entries.flatMap { key, value -> [UInt8] in
            let entry = Array("\(key)=\(value)".utf8.prefix(255))
            return [UInt8(entry.count)] + entry
        }
    }

    static func sessionTXT(_ parameters: SessionParameters) -> [(String, String)] {
        [("SII", String(parameters.idleInterval.milliseconds)), ("SAI", String(parameters.activeInterval.milliseconds)),
         ("SAT", String(parameters.activeThreshold.milliseconds)), ("T", "0")]
    }

    /// Every record, grouped as answers: what a query may be answered with.
    var all: [DNSRecord] {
        var records: [DNSRecord] = addresses.map { DNSRecord(name: host, data: $0, ttl: Self.ttl, cacheFlush: true) }
        var services: [DNSName] = []
        if let commissionable {
            let service = Self.commissionableService
            services.append(service)
            let instance = DNSName([commissionableInstance] + service.labels)
            let short = commissionable.discriminator >> 8
            for label in ["_L\(commissionable.discriminator)", "_S\(short)", "_V\(commissionable.vendorID)", "_T\(commissionable.deviceType)", "_CM"] {
                records.append(DNSRecord(name: Self.subtype(label, of: service), data: .ptr(instance), ttl: Self.ttl))
            }
            records.append(DNSRecord(name: service, data: .ptr(instance), ttl: Self.ttl))
            records.append(DNSRecord(name: instance, data: .srv(priority: 0, weight: 0, port: UInt16(commissionable.port), target: host),
                                     ttl: Self.ttl, cacheFlush: true))
            records.append(DNSRecord(name: instance, data: .txt(Self.txt([
                ("D", String(commissionable.discriminator)), ("CM", String(commissionable.commissioningMode)),
                ("VP", "\(commissionable.vendorID)+\(commissionable.productID)"), ("DT", String(commissionable.deviceType)),
                ("DN", commissionable.deviceName),
            ] + Self.sessionTXT(commissionable.parameters))), ttl: Self.ttl, cacheFlush: true))
        }
        if !operational.isEmpty { services.append(Self.operationalService) }
        for advertisement in operational {
            let service = Self.operationalService
            let fabric = hexString(advertisement.compressedFabricID)
            let instance = DNSName(["\(fabric)-\(zeroPadded(advertisement.nodeID, width: 16, radix: 16))"] + service.labels)
            records.append(DNSRecord(name: service, data: .ptr(instance), ttl: Self.ttl))
            records.append(DNSRecord(name: Self.subtype("_I\(fabric)", of: service), data: .ptr(instance), ttl: Self.ttl))
            records.append(DNSRecord(name: instance, data: .srv(priority: 0, weight: 0, port: UInt16(advertisement.port), target: host),
                                     ttl: Self.ttl, cacheFlush: true))
            records.append(DNSRecord(name: instance, data: .txt(Self.txt(Self.sessionTXT(advertisement.parameters))), ttl: Self.ttl,
                                     cacheFlush: true))
        }
        records += services.map { DNSRecord(name: Self.serviceEnumeration, data: .ptr($0), ttl: Self.ttl) }
        return records
    }

    /// The answers to a query's questions, and the additional records that save the querier a round trip.
    func answer(_ questions: [DNSQuestion]) -> (answers: [DNSRecord], additionals: [DNSRecord]) {
        Self.answer(questions, index: Dictionary(grouping: all, by: \.name), host: host)
    }

    /// Answers from records indexed by name (the advertiser keeps the index between queries).
    static func answer(_ questions: [DNSQuestion], index: [DNSName: [DNSRecord]], host: DNSName) -> (answers: [DNSRecord], additionals: [DNSRecord]) {
        var answers: [DNSRecord] = []
        for question in questions {
            answers += (index[question.name] ?? []).filter { question.type == DNSType.any || question.type == $0.type }
        }
        var additionals: [DNSRecord] = []
        for answer in answers {
            if case .ptr(let instance) = answer.data { additionals += index[instance] ?? [] }
            if case .srv = answer.data { additionals += index[host] ?? [] }
        }
        if additionals.contains(where: { if case .srv = $0.data { true } else { false } }) {
            additionals += index[host] ?? []
        }
        var seen = Set<DNSRecord>(answers)
        return (Array(answers.uniqued()), additionals.filter { seen.insert($0).inserted })
    }
}

extension Array where Element: Hashable {
    func uniqued() -> [Element] {
        var seen = Set<Element>()
        return filter { seen.insert($0).inserted }
    }
}

/// A built-in mDNS responder (RFC 6762) for a node's DNS-SD records, on IPv4 and IPv6: it answers queries on
/// 224.0.0.251 and ff02::fb, port 5353, and announces changes.
public actor MDNSAdvertiser: NodeAdvertiser {
    static let port = 5353
    private let group: EventLoopGroup
    private let logger: Logger
    private var records: MatterRecords
    /// The records by name, rebuilt when they change rather than for every query.
    private var index: [DNSName: [DNSRecord]] = [:]
    private var channels: [Channel] = []
    private var started = false

    /// `hostName` is the label of `<hostName>.local`; a random one by default.
    public init(hostName: String? = nil, group: EventLoopGroup = MultiThreadedEventLoopGroup.singleton,
                logger: Logger = Logger(label: "matter.mdns")) {
        self.group = group
        self.logger = logger
        let host = hostName ?? hexString(MatterCrypto.random(6))
        records = MatterRecords(host: DNSName([host, "local"]), addresses: [], commissionableInstance: Self.randomInstance())
    }

    static func randomInstance() -> String { hexString(MatterCrypto.random(8)) }

    public func advertiseCommissionable(_ advertisement: CommissionableAdvertisement?) async {
        await update {
            if advertisement != nil, $0.commissionable == nil { $0.commissionableInstance = Self.randomInstance() }
            $0.commissionable = advertisement
        }
    }

    public func advertiseOperational(_ advertisements: [OperationalAdvertisement]) async {
        await update { $0.operational = advertisements }
    }

    public func stop() async {
        await send(DNSMessage(isResponse: true, answers: goodbye(records.all)))
        for channel in channels { try? await channel.close() }
        channels = []
        started = false
    }

    /// Applies a change, says goodbye to records that went away and announces the rest (RFC 6762 §8.3, §10.1).
    private func update(_ change: (inout MatterRecords) -> Void) async {
        let before = records.all
        change(&records)
        if !started { await start() }
        let after = records.all
        index = Dictionary(grouping: after, by: \.name)
        let current = Set(after.map { RecordKey(name: $0.name, data: $0.data) })
        let removed = before.filter { !current.contains(RecordKey(name: $0.name, data: $0.data)) }
        if !removed.isEmpty { await send(DNSMessage(isResponse: true, answers: goodbye(removed))) }
        guard !after.isEmpty else { return }
        let announcement = DNSMessage(isResponse: true, answers: after)
        await send(announcement)
        // A second announcement a second later, as RFC 6762 §8.3 asks.
        Task { [weak self] in
            try? await Task.sleep(for: .seconds(1))
            await self?.send(announcement)
        }
    }

    private func goodbye(_ records: [DNSRecord]) -> [DNSRecord] {
        records.map { var record = $0; record.ttl = 0; return record }
    }

    // MARK: - Network

    private func start() async {
        started = true
        let devices = (try? System.enumerateDevices()) ?? []
        records.addresses = devices.compactMap { device -> DNSRecord.Data? in
            guard device.multicastSupported, let address = device.address, address.ipAddress.map(Self.isRoutable) == true else { return nil }
            switch address {
            case .v4(let v4): return .a(withUnsafeBytes(of: v4.address.sin_addr) { Array($0) })
            case .v6(let v6): return .aaaa(withUnsafeBytes(of: v6.address.sin6_addr) { Array($0) })
            default: return nil
            }
        }.uniqued()
        // One socket per interface and family, so queries are answered on the link they came from.
        for device in devices where device.multicastSupported {
            guard let address = device.address else { continue }
            let isV6 = address.protocol == .inet6
            if let channel = await bind(device: device, ipv6: isV6) { channels.append(channel) }
        }
        if channels.isEmpty { logger.warning("mDNS: no multicast interface to advertise on") }
    }

    static func isRoutable(_ ip: String) -> Bool { !(ip.hasPrefix("127.") || ip == "::1") }

    private func bind(device: NIONetworkDevice, ipv6: Bool) async -> Channel? {
        let groupAddress = ipv6 ? "ff02::fb" : "224.0.0.251"
        do {
            let channel = try await DatagramBootstrap(group: group)
                .channelOption(.socketOption(.so_reuseaddr), value: 1)
                .channelOption(.socketOption(.so_reuseport), value: 1)
                .channelInitializer { [weak self] channel in
                    channel.eventLoop.makeCompletedFuture {
                        try channel.pipeline.syncOperations.addHandler(Inbound { [weak self] bytes, sender in
                            Task { await self?.receive(bytes, from: sender, on: channel) }
                        })
                    }
                }
                .bind(host: ipv6 ? "::" : "0.0.0.0", port: Self.port)
                .get()
            guard let multicast = channel as? MulticastChannel, let options = channel as? SocketOptionProvider else {
                try? await channel.close()
                return nil
            }
            try await multicast.joinGroup(try SocketAddress(ipAddress: groupAddress, port: Self.port), device: device).get()
            if ipv6 {
                try await options.setIPv6MulticastIF(CUnsignedInt(device.interfaceIndex)).get()
            } else if case .v4(let v4)? = device.address {
                try await options.setIPMulticastIF(v4.address.sin_addr).get()
            }
            return channel
        } catch {
            logger.debug("mDNS: cannot listen on \(device.name) (\(ipv6 ? "IPv6" : "IPv4")): \(error)")
            return nil
        }
    }

    private func send(_ message: DNSMessage) async {
        let bytes = message.encode()
        for channel in channels {
            let ipv6 = channel.localAddress?.protocol == .inet6
            guard let destination = try? SocketAddress(ipAddress: ipv6 ? "ff02::fb" : "224.0.0.251", port: Self.port) else { continue }
            try? await channel.writeAndFlush(AddressedEnvelope(remoteAddress: destination, data: channel.allocator.buffer(bytes: bytes)))
        }
    }

    private func receive(_ bytes: [UInt8], from sender: SocketAddress, on channel: Channel) async {
        guard let query = try? DNSMessage(bytes: bytes), !query.isResponse, !query.questions.isEmpty else { return }
        let (answers, additionals) = MatterRecords.answer(query.questions, index: index, host: records.host)
        guard !answers.isEmpty else { return }
        // A legacy querier (not from port 5353) gets a unicast reply that echoes its id and questions (RFC 6762 §6.7).
        let legacy = sender.port != Self.port
        let unicast = legacy || query.questions.contains(where: \.unicastResponse)
        var response = DNSMessage(isResponse: true, answers: answers, additionals: additionals)
        if legacy {
            response.id = query.id
            response.questions = query.questions
            response.answers = answers.map { var record = $0; record.ttl = min(record.ttl, 10); return record }
        }
        let destination = unicast ? sender : (try? SocketAddress(ipAddress: channel.localAddress?.protocol == .inet6 ? "ff02::fb" : "224.0.0.251",
                                                                  port: Self.port)) ?? sender
        try? await channel.writeAndFlush(AddressedEnvelope(remoteAddress: destination, data: channel.allocator.buffer(bytes: response.encode())))
    }

    private struct RecordKey: Hashable {
        var name: DNSName
        var data: DNSRecord.Data
    }

    private final class Inbound: ChannelInboundHandler, Sendable {
        typealias InboundIn = AddressedEnvelope<ByteBuffer>
        let receive: @Sendable ([UInt8], SocketAddress) -> Void

        init(receive: @escaping @Sendable ([UInt8], SocketAddress) -> Void) { self.receive = receive }

        func channelRead(context: ChannelHandlerContext, data: NIOAny) {
            let envelope = unwrapInboundIn(data)
            receive(Array(envelope.data.readableBytesView), envelope.remoteAddress)
        }
    }
}
