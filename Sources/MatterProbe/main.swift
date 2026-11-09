import Foundation
import Logging
import Matter
import NIOCore

// matter-probe: joins a Matter device as an extra administrator (its own fabric, through a commissioning window another
// controller opened) and prints what it is and every event it sends. A spike for controller support, not a product.
//
//   matter-probe commission <ipv6> <port> <manual pairing code> [--state <file>]
//   matter-probe watch <ipv6> <port> [--state <file>]
//   matter-probe forget <ipv6> <port> [--state <file>]
//   matter-probe attest <ipv6> <port> [--state <file>] [--node <hex node id>]
//
// `commission` verifies the device's attestation against the Matter registry's roots (Core §6.2.3.1). `attest` runs that
// check again over CASE on a device already commissioned (its node id in hex with --node, when another tool commissioned
// it on the same fabric).
//
// The state file holds the fabric's private keys: it is written owner-only. MATTER_PROBE_DEBUG=1 logs the protocol.

LoggingSystem.bootstrap { label in
    var handler = StreamLogHandler.standardError(label: label)
    handler.logLevel = ProcessInfo.processInfo.environment["MATTER_PROBE_DEBUG"] != nil ? .debug : .warning
    return handler
}


func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}

func say(_ message: String) {
    let time = Date().formatted(.dateTime.hour().minute().second())
    // Unbuffered, so each line shows at once when piped (Glibc's `stdout` is not concurrency-safe to flush).
    FileHandle.standardOutput.write(Data("[\(time)] \(message)\n".utf8))
}

/// The value of `--name value`, removed from `arguments`.
func option(_ name: String, in arguments: inout [String]) -> String? {
    guard let index = arguments.firstIndex(of: name), index + 1 < arguments.count else { return nil }
    defer { arguments.removeSubrange(index...(index + 1)) }
    return arguments[index + 1]
}
let (arguments, statePath, nodeOption): ([String], String, String?) = {
    var arguments = Array(CommandLine.arguments.dropFirst())
    let state = option("--state", in: &arguments) ?? "matter-probe-state.json"
    let node = option("--node", in: &arguments)
    return (arguments, state, node)
}()
let deviceNodeID: NodeID = nodeOption.flatMap { NodeID($0, radix: 16) } ?? 0x0000_0000_B11E_5A01
guard arguments.count >= 3, let port = Int(arguments[2]) else {
    fail("usage: matter-probe commission <ipv6> <port> <manual code> | watch|forget|attest <ipv6> <port> [--state <file>] [--node <hex>]")
}
let command = arguments[0]
let peer: PeerAddress
do { peer = .socket(try SocketAddress(ipAddress: arguments[1], port: port)) } catch { fail("Not an address: \(arguments[1])") }

// MARK: - Printing

func render(_ value: TLVValue) -> String {
    func elements(_ list: [TLVElement], _ open: String, _ close: String) -> String {
        open + list.map { element in
            if case .context(let tag) = element.tag { return "\(tag): \(render(element.value))" }
            return render(element.value)
        }.joined(separator: ", ") + close
    }
    switch value {
    case .signed(let number): return "\(number)"
    case .unsigned(let number): return "\(number)"
    case .bool(let flag): return "\(flag)"
    case .float(let number): return "\(number)"
    case .double(let number): return "\(number)"
    case .utf8(let text): return "\"\(text)\""
    case .bytes(let bytes): return "0x" + bytes.prefix(32).map { String(format: "%02x", $0) }.joined() + (bytes.count > 32 ? "… (\(bytes.count) B)" : "")
    case .null: return "null"
    case .structure(let list): return elements(list, "{", "}")
    case .array(let list): return elements(list, "[", "]")
    case .list(let list): return elements(list, "(", ")")
    }
}

func clusterName(_ id: ClusterID) -> String {
    switch id {
    case BasicInformationCluster.id: "BasicInformation"
    case DescriptorCluster.id: "Descriptor"
    case SwitchCluster.id: "Switch"
    case IcdManagementCluster.id: "IcdManagement"
    case 0x002F: "PowerSource"
    case 0x0003: "Identify"
    default: String(format: "0x%04X", id)
    }
}

func eventName(_ cluster: ClusterID, _ event: EventID) -> String {
    guard cluster == SwitchCluster.id else { return String(format: "event 0x%02X", event) }
    switch event {
    case SwitchCluster.Event.switchLatched: return "SwitchLatched"
    case SwitchCluster.Event.initialPress: return "InitialPress"
    case SwitchCluster.Event.longPress: return "LongPress"
    case SwitchCluster.Event.shortRelease: return "ShortRelease"
    case SwitchCluster.Event.longRelease: return "LongRelease"
    case SwitchCluster.Event.multiPressOngoing: return "MultiPressOngoing"
    case SwitchCluster.Event.multiPressComplete: return "MultiPressComplete"
    default: return String(format: "event 0x%02X", event)
    }
}

func show(_ reports: [AttributeReport]) {
    for report in reports {
        switch report {
        case .data(let path, _, let value):
            say("  ep\(path.endpoint.map(String.init) ?? "*") \(clusterName(path.cluster ?? 0)) attr 0x\(String(format: "%04X", path.attribute ?? 0)) = \(render(value))")
        case .status(let path, let status):
            say("  ep\(path.endpoint.map(String.init) ?? "*") \(clusterName(path.cluster ?? 0)) attr 0x\(String(format: "%04X", path.attribute ?? 0)): \(status)")
        }
    }
}

func show(_ reports: [EventReport]) {
    for report in reports {
        switch report {
        case .data(let record):
            say("EVENT ep\(record.endpoint) \(clusterName(record.cluster)) \(eventName(record.cluster, record.event)) #\(record.number) \(render(record.data))")
        case .status(let path, let status):
            say("event status ep\(path.endpoint.map(String.init) ?? "*") \(clusterName(path.cluster ?? 0)): \(status)")
        }
    }
}

// MARK: - State

func save(_ snapshot: Commissioner.Snapshot) throws {
    let data = try JSONEncoder().encode(snapshot)
    let url = URL(fileURLWithPath: statePath)
    FileManager.default.createFile(atPath: url.path, contents: nil, attributes: [.posixPermissions: 0o600])
    try data.write(to: url)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
}

func restore(_ layer: MessageLayer) throws -> Commissioner {
    guard let data = FileManager.default.contents(atPath: statePath) else { fail("No state at \(statePath): commission first") }
    return try Commissioner(layer: layer, snapshot: try JSONDecoder().decode(Commissioner.Snapshot.self, from: data))
}

// MARK: - What the device is

func describe(_ client: InteractionClient, session: UInt16) async {
    let reads: [(String, [AttributePath])] = [
        ("Basic Information", [BasicInformationCluster.Attribute.vendorName, BasicInformationCluster.Attribute.vendorId,
                               BasicInformationCluster.Attribute.productName, BasicInformationCluster.Attribute.productId,
                               BasicInformationCluster.Attribute.softwareVersionString, BasicInformationCluster.Attribute.hardwareVersionString]
            .map { AttributePath(endpoint: 0, cluster: BasicInformationCluster.id, attribute: $0) }),
        ("Endpoints and device types", [AttributePath(cluster: DescriptorCluster.id, attribute: DescriptorCluster.Attribute.deviceTypeList)]),
        ("Switch clusters", [AttributePath(cluster: SwitchCluster.id)]),
        ("ICD Management", [AttributePath(endpoint: 0, cluster: IcdManagementCluster.id)]),
        ("Power Source", [AttributePath(cluster: 0x002F)]),
    ]
    for (title, paths) in reads {
        say("\(title):")
        do { show(try await client.read(paths, session: session).attributes) } catch { say("  read failed: \(error)") }
    }
}

// MARK: - Events

/// Subscribes to every event and the Switch clusters' attributes and prints what comes, subscribing again when the
/// reports stop for longer than the negotiated interval allows.
func watch(_ commissioner: Commissioner, session initial: UInt16) async throws -> Never {
    var session = initial
    while true {
        let (id, maxInterval, reports) = try await commissioner.client.subscribe(
            [AttributePath(cluster: SwitchCluster.id)], events: [EventPath(isUrgent: true)], eventMin: await nextEvent.value, minInterval: 0,
            maxInterval: 60, keepSubscriptions: false, session: session)
        say("Subscribed (id \(id), max interval \(maxInterval) s). Press, turn, hold the remote: Ctrl-C to stop.")
        let last = Clock()
        await last.touch()
        let reader = Task {
            var first = true
            for await report in reports {
                await last.touch()
                let numbers = report.events.compactMap { event -> UInt64? in if case .data(let record) = event { record.number } else { nil } }
                if let highest = numbers.max(), highest < .max { await nextEvent.set(highest + 1) }
                if first {
                    say("Priming report: \(report.attributes.count) attribute(s), \(report.events.count) buffered event(s)")
                    show(report.events)
                    first = false
                    continue
                }
                if !report.attributes.isEmpty { say("Attribute report:"); show(report.attributes) }
                show(report.events)
                if report.attributes.isEmpty && report.events.isEmpty { say("(keep-alive)") }
            }
        }
        while await last.age < .seconds(Int(maxInterval) + 30) { try await Task.sleep(for: .seconds(5)) }
        say("No report for \(Int(maxInterval) + 30) s: subscribing again")
        reader.cancel()
        await commissioner.client.cancelSubscription(id)
        session = try await CASE.establish(with: peer, peerNodeID: deviceNodeID, identity: await commissioner.identity,
                                           layer: commissioner.layer).localSessionID
    }
}

/// One past the last event seen: a new subscription starts there, so nothing is printed twice.
actor NextEvent {
    private(set) var value: UInt64?
    func set(_ next: UInt64) { value = max(value ?? 0, next) }
}
let nextEvent = NextEvent()

actor Clock {
    private var time = ContinuousClock.now
    func touch() { time = .now }
    var age: Duration { .now - time }
}

// MARK: - Commands

let layer = MessageLayer(transport: UDPTransport(port: 0))
do {
    switch command {
    case "commission":
        guard arguments.count > 3 else { fail("commission needs the manual pairing code") }
        let code = try ManualPairingCode(arguments[3].filter(\.isNumber))
        let commissioner = try Commissioner(layer: layer, fabricID: UInt64.random(in: 1...0xFFFF_FFF0), nodeID: 0x0000_0000_0001_B0B0)
        try await commissioner.start()
        say("Commissioning \(peer), its attestation verified against the Matter registry")
        let commissioned = try await commissioner.commissionNode(peer, passcode: code.passcode, nodeID: deviceNodeID)
        let session = commissioned.session.localSessionID
        try save(await commissioner.snapshot)
        let product = (vendorID: commissioned.vendorID, productID: commissioned.productID)
        say("Commissioned as node 0x\(String(deviceNodeID, radix: 16)); DAC vendor \(product.vendorID.map { String(format: "0x%04X", $0) } ?? "?"), product \(product.productID.map { String(format: "0x%04X", $0) } ?? "?"); state in \(statePath)")
        await describe(commissioner.client, session: session)
        try await watch(commissioner, session: session)
    case "watch":
        let commissioner = try restore(layer)
        try await commissioner.start()
        let session = try await CASE.establish(with: peer, peerNodeID: deviceNodeID, identity: await commissioner.identity, layer: layer)
        say("Connected over CASE")
        await describe(commissioner.client, session: session.localSessionID)
        try await watch(commissioner, session: session.localSessionID)
    case "forget":
        let commissioner = try restore(layer)
        try await commissioner.start()
        let session = try await CASE.establish(with: peer, peerNodeID: deviceNodeID, identity: await commissioner.identity, layer: layer).localSessionID
        try await commissioner.removeFabric(session: session)
        say("Removed this probe's fabric from the device")
        try? FileManager.default.removeItem(atPath: statePath)
    case "attest":
        let commissioner = try restore(layer)
        try await commissioner.start()
        let session = try await CASE.establish(with: peer, peerNodeID: deviceNodeID, identity: await commissioner.identity, layer: layer).localSessionID
        say("Connected over CASE; asking for its attestation")
        let info = try await commissioner.attestationInformation(session: session)
        say("DAC \(info.dac.count) bytes, PAI \(info.pai.count) bytes; Basic Information vendor \(String(format: "0x%04X", info.vendorID)), product \(String(format: "0x%04X", info.productID))")
        do {
            let ids = try AttestationVerifier.verify(info, trusting: .registry)
            say("Attestation verified against the Matter registry (\(AttestationTrustStore.registry.paaCertificates.count) PAAs): vendor \(String(format: "0x%04X", ids.vendorID)), product \(String(format: "0x%04X", ids.productID))")
        } catch {
            say("Attestation refused: \(error)")
        }
    default:
        fail("Unknown command \(command)")
    }
} catch {
    fail("Failed: \(error)")
}
await layer.stop()
