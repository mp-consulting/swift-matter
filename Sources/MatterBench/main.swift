import Foundation
import Logging
import Matter
import NIOCore
#if canImport(Darwin)
import Darwin
#endif

// Measures a Matter bridge node as a controller sees it, over UDP on the loopback interface with the real
// cryptography: commissioning, session establishment, reads, invokes, subscription reports, and memory with many
// bridged devices. Build in release (bin/dev bench); the numbers go in Benchmarks.md.
//
//   matter-bench [--devices 100] [--iterations 200] [--sessions 10]

struct Options {
    var devices = 100
    var iterations = 200
    var sessions = 10

    init(_ arguments: [String]) {
        var iterator = arguments.dropFirst().makeIterator()
        while let argument = iterator.next() {
            let value = iterator.next().flatMap(Int.init)
            switch (argument, value) {
            case ("--devices", let value?): devices = value
            case ("--iterations", let value?): iterations = value
            case ("--sessions", let value?): sessions = value
            default:
                print("Usage: matter-bench [--devices N] [--iterations N] [--sessions N]")
                exit(1)
            }
        }
    }
}

let options = Options(CommandLine.arguments)
LoggingSystem.bootstrap { label in
    var handler = StreamLogHandler.standardError(label: label)
    handler.logLevel = ProcessInfo.processInfo.environment["MATTER_BENCH_LOG"].flatMap(Logger.Level.init(rawValue:)) ?? .error
    return handler
}

/// Resident memory, in megabytes.
func residentMegabytes() -> Double {
    #if canImport(Darwin)
    var info = mach_task_basic_info()
    var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size / MemoryLayout<natural_t>.size)
    let result = withUnsafeMutablePointer(to: &info) {
        $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count) }
    }
    return result == KERN_SUCCESS ? Double(info.resident_size) / 1_048_576 : 0
    #else
    let statm = (try? String(contentsOfFile: "/proc/self/statm", encoding: .utf8))?.split(separator: " ")
    return Double(statm.flatMap { $0.count > 1 ? Int($0[1]) : nil } ?? 0) * Double(sysconf(Int32(_SC_PAGESIZE))) / 1_048_576
    #endif
}

/// Times each run of `body`, in milliseconds.
func measure(_ runs: Int, _ body: () async throws -> Void) async throws -> [Double] {
    var times: [Double] = []
    for _ in 0..<runs {
        let start = ContinuousClock.now
        try await body()
        let elapsed = ContinuousClock.now - start
        times.append(Double(elapsed.components.seconds) * 1000 + Double(elapsed.components.attoseconds) / 1e15)
    }
    return times
}

func row(_ name: String, _ times: [Double]) -> String {
    let sorted = times.sorted()
    func percentile(_ p: Double) -> Double { sorted[min(sorted.count - 1, Int(Double(sorted.count) * p))] }
    return String(format: "| %@ | %d | %.2f ms | %.2f ms | %.2f ms |", name, times.count, percentile(0.5), percentile(0.95), sorted.last ?? 0)
}

let loopback = try SocketAddress(ipAddress: "127.0.0.1", port: 0)

/// A bridge node on a free UDP port, with `devices` lights.
func makeBridge(devices: Int) async throws -> (node: MatterNode, bridge: MatterBridge, lights: [BridgedDevice], port: Int) {
    let transport = UDPTransport(port: 0)
    var configuration = NodeConfiguration(passcode: 20202021, discriminator: 3840)
    configuration.initialWindowTimeout = nil
    let node = try await MatterNode(configuration: configuration, storage: MemoryStorage(), transport: transport)
    let bridge = try await MatterBridge(node: node)
    var lights: [BridgedDevice] = []
    for index in 0..<devices {
        lights.append(try await bridge.add(BridgedDeviceInfo(id: "light-\(index)", name: "Light \(index)"), kind: .dimmableLight))
    }
    try await node.start()
    return (node, bridge, lights, transport.localPort ?? 0)
}

func peer(_ port: Int) throws -> PeerAddress { .socket(try SocketAddress(ipAddress: "127.0.0.1", port: port)) }

func run() async throws {
    var lines: [String] = []
    let memoryBefore = residentMegabytes()

    // Commissioning: PASE, attestation, CSR, NOC and CASE; a fresh node each time (the fabric table is small).
    var commissioning: [Double] = []
    var pase: [Double] = []
    for _ in 0..<max(3, options.iterations / 40) {
        let (node, _, _, port) = try await makeBridge(devices: 1)
        let layer = MessageLayer(transport: UDPTransport(port: 0))
        let commissioner = try Commissioner(layer: layer, fabricID: 1, nodeID: 0x1122)
        try await commissioner.start()
        pase += try await measure(1) { _ = try await PASE.establish(with: try peer(port), passcode: 20202021, layer: layer) }
        commissioning += try await measure(1) { _ = try await commissioner.commission(try peer(port), passcode: 20202021, nodeID: 0x42) }
        await layer.stop()
        await node.stop()
    }
    lines.append(row("PASE session", pase))
    lines.append(row("Commissioning (PASE, attestation, NOC, CASE)", commissioning))

    // One commissioned bridge for the rest.
    let (node, _, lights, port) = try await makeBridge(devices: options.devices)
    let memoryWithDevices = residentMegabytes()
    let layer = MessageLayer(transport: UDPTransport(port: 0))
    let commissioner = try Commissioner(layer: layer, fabricID: 1, nodeID: 0x1122)
    try await commissioner.start()
    let session = try await commissioner.commission(try peer(port), passcode: 20202021, nodeID: 0x42).localSessionID
    let identity = await commissioner.identity

    var ticket: CASE.ResumptionTicket?
    lines.append(row("CASE session", try await measure(options.iterations / 10) {
        ticket = try await CASE.establishResumable(with: try peer(port), peerNodeID: 0x42, identity: identity, layer: layer).ticket
    }))
    lines.append(row("CASE resumption", try await measure(options.iterations / 10) {
        ticket = try await CASE.establishResumable(with: try peer(port), peerNodeID: 0x42, identity: identity, layer: layer, ticket: ticket).ticket
    }))

    let light = lights[lights.count / 2].endpoint
    lines.append(row("Read one attribute", try await measure(options.iterations) {
        _ = try await commissioner.client.read(endpoint: light, cluster: OnOffCluster.id, attribute: OnOffCluster.Attribute.onOff, session: session)
    }))
    lines.append(row("Read a device's every attribute", try await measure(options.iterations / 4) {
        _ = try await commissioner.client.read([AttributePath(endpoint: light)], session: session)
    }))
    lines.append(row("Invoke (toggle)", try await measure(options.iterations) {
        _ = try await commissioner.client.invoke(CommandPath(endpoint: light, cluster: OnOffCluster.id, command: OnOffCluster.Command.toggle),
                                                 session: session)
    }))

    // A report reaching a subscriber after the device changed.
    let (_, _, reports) = try await commissioner.client.subscribe(
        [AttributePath(endpoint: light, cluster: LevelControlCluster.id, attribute: LevelControlCluster.Attribute.currentLevel)],
        minInterval: 0, maxInterval: 60, session: session)
    var iterator = reports.makeAsyncIterator()
    _ = await iterator.next() // The priming report.
    var level: UInt8 = 1
    lines.append(row("Subscription report after a change", try await measure(options.iterations / 2) {
        level = level % 250 + 1
        await lights[lights.count / 2].update(.level(level))
        _ = await iterator.next()
    }))

    // Several controllers at once: sessions reading in parallel.
    var sessions: [UInt16] = []
    for _ in 0..<options.sessions {
        sessions.append(try await CASE.establish(with: try peer(port), peerNodeID: 0x42, identity: identity, layer: layer).localSessionID)
    }
    let parallelStart = ContinuousClock.now
    let reads = options.iterations
    try await withThrowingTaskGroup(of: Void.self) { group in
        for session in sessions {
            group.addTask {
                for _ in 0..<reads {
                    _ = try await commissioner.client.read(endpoint: light, cluster: OnOffCluster.id, attribute: OnOffCluster.Attribute.onOff,
                                                           session: session)
                }
            }
        }
        try await group.waitForAll()
    }
    let parallelSeconds = Double((ContinuousClock.now - parallelStart).components.attoseconds) / 1e18
        + Double((ContinuousClock.now - parallelStart).components.seconds)

    print("""
        swift-matter benchmark: \(options.devices) bridged lights, \(options.iterations) iterations, UDP loopback, \(ProcessInfo.processInfo.operatingSystemVersionString)

        | Operation | Runs | Median | p95 | Max |
        |---|---|---|---|---|
        \(lines.joined(separator: "\n"))

        Reads from \(options.sessions) sessions at once: \(String(format: "%.0f", Double(reads * options.sessions) / parallelSeconds)) reads/s
        Resident memory: \(String(format: "%.1f", memoryBefore)) MB at start, \(String(format: "%.1f", memoryWithDevices)) MB with \(options.devices) bridged lights
        """)
    await layer.stop()
    await node.stop()
}

try await run()
