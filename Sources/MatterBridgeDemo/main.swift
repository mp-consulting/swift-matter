import Foundation
import Logging
import Matter

// A Matter bridge of virtual devices: two lights, a plug, a temperature sensor whose reading drifts and a door that
// opens and closes. Commission it with a Matter controller (Apple Home, Google Home, Home Assistant, chip-tool) using
// the pairing code it prints.
//
//   matter-bridge-demo [--storage DIR] [--port 5540] [--passcode 20202021] [--discriminator 3840] [--reset] [--verbose]

struct Options {
    var storage = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".swift-matter-demo")
    var port = 5540
    var passcode: UInt32?
    var discriminator: UInt16?
    var reset = false
    var verbose = false

    init(_ arguments: [String]) {
        var iterator = arguments.dropFirst().makeIterator()
        while let argument = iterator.next() {
            switch argument {
            case "--storage": storage = URL(fileURLWithPath: iterator.next() ?? storage.path)
            case "--port": port = iterator.next().flatMap(Int.init) ?? port
            case "--passcode": passcode = iterator.next().flatMap(UInt32.init)
            case "--discriminator": discriminator = iterator.next().flatMap(UInt16.init)
            case "--reset": reset = true
            case "--verbose": verbose = true
            default:
                print("Unknown option \(argument)")
                exit(1)
            }
        }
    }
}

let options = Options(CommandLine.arguments)
let verbose = options.verbose
LoggingSystem.bootstrap { label in
    var handler = StreamLogHandler.standardError(label: label)
    handler.logLevel = verbose ? .debug : .info
    return handler
}
if options.reset { try? FileManager.default.removeItem(at: options.storage) }

let storage = try FileStorage(directory: options.storage)
var configuration = NodeConfiguration(information: NodeInformation(vendorName: "swift-matter", productName: "Demo Bridge"),
                                      passcode: options.passcode, discriminator: options.discriminator, port: options.port)
configuration.initialWindowTimeout = nil
let node = try await MatterNode(configuration: configuration, storage: storage, advertiser: MDNSAdvertiser())
let bridge = try await MatterBridge(node: node)

func log(_ device: String) -> DeviceCommandHandler {
    { command in print("\(device): \(command)") }
}

let ceiling = try await bridge.add(BridgedDeviceInfo(id: "demo-light-1", name: "Ceiling light", vendorName: "swift-matter",
                                                     productName: "Virtual light"),
                                   kind: .dimmableLight, handler: log("Ceiling light"))
_ = try await bridge.add(BridgedDeviceInfo(id: "demo-light-2", name: "Desk lamp", vendorName: "swift-matter", productName: "Virtual color light"),
                         kind: .extendedColorLight(mireds: 153...500), handler: log("Desk lamp"))
_ = try await bridge.add(BridgedDeviceInfo(id: "demo-plug", name: "Coffee machine", vendorName: "swift-matter", productName: "Virtual plug"),
                         kind: .onOffPlug, handler: log("Coffee machine"))
let thermometer = try await bridge.add(BridgedDeviceInfo(id: "demo-temperature", name: "Living room", vendorName: "swift-matter",
                                                         productName: "Virtual thermometer"), kind: .temperatureSensor, battery: true)
let door = try await bridge.add(BridgedDeviceInfo(id: "demo-door", name: "Front door", vendorName: "swift-matter",
                                                  productName: "Virtual contact sensor"), kind: .contactSensor)
await ceiling.update(.level(128))
await thermometer.update(.battery(percent: 80))

try await node.start()

if await node.isCommissioned {
    print("The bridge is commissioned. Open a commissioning window from your controller to add it to another one.")
} else {
    // The demo shows its pairing code on purpose: it is how a person commissions it.
    let payload = node.setupPayload
    print("""
        Commission the bridge with a Matter controller:
          QR code payload:     \(payload.qrCode)
          Manual pairing code: \(payload.manualCode)
        """)
}

// The sensors change on their own.
var temperature = 21.0
var closed = true
while true {
    try await Task.sleep(for: .seconds(30))
    temperature += Double.random(in: -0.3...0.3)
    await thermometer.update(.temperature((temperature * 10).rounded() / 10))
    closed.toggle()
    await door.update(.contact(closed))
}
