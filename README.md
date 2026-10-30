# swift-matter

The [Matter](https://csa-iot.org/all-solutions/matter/) smart home protocol in Swift: a Matter node over IP that
Apple Home, Google Home, Amazon Alexa, SmartThings and Home Assistant can commission and control, and a bridge API to
expose other devices as bridged Matter endpoints. Written against the Matter 1.6.1 specifications; macOS 14+ and Linux.

## What it does

- Commissioning over the network: PASE (SPAKE2+), device attestation, CSR and operational certificates, CASE with
  session resumption, the fail-safe, multiple fabrics (Administrator Commissioning's enhanced window).
- The Interaction Model: reads, writes, invokes, timed interactions, subscriptions with chunked reports, events,
  per-fabric access control.
- DNS-SD with a built-in mDNS responder on IPv4 and IPv6.
- A bridge: an Aggregator with bridged lights (on/off, dimmable, color temperature, extended color), plugs, contact,
  occupancy, temperature, humidity and light sensors, window coverings, fans, thermostats, door locks and buttons;
  compound devices; custom device kinds with your own clusters. Endpoint numbers are stable across restarts.

## A bridge in a few lines

```swift
import Matter

let node = try await MatterNode(configuration: NodeConfiguration(), storage: try FileStorage(directory: storageURL),
                                advertiser: MDNSAdvertiser())
let bridge = try await MatterBridge(node: node)
let lamp = try await bridge.add(BridgedDeviceInfo(id: "lamp-1", name: "Desk lamp"), kind: .dimmableLight) { command in
    // .setOn(true), .setLevel(128)...: tell the real lamp.
}
try await node.start()
print(node.setupPayload.qrCode, node.setupPayload.manualCode)
await lamp.update(.on(true))   // the lamp changed on its own
```

`bin/dev demo` runs a bridge of virtual devices, `bin/dev bench` measures one ([Benchmarks.md](Benchmarks.md)); see [CLAUDE.md](CLAUDE.md) for the layout and `bin/dev help` for the
development commands.

## Limits

- Matter over IP only: no Bluetooth (BTP), Thread or Wi-Fi PAF commissioning; the node must already be on the network.
- Groups take trust-first and cache-and-sync keys (MCSP); no Groupcast cluster. MCSP messages are not retransmitted. No
  OTA (it needs a vendor ID of its own), no ICD (sleepy device) support. TCP (`NodeConfiguration.tcp`) is off by default.
- Scenes are reported with an empty table; level and color transitions complete at once.

## Certification

swift-matter is not a certified Matter product. It uses the test vendor ID `0xFFF1` and test attestation
credentials, so commissioners show it as an uncertified device, and some ecosystems only accept it in developer mode.

## Licence

MIT. Portions follow the structure of [matter.js](https://github.com/project-chip/matter.js) and use test vectors and
the test attestation credentials of [connectedhomeip](https://github.com/project-chip/connectedhomeip); see
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
