# swift-matter

The Matter protocol (device side, over IP) in Swift: a Matter node that a commissioner (Apple Home, Google Home,
Alexa, SmartThings, Home Assistant, chip-tool) can commission and control, and a bridge API that exposes other devices
as bridged Matter endpoints. Written against the Matter 1.6.1 specifications (Core `23-27349-012`, Application
Clusters `23-27350-011`, Device Library `23-27351-011`). macOS 14+ and Linux. Library `Matter`; the demo bridge is
`matter-bridge-demo`.

## Layout

| Path | What it is |
|---|---|
| `Sources/Matter/TLV` | Matter TLV (Core Appendix A): `TLVValue`/`TLVElement`, `TLVEncoder`/`TLVDecoder`, `TLVStruct` for typed field access |
| `Sources/Matter/Crypto` | `MatterCrypto` (KDF, HMAC, hash, constant-time compare), `AESCCM` (CBC-MAC and CTR from `_CryptoExtras`), `PBKDF2` (`_CryptoExtras`, Matter's iteration range), `P256` (point arithmetic swift-crypto keeps internal, on `CP256`), `SPAKE2Plus` (draft-02, Core §3.10) |
| `Sources/CP256` | P-256 field and point arithmetic in C (Montgomery multiplication, complete addition, constant-time ladder): the Swift version took most of a second per scalar multiplication in debug builds |
| `Sources/Matter/Certificates` | `DER` (writer, reader, `signed`), `OID`, `MatterCertificate` (RCAC/ICAC/NOC: TLV ↔ X.509 TBS, signing and verification) |
| `Sources/Matter/Onboarding` | `SetupPayload` and `ManualPairingCode`: QR code (`MT:` Base38), manual pairing code (Verhoeff), passcode rules |
| `Sources/Matter/Messages` | Message frames (`MessageHeader`, `PayloadHeader`, `Message` sealing and opening), counters and duplicate detection, `StatusReport` |
| `Sources/Matter/Groups` | `Groups` (Core §4.16-4.17: key sets stored as operational keys, GroupKeyMap, memberships, trust-first peer counters, multicast addresses, group session ids), used by the message layer (private group messages), the IM server (group invokes and writes, no response), Group Key Management and the Groups cluster |
| `Sources/Matter/Transport` | `MatterTransport`: `UDPTransport` (dual-stack IPv6 on NIO, IPv4 peers unmapped), `TCPTransport` (Core §4.15: 4-byte little-endian length prefix, MRP off, a `.stream` peer per connection, server and client), `CombinedTransport` (UDP and TCP), `MemoryNetwork`/`MemoryTransport` for tests (with a drop filter) |
| `Sources/Matter/Sessions` | `MessageLayer` (sessions, exchanges, MRP retransmissions and acknowledgements, handler registry), `Exchange`, `SessionInfo`, `SessionParameters` |
| `Sources/Matter/SecureChannel` | `PASE` (responder and initiator), `CASE` (responder and initiator, resumption with `ResumptionStore`), `SecureChannelServer` (one PASE at a time, CloseSession) |
| `Sources/Matter/DataModel` | `Definitions.swift` (generated: every cluster's ids, access, struct field tags, device types), `Model.swift` (privileges, IM status), `ClusterHandler` and `AttributeCluster` (stored attributes, command closures, write hooks, events), `FabricScopedList`, `DataModel` (endpoints, Descriptors, events, change stream), `AccessControlEntry` and `AccessControlEntries` (the persisted ACL) |
| `Sources/Matter/InteractionModel` | `InteractionServer` (read, write, invoke, timed, subscribe; chunking), `Subscription`, `InteractionClient`, paths and report IBs |
| `Sources/Matter/Fabrics` | `MatterStorage` (`MemoryStorage`, `FileStorage`), `StorageKey`, `Fabric` (compressed fabric id, IPK, destination id), `FabricTable`, `CertificateChain` |
| `Sources/Matter/Attestation` | `DeviceAttestation` (DAC/PAI issued under connectedhomeip's test PAA), `CertificationDeclaration` (CMS), `X509`, `CertificationRequest` (PKCS#10), `TestCredentials` |
| `Sources/Matter/Commissioning` | `Commissioning` (window, fail-safe, pending credentials, AddNOC/UpdateNOC, fabric removal), `RootClusters` (Basic Information, General Commissioning, Operational Credentials, Access Control, Group Key Management, Network Commissioning, General Diagnostics, Administrator Commissioning) |
| `Sources/Matter/Commissioner` | `Commissioner`: a controller with its own fabric that verifies attestation, issues NOCs and completes commissioning (tests, tools) |
| `Sources/Matter/Discovery` | `MDNSAdvertiser` (built-in mDNS responder on IPv4 and IPv6: `_matterc._udp` with subtypes, `_matter._tcp`), `MatterRecords`, `DNSMessage` (from homeswift) |
| `Sources/Matter/Node` | `MatterNode`: storage, attestation, setup code, root endpoint, servers, advertising; `NodeConfiguration`, `NodeAdvertiser` |
| `Sources/Matter/Bridge` | `MatterBridge` (Aggregator, persisted endpoint numbers, compound devices), `DeviceKind` presets and custom kinds, `DevicePart`, `BridgedDevice` (`update`, `set`, `emit`, `press`), `DeviceClusters` (application clusters), `DeviceCommand`/`DeviceState` |
| `Sources/MatterBridgeDemo` | `matter-bridge-demo`: virtual lights, plug, thermometer and door |
| `Scripts/generate-clusters.mjs` | Generates `Definitions.swift` from matter.js's model files (read as text, never executed) |
| `Scripts/interop.sh` | Commissions the running demo with chip-tool and drives it |
| `Sources/MatterBench` | `matter-bench` (`bin/dev bench`): a bridge node and a controller over UDP loopback, timing commissioning, sessions, reads, invokes and reports, and memory; results in `Benchmarks.md` |
| `Tests/MatterTests` | Swift Testing suites; vectors from the specification, the SPAKE2+ draft, RFC 3610/7914 and matter.js's tests; end-to-end commissioning on a memory network and over UDP |
| `bin/dev` | Development commands (`bin/dev help`) |

## Commands

```sh
bin/dev build                 # debug build (scratch path outside ~/Documents on macOS: codesign rejects Finder metadata)
bin/dev test                  # all tests; bin/dev test SPAKE2PlusTests for one suite
bin/dev lint                  # whitespace, tabs, stray prints
bin/dev demo --reset          # the demo bridge on port 5540, storage in ~/.swift-matter-demo
bin/dev bench                 # matter-bench in release; update Benchmarks.md with its tables
bin/dev interop               # commission the running demo with chip-tool and toggle a light
bin/dev generate ~/src/matter.js   # regenerate Definitions.swift after a matter.js update
```

## Rules

- **No Claude attribution in git.** Commit messages and pull requests carry no `Co-Authored-By: Claude` trailer and no
  "Generated with Claude Code" line.
- **Conventional Commits**: `<type>(<scope>): <summary>`, type one of `feat`, `fix`, `perf`, `refactor`, `docs`, `test`,
  `build`, `ci`, `chore`, `style`, `revert`; scope the area (`tlv`, `crypto`, `certificates`, `onboarding`, `messages`,
  `pase`, `case`, `im`, `clusters`, `commissioning`, `fabrics`, `attestation`, `discovery`, `bridge`, `demo`); summary
  imperative, no final period.
- **Never guess byte layouts.** Follow the specification and check against known vectors (the spec's examples,
  RFCs, the SPAKE2+ draft, matter.js and connectedhomeip test data). Crypto is never only tested against itself:
  P-256 is checked against swift-crypto, SPAKE2+ against the draft's vectors, certificates against Core §6.5.15, the
  Certification Declaration against Appendix F.1, fabric derivations against §4.3.2.2 and §4.14.2.4.
- **Never hand-type cluster ids.** Use the generated constants (`OnOffCluster.Attribute.onOff`, struct field tags such
  as `AccessControlCluster.AccessControlEntryStruct.privilege`, `DeviceTypes.extendedColorLight`).
- **Never log** passcodes, pairing codes, verifiers, keys, session keys, NOC private keys or PASE/CASE payloads (sizes
  only). The demo prints its pairing code to stdout on purpose; the library never does.
- **Peer input never traps.** Narrow integers with `uint(_:as:)`/`exactly:`, never `Int(...)`/`UInt8(...)` on a peer
  value; a remote crash takes every bridged device down.
- **No new dependencies** beyond swift-nio, swift-crypto (including `_CryptoExtras`) and swift-log.
- **Keep Linux building**: Darwin-only APIs behind `#if canImport(...)`. Use `[UInt8]` for bytes, not `Data`, except at
  Foundation boundaries. CI runs the tests on macOS and Linux.
- Secret comparisons go through `MatterCrypto.equal`; scalar arithmetic on secrets uses the constant-time ladder.
- Tests wait for what they check (`eventually`), never a fixed sleep; MRP and subscriptions take a time scale
  (`ReliabilityParameters.timeScale`, `InteractionServer.setTimeScale`).
- Endpoint numbers of bridged devices are persisted by device id and never reused (Core §9.2.10).
