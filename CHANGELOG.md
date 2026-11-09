# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).
Before 1.0, a minor version may change the API.

## [Unreleased]

## [0.6.0] - 2026-11-09

### Added

- A changelog, contribution guide, security policy, code of conduct, issue and pull request templates, and Dependabot
  for the Swift packages and the workflows' actions.
- docs/specifications.md: the Matter 1.6.1 documents the code cites, and where to download them.
- Scenes on lights and plugs: Scenes Management stores, recalls, copies and removes scenes of their On/Off, Level
  Control and Color Control state, per fabric and group, with names, kept in storage (`MatterNode.scenes`). On/Off's
  OffWithEffect and OnWithRecallGlobalScene store and recall the global scene. A group's scenes go when the endpoint
  leaves the group.
- Extended color lights support enhanced hue (EnhancedMoveToHue, EnhancedMoveToHueAndSaturation), so a scene keeps
  their hue.
- Device attestation as a commissioner validates it (Core §6.2.3.1), without connectedhomeip: `AttestationVerifier`
  checks the DAC, PAI and PAA chain (each valid when the DAC was issued, vendor and product ids in either of the
  encodings of §6.2.2.2), the attestation signature and nonce, and the Certification Declaration (its signer, vendor,
  products, DAC origin and authorized PAAs). `AttestationTrustStore.registry` holds the 74 PAA certificates the
  Distributed Compliance Ledger approved and the CSA's five declaration signing keys; `Scripts/update-trust-store.py`
  (`bin/dev trust-store`) fetches the roots from the ledger again. `.test` is connectedhomeip's test PKI. Revocation
  (§6.2.4) is not checked yet.
- The controller side for production devices: `Commissioner(trustStore:)`, the registry's by default;
  `attestationPolicy` `.signaturesOnly` takes a device whose certification did not check out once the person agreed
  (`AttestationFailure.isCertificationFailure`), its DAC's signatures still checked; `commissionNode` says whose it is;
  `attestationInformation(session:)` asks a node for its attestation over PASE or CASE; `Commissioner.Snapshot` saves a fabric's keys and certificates and
  `Commissioner(layer:snapshot:)` restores it; `compressedFabricID`. Commissioning reads the device's LocationCapability
  before SetRegulatoryConfig, so an indoor-only device is not refused.
- `InteractionClient.subscribe(eventMin:)`: a subscription from an event number (an EventFilterIB), so one made again
  does not replay what the last one delivered.
- DNS-SD records for a commissioner: `CommissionableNodeInfo` (a `_matterc._udp` TXT record: discriminator,
  commissioning mode, vendor and product, MRP intervals), `PairingCode` (a manual code or a QR code, matched to a
  record) and `OperationalInstanceName` (`<compressed fabric id>-<node id>`). `SessionParameters(txt:)` reads SII, SAI,
  SAT and T; `MessageLayer.setParameters(_:of:)` gives a peer's to the unsecured messages that establish a session.
- Commissioning sets the fabric's label (`commissionNode(fabricLabel:)`, UpdateFabricLabel, the next free one on a
  LabelConflict), as a commissioner SHALL (Core §5.5, step 13). `CommissionableNodeInfo.isCommissionable` is CM 1 or 2:
  CM 3 is Joint Fabric commissioning, which needs steps of its own.
- `matter-probe`: joins a real device as an extra administrator through a window another controller opened, and prints
  what it is and every event it sends (`commission`, `watch`, `forget`, and `attest`, which checks a commissioned
  device's attestation against the registry over CASE).
- A commissioning that stops after ArmFailSafe (a refused attestation, a failed command) expires the fail-safe at once,
  so the device takes a new PASE session in the same window rather than answering BusyWithOtherAdmin.

### Fixed

- A DNS-SD TXT value beyond its bound (SII or SAI above an hour, SAT above 65535 ms) is invalid and means the default,
  as Core §4.3.4 says, rather than being clamped.
- Spec citations: KeepSubscriptions is Core §8.5.2.3, the Switch cluster's events Application Clusters §1.13.6.
- MRP retransmits from the peer's idle interval once it has been quiet for its active threshold, and from its active
  interval while it is active (Core §4.12.8); it always used the active one, which a sleepy device polling every idle
  interval could miss.
- A certificate time of 0 is 99991231235959Z in X.509 for notBefore as for notAfter, as connectedhomeip encodes it, so a
  signature over the X.509 form verifies on both sides. The commissioner's own certificates start a day ago: a device on
  connectedhomeip refused its root certificate (AddTrustedRootCertificate, InvalidCommand) when it started at 0.

### Changed

- `AccessContext` and `InteractionServer` take the node's `Scenes`, as they take its `Groups`.

### Fixed

- The UDP and TCP transports listen on IPv4 alone when the host has no IPv6 (a container without it), instead of
  failing to start.
- `FileStorage` replaces a key's file with rename(2): Foundation's `replaceItemAt` failed on Linux.

## [0.5.0] - 2026-10-30

### Added

- Air purifiers with a HEPA filter, and air quality sensors that report carbon dioxide, PM2.5, PM10 and VOC
  concentrations.
- Fans that rock and change airflow direction.
- Thermostats in auto mode, with separate heating and cooling setpoints.

## [0.4.1] - 2026-10-30

### Added

- `MatterNode` lets callers follow the commissioning window as it opens and closes.
- Debug logs say why an invoke or a write was denied, and why a CASE resumption fell back to a full CASE.
- A warning when the host has no IPv6 address, which commissioners need.

### Fixed

- A resumed CASE session's keys are salted with the resumed ticket's id, as the specification says.
- A CASE session stays on its own fabric when the controller adds another fabric over it.

## [0.4.0] - 2026-10-30

### Added

- The Closure device type: gates, garage doors, doors and windows.
- The Groupcast cluster, as a listener.
- CASE resumption tickets are kept across restarts, one per peer.
- Interactions are logged at debug level.
- CI commissions the demo with connectedhomeip's own controller on every change.

### Fixed

- An empty intermediate certificate in AddNOC is taken as none, as Apple Home sends it: Apple Home can commission a
  node.
- A closure that reverses or stops half open moves correctly; Groupcast's key map is bounded.

## [0.3.0] - 2026-10-30

### Added

- `MatterNode.addDevice` makes a node one device of its own, without a bridge's Aggregator.
- A node's own device reports its reachability and name in Basic Information.

### Changed

- Node strings (names, labels) are cut to the specification's limits.

## [0.2.1] - 2026-10-30

### Fixed

- mDNS answers link-local addresses only on their own link.

## [0.2.0] - 2026-10-30

### Added

- Robot vacuums.
- Group counters synchronized for cache-and-sync keys (MCSP), with lost sync requests resent.

### Fixed

- Derived clusters get their base cluster's attributes and commands.
- Group messages with counters behind the window are refused.

## [0.1.0] - 2026-10-30

The first release: a Matter node over IP and a bridge API.

### Added

- Matter TLV, AES-CCM, PBKDF2, P-256 (in C) and SPAKE2+.
- QR and manual pairing codes.
- Matter operational certificates, converted to X.509 and signed; test DACs, PAIs and Certification Declarations.
- Message frames, sessions, exchanges and the message reliability protocol over UDP, TCP and an in-memory network.
- PASE and CASE, as responder and initiator, with CASE session resumption.
- The data model generated from matter.js's model, access control lists, and the Interaction Model: reads, writes,
  invokes, timed interactions and subscriptions.
- Commissioning: the root endpoint's clusters, the fail-safe, the commissioning window, multiple fabrics, and a
  `Commissioner` that verifies attestation.
- DNS-SD with a built-in mDNS responder.
- Group commands and writes.
- `MatterBridge`: bridged lights, plugs, sensors, window coverings, fans, thermostats, door locks, buttons, water leak
  detectors, smoke and CO alarms, air quality sensors, valves and electrical metering; compound devices and custom
  device kinds; endpoint numbers kept across restarts.
- `matter-bridge-demo`, a bridge of virtual devices, and `matter-bench`, which measures a node.

[Unreleased]: https://github.com/mp-consulting/swift-matter/compare/0.6.0...HEAD
[0.6.0]: https://github.com/mp-consulting/swift-matter/compare/0.5.0...0.6.0
[0.5.0]: https://github.com/mp-consulting/swift-matter/compare/0.4.1...0.5.0
[0.4.1]: https://github.com/mp-consulting/swift-matter/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/mp-consulting/swift-matter/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/mp-consulting/swift-matter/compare/0.2.1...0.3.0
[0.2.1]: https://github.com/mp-consulting/swift-matter/compare/0.2.0...0.2.1
[0.2.0]: https://github.com/mp-consulting/swift-matter/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/mp-consulting/swift-matter/releases/tag/0.1.0
