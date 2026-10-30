# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).
Before 1.0, a minor version may change the API.

## [Unreleased]

### Added

- A changelog, contribution guide, security policy, code of conduct, issue and pull request templates, and Dependabot
  for the Swift packages and the workflows' actions.
- docs/specifications.md: the Matter 1.6.1 documents the code cites, and where to download them.

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

[Unreleased]: https://github.com/mp-consulting/swift-matter/compare/0.5.0...HEAD
[0.5.0]: https://github.com/mp-consulting/swift-matter/compare/0.4.1...0.5.0
[0.4.1]: https://github.com/mp-consulting/swift-matter/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/mp-consulting/swift-matter/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/mp-consulting/swift-matter/compare/0.2.1...0.3.0
[0.2.1]: https://github.com/mp-consulting/swift-matter/compare/0.2.0...0.2.1
[0.2.0]: https://github.com/mp-consulting/swift-matter/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/mp-consulting/swift-matter/releases/tag/0.1.0
