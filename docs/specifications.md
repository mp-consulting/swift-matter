# The Matter specifications

swift-matter is written against the Matter 1.6.1 specifications. The Connectivity Standards Alliance (CSA) publishes
them, and their licence lets only CSA members reproduce them, so this repository does not include them. Anyone can
download them for free from the CSA's
[specifications download request](https://csa-iot.org/developer-resource/specifications-download-request/) form.

| Document | Number | Cited in the code as |
|---|---|---|
| Matter Specification (Core), version 1.6.1 | `23-27349-012` | `Core §4.15` |
| Matter Application Cluster Specification, version 1.6.1 | `23-27350-011` | `Application Clusters §1.3` |
| Matter Device Library Specification, version 1.6.1 | `23-27351-011` | `Device Library §2.5` |
| Matter Standard Namespaces, version 1.6.1 | `23-31936-009` | |

All four were accepted by the CSA's board on September 16, 2026.

## Keeping them with your checkout

Put the PDFs in `specs/` at the root of the repository: git ignores it, so they stay on your machine. Section numbers
change between versions, so read the ones above when a comment cites a section.

## Other references

- Cluster and device type ids, fields and access come from [matter.js](https://github.com/project-chip/matter.js)'s
  model, which follows the specifications (`bin/dev generate`, `Scripts/generate-clusters.mjs`).
- [connectedhomeip](https://github.com/project-chip/connectedhomeip), the reference implementation, is where the test
  attestation credentials and many test vectors come from, and the controller CI commissions the demo with.
- SPAKE2+ follows [draft-bar-cfrg-spake2plus-02](https://datatracker.ietf.org/doc/html/draft-bar-cfrg-spake2plus-02);
  AES-CCM is checked against [RFC 3610](https://www.rfc-editor.org/rfc/rfc3610), PBKDF2 against
  [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914).

## A new version of the specifications

Update the version and document numbers here, in the README and in CLAUDE.md, regenerate `Definitions.swift` from a
matter.js release that follows the new version, and note in CHANGELOG.md what changed for users.
