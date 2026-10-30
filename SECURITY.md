# Security

swift-matter runs the protocol that commissions a node and keeps its fabrics' operational keys: PASE, CASE, device
attestation, certificates and access control. A flaw in any of them can let someone control the devices a bridge
exposes, locks included, so please report it privately.

## Reporting a vulnerability

Use [Report a vulnerability](https://github.com/mp-consulting/swift-matter/security/advisories/new) on the repository's
Security tab. Do not open a public issue, pull request or discussion for it.

Say what is affected (the version and the component: PASE, CASE, messages, the Interaction Model, access control,
groups, discovery, the bridge), how to reproduce it, and what an attacker gains. A proof of concept helps; keep real
pairing codes and keys out of it.

You get an answer within a week. We agree on a fix and a date with you, publish an advisory with the release that
fixes it, and credit you unless you prefer otherwise.

## Supported versions

Fixes go into the latest release. Update to it before reporting, if you can.

## Scope

In scope: this repository's code. Out of scope: the specification itself (report those to the Connectivity Standards
Alliance), commissioners' own flaws (report those to their makers), and the test attestation credentials, which are
public on purpose (see the README's Certification section).
